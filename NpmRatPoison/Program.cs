using Autofac;
using Autofac.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Serilog;
using System.Reflection;
using System.Text;
using System.Diagnostics;
using System.Threading.RateLimiting;
using VapeCache.Abstractions.Caching;
using VapeCache.Extensions.Logging;
using VapeCache.Infrastructure.Caching;

public static class Program
{
    private const string DefaultDashboardUrl = "http://127.0.0.1:5100";

    public static async Task<int> Main(string[] args)
    {
        var options = CliOptions.Parse(args);

        if (options.ShowVersion)
        {
            Console.WriteLine(BuildVersionText());
            return ScanExitCodeEvaluator.Success;
        }

        if (options.ShowHelp)
        {
            Console.WriteLine(BuildHelpText());
            return ScanExitCodeEvaluator.Success;
        }

        if (options.SimulateIncident && !options.PathProvided)
        {
            Console.WriteLine("The --simulate-incident mode requires --path <directory>.");
            Console.WriteLine();
            Console.WriteLine(BuildHelpText());
            return ScanExitCodeEvaluator.InvalidArguments;
        }

        if (options.RemoteGitHubScan
            && string.IsNullOrWhiteSpace(options.RemoteGitHubOrganization)
            && string.IsNullOrWhiteSpace(options.RemoteGitHubUser)
            && options.RemoteGitHubRepositories.Count == 0)
        {
            Console.WriteLine("Remote GitHub scan requires --remote-github-org, --remote-github-user, or one or more --remote-github-repo values.");
            Console.WriteLine();
            Console.WriteLine(BuildHelpText());
            return ScanExitCodeEvaluator.InvalidArguments;
        }

        if (options.GenerateProviderApiKey && string.IsNullOrWhiteSpace(options.ProviderId))
        {
            Console.WriteLine("Provider API key generation requires --provider-id <provider>.");
            Console.WriteLine();
            Console.WriteLine(BuildHelpText());
            return ScanExitCodeEvaluator.InvalidArguments;
        }

        var builder = CreateBuilder(args, options);

        try
        {
            var app = builder.Build();

            if (options.UiMode || options.ServiceMode)
            {
                ConfigureServerSurface(app, options);
                await app.RunAsync();
                return ScanExitCodeEvaluator.Success;
            }

            return await ExecuteCliAsync(app, options);
        }
        finally
        {
            await Log.CloseAndFlushAsync();
        }
    }

    private static WebApplicationBuilder CreateBuilder(string[] args, CliOptions options)
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            Args = args,
            ContentRootPath = Directory.GetCurrentDirectory()
        });

        builder.Host.UseServiceProviderFactory(new AutofacServiceProviderFactory());
        builder.Host.UseSerilog((context, services, loggerConfiguration) =>
        {
            loggerConfiguration.ConfigureVapeCacheLogging(
                context.Configuration,
                services,
                context.HostingEnvironment.EnvironmentName);
        });
        builder.Host.ConfigureContainer<ContainerBuilder>(containerBuilder =>
        {
            containerBuilder.RegisterModule<ApplicationModule>();
            containerBuilder.RegisterModule<InfrastructureModule>();
            containerBuilder.RegisterModule<VapeCacheInMemoryModule>();
        });

        if (options.ServiceMode)
        {
            builder.Host.UseWindowsService();
        }

        if (options.UiMode || options.ServiceMode)
        {
            builder.WebHost.UseUrls(string.IsNullOrWhiteSpace(options.UiUrls) ? DefaultDashboardUrl : options.UiUrls);
        }

        builder.Services.AddLogging();
        builder.Services.AddOptions<ProviderIngressOptions>()
            .Bind(builder.Configuration.GetSection("ProviderIngress"));

        var providerIngressConnectionString = builder.Configuration.GetConnectionString("ProviderIngress")
                                             ?? builder.Configuration["ProviderIngress:ConnectionString"];
        builder.Services.AddPooledDbContextFactory<ProviderIngressDbContext>((serviceProvider, dbContextOptions) =>
        {
            var providerOptions = serviceProvider.GetRequiredService<IOptions<ProviderIngressOptions>>().Value;
            var databaseProvider = providerOptions.DatabaseProvider?.Trim().ToLowerInvariant() ?? "postgres";

            if (string.IsNullOrWhiteSpace(providerIngressConnectionString))
            {
                throw new InvalidOperationException("Provider ingress database connection string is missing. Configure ConnectionStrings:ProviderIngress.");
            }

            if (string.Equals(databaseProvider, "sqlite", StringComparison.OrdinalIgnoreCase))
            {
                dbContextOptions.UseSqlite(providerIngressConnectionString);
                return;
            }

            dbContextOptions.UseNpgsql(providerIngressConnectionString, npgsqlOptions =>
            {
                npgsqlOptions.EnableRetryOnFailure();
            });
        });

        var providerIngressOptions = builder.Configuration.GetSection("ProviderIngress").Get<ProviderIngressOptions>() ?? new ProviderIngressOptions();
        builder.Services.AddRateLimiter(rateLimiterOptions =>
        {
            rateLimiterOptions.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
            rateLimiterOptions.AddPolicy("provider-ingress", context =>
            {
                var providerId = context.Request.Headers["X-NpmRatPoison-Provider"].ToString();
                var remoteAddress = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
                var partitionKey = !string.IsNullOrWhiteSpace(providerId)
                    ? $"provider:{providerId.Trim().ToLowerInvariant()}"
                    : $"ip:{remoteAddress}";
                return RateLimitPartition.GetFixedWindowLimiter(
                    partitionKey,
                    _ => new FixedWindowRateLimiterOptions
                    {
                        PermitLimit = Math.Max(1, providerIngressOptions.RequestsPerMinute),
                        Window = TimeSpan.FromMinutes(1),
                        QueueLimit = 0,
                        AutoReplenishment = true
                    });
            });
        });
        builder.Services.AddOptions<CacheStampedeOptions>()
            .UseCacheStampedeProfile(CacheStampedeProfile.Balanced);
        builder.Services.AddNpmRatPoisonObservability(builder.Configuration);
        builder.Services.AddRazorComponents()
            .AddInteractiveServerComponents();

        builder.Services.AddSingleton<ScanDashboardState>();
        builder.Services.AddSingleton<DashboardScanCoordinator>();

        if (options.UiMode)
        {
            builder.Services.AddHostedService<DashboardLifecycleService>();
        }

        if (options.UiMode || options.ServiceMode)
        {
            builder.Services.AddHostedService<ProviderIngressDatabaseInitializerHostedService>();
        }

        if (options.ServiceMode)
        {
            builder.Services.AddSingleton(new ServiceScanOptions(options.ServiceIntervalMinutes, options.GitHubOnly, options.ReportDirectory, options.CatalogPath));
            builder.Services.AddHostedService<NpmThreatMonitorService>();
        }

        return builder;
    }

    private static void ConfigureServerSurface(WebApplication app, CliOptions options)
    {
        app.UseRateLimiter();
        LogProviderIngressConfiguration(app.Services);

        app.MapGet("/health", () => Results.Ok(new
        {
            status = "ok",
            service = "NpmRatPoison",
            version = BuildVersionText()
        }));

        app.MapGet("/api/provider-ingress/v1", (IOptions<ProviderIngressOptions> optionsAccessor) =>
        {
            var providerOptions = optionsAccessor.Value;
            return Results.Ok(new
            {
                service = "NpmRatPoison Provider Ingress",
                enabled = providerOptions.Enabled,
                endpoint = "/api/provider-ingress/v1/submissions",
                authentication = "rsa-pss-sha256",
                requiredHeaders = new[]
                {
                    "X-NpmRatPoison-Api-Key",
                    "X-NpmRatPoison-Provider",
                    "X-NpmRatPoison-Timestamp",
                    "X-NpmRatPoison-Signature"
                },
                timestampFormat = "ISO-8601 UTC",
                signatureFormat = "rsa-pss-sha256=<base64> or <base64>",
                configuredProviderCount = providerOptions.Providers.Count,
                replayCacheMinutes = providerOptions.ReplayCacheMinutes,
                maxPayloadBytes = providerOptions.MaxPayloadBytes,
                requiredPayloadFields = new[]
                {
                    "schemaVersion",
                    "documentType",
                    "providerDocumentId",
                    "publishedUtc",
                    "payload"
                },
                supportedDocumentTypes = new[]
                {
                    "vulnerability-advisory",
                    "patch-bundle",
                    "indicator-bundle",
                    "catalog-delta"
                },
                schemaEndpoint = "/api/provider-ingress/v1/schema",
                configuredProviders = providerOptions.Providers
                    .Where(pair => pair.Value.Enabled)
                    .Select(pair => new
                    {
                        providerId = pair.Key,
                        displayName = pair.Value.DisplayName ?? pair.Key,
                        contact = pair.Value.Contact,
                        allowedDocumentTypes = pair.Value.AllowedDocumentTypes
                    })
                    .OrderBy(entry => entry.providerId, StringComparer.OrdinalIgnoreCase)
                    .ToArray()
            });
        });

        app.MapGet("/api/provider-ingress/v1/schema", () =>
        {
            var schemaPath = Path.Combine(AppContext.BaseDirectory, "provider-ingress.schema.v1.json");
            return Results.File(schemaPath, "application/schema+json");
        });

        app.MapPost("/api/provider-ingress/v1/submissions", AcceptProviderIngressAsync)
            .DisableAntiforgery()
            .RequireRateLimiting("provider-ingress");

        if (!options.UiMode)
        {
            return;
        }

        var artifactsRoot = Path.Combine(Directory.GetCurrentDirectory(), "artifacts");
        Directory.CreateDirectory(artifactsRoot);

        app.UseStaticFiles();
        app.UseAntiforgery();
        app.UseStaticFiles(new StaticFileOptions
        {
            FileProvider = new PhysicalFileProvider(artifactsRoot),
            RequestPath = "/artifacts"
        });

        app.MapRazorComponents<NpmRatPoison.Components.App>()
            .AddInteractiveServerRenderMode();
    }

    private static async Task<IResult> AcceptProviderIngressAsync(
        HttpContext httpContext,
        IProviderApiKeyService providerApiKeyService,
        IProviderIngressService providerIngressService,
        IOptions<ProviderIngressOptions> optionsAccessor,
        CancellationToken cancellationToken)
    {
        var providerOptions = optionsAccessor.Value;
        var body = await ReadRequestBodyAsync(httpContext.Request, Math.Max(1024, providerOptions.MaxPayloadBytes), cancellationToken);
        if (body is null)
        {
            return Results.Json(
                new { accepted = false, message = "Payload exceeds the configured size limit." },
                statusCode: StatusCodes.Status413PayloadTooLarge);
        }

        var rawApiKey = httpContext.Request.Headers["X-NpmRatPoison-Api-Key"].ToString();
        var providerId = httpContext.Request.Headers["X-NpmRatPoison-Provider"].ToString();
        var timestamp = httpContext.Request.Headers["X-NpmRatPoison-Timestamp"].ToString();
        var signature = httpContext.Request.Headers["X-NpmRatPoison-Signature"].ToString();
        var apiKeyValidation = await providerApiKeyService.ValidateSignatureAsync(rawApiKey, providerId, timestamp, body, signature, cancellationToken);
        if (!apiKeyValidation.IsValid)
        {
            return Results.Json(
                new { accepted = false, message = apiKeyValidation.Message },
                statusCode: StatusCodes.Status401Unauthorized);
        }

        var submission = new ProviderIngressSubmission(
            ProviderId: providerId,
            ApiKeyId: apiKeyValidation.KeyId ?? string.Empty,
            Timestamp: timestamp,
            Signature: signature,
            BodyUtf8: body,
            ContentType: httpContext.Request.ContentType,
            RemoteIp: httpContext.Connection.RemoteIpAddress?.ToString(),
            UserAgent: httpContext.Request.Headers.UserAgent.ToString());

        var result = await providerIngressService.AcceptAsync(submission, cancellationToken);
        return Results.Json(
            new
            {
                accepted = result.Accepted,
                message = result.Message,
                submissionId = result.SubmissionId,
                isDuplicate = result.IsDuplicate,
                apiKeyId = apiKeyValidation.KeyId,
                providerDocumentId = result.ProviderDocumentId,
                documentType = result.DocumentType,
                payloadSha256 = result.PayloadSha256
            },
            statusCode: result.StatusCode);
    }

    private static async Task<byte[]?> ReadRequestBodyAsync(HttpRequest request, int maxPayloadBytes, CancellationToken cancellationToken)
    {
        if (request.ContentLength.HasValue && request.ContentLength.Value > maxPayloadBytes)
        {
            return null;
        }

        var buffer = new byte[8192];
        var initialCapacity = request.ContentLength.HasValue
            ? (int)Math.Min(request.ContentLength.Value, maxPayloadBytes)
            : Math.Min(maxPayloadBytes, 8192);
        await using var memoryStream = new MemoryStream(initialCapacity);

        while (true)
        {
            var bytesRead = await request.Body.ReadAsync(buffer.AsMemory(0, buffer.Length), cancellationToken);
            if (bytesRead == 0)
            {
                break;
            }

            if (memoryStream.Length + bytesRead > maxPayloadBytes)
            {
                return null;
            }

            await memoryStream.WriteAsync(buffer.AsMemory(0, bytesRead), cancellationToken);
        }

        return memoryStream.ToArray();
    }

    private static void LogProviderIngressConfiguration(IServiceProvider services)
    {
        var providerOptions = services.GetRequiredService<IOptions<ProviderIngressOptions>>().Value;
        var logger = services.GetRequiredService<ILoggerFactory>().CreateLogger("ProviderIngressConfiguration");

        if (!providerOptions.Enabled)
        {
            logger.LogInformation("Provider ingress is disabled.");
            return;
        }

        var configuration = services.GetRequiredService<IConfiguration>();
        var connectionString = configuration.GetConnectionString("ProviderIngress") ?? configuration["ProviderIngress:ConnectionString"];
        if (string.IsNullOrWhiteSpace(connectionString))
        {
            logger.LogWarning("Provider ingress is enabled, but ConnectionStrings:ProviderIngress is not configured.");
        }

        if (providerOptions.Providers.Count == 0)
        {
            logger.LogWarning("Provider ingress is enabled, but no providers are configured. All submissions will be rejected.");
            return;
        }

        logger.LogInformation("Provider ingress is using RSA-backed API credentials stored in the provider ingress database.");
    }

    private static async Task<int> ExecuteCliAsync(WebApplication app, CliOptions options)
    {
        await using var scope = app.Services.CreateAsyncScope();
        var services = scope.ServiceProvider;

        var progressPublisher = services.GetRequiredService<IScanProgressPublisher>();
        progressPublisher.Publish("startup", null, Directory.GetCurrentDirectory(), "Working directory detected");

        var catalogProvider = services.GetRequiredService<IThreatCatalogProvider>();
        var catalog = catalogProvider.Load(options.CatalogPath);
        if (!string.IsNullOrWhiteSpace(options.CatalogSha256))
        {
            catalog.ValidateSha256(options.CatalogSha256);
            if (catalog.Info.IntegrityStatus == CatalogIntegrityStatus.ValidationFailed)
            {
                Console.WriteLine($"Catalog validation failed: {catalog.Info.ValidationMessage}");
                return ScanExitCodeEvaluator.InvalidArguments;
            }
        }

        var reportWriter = services.GetRequiredService<IReportWriter>();

        if (options.GenerateProviderApiKey)
        {
            var providerIngressOptions = services.GetRequiredService<IOptions<ProviderIngressOptions>>().Value;
            if (!providerIngressOptions.Providers.TryGetValue(options.ProviderId!, out var providerConfiguration)
                || providerConfiguration is null
                || !providerConfiguration.Enabled)
            {
                Console.WriteLine($"Provider '{options.ProviderId}' is not configured or is disabled in ProviderIngress:Providers.");
                return ScanExitCodeEvaluator.InvalidArguments;
            }

            await ApplyProviderIngressMigrationsAsync(services);

            var apiKeyService = services.GetRequiredService<IProviderApiKeyService>();
            DateTimeOffset? expiresUtc = options.ProviderApiKeyExpiryDays.HasValue
                ? DateTimeOffset.UtcNow.AddDays(options.ProviderApiKeyExpiryDays.Value)
                : null;
            var generation = await apiKeyService.GenerateAsync(new ProviderApiKeyGenerationRequest(
                options.ProviderId!,
                options.ProviderApiKeyName,
                expiresUtc));

            Console.WriteLine("Provider RSA Credential Created");
            Console.WriteLine($"Provider: {generation.ProviderId}");
            Console.WriteLine($"KeyId: {generation.KeyId}");
            Console.WriteLine($"Name: {generation.Name}");
            Console.WriteLine($"CreatedUtc: {generation.CreatedUtc:O}");
            Console.WriteLine($"ExpiresUtc: {(generation.ExpiresUtc.HasValue ? generation.ExpiresUtc.Value.ToString("O") : "none")}");
            Console.WriteLine("PublicKeyPem:");
            Console.WriteLine(generation.PublicKeyPem);
            Console.WriteLine();
            Console.WriteLine("PrivateKeyPem:");
            Console.WriteLine(generation.PrivateKeyPem);
            Console.WriteLine();
            Console.WriteLine("Store the private key now. It is not retrievable again.");
            return ScanExitCodeEvaluator.Success;
        }

        if (options.ApplyProviderIngressMigrations)
        {
            await ApplyProviderIngressMigrationsAsync(services);
            Console.WriteLine("Provider ingress database migrations applied successfully.");
            return ScanExitCodeEvaluator.Success;
        }

        if (options.SimulateIncident)
        {
            var simulator = services.GetRequiredService<IIncidentSimulationService>();
            var simulationReport = await simulator.PlantAsync(options.RootPath, catalog);
            simulationReport.Print();
            await reportWriter.WriteAsync(options.ReportDirectory, "simulated-incident", simulationReport);
            return ScanExitCodeEvaluator.Success;
        }

        if (options.RemoteGitHubScan)
        {
            var gitHubAccessTokenResolver = services.GetRequiredService<IGitHubAccessTokenResolver>();
            var remoteGitHubScanService = services.GetRequiredService<IRemoteGitHubScanService>();
            var accessToken = gitHubAccessTokenResolver.ResolveAccessToken(options.GitHubAccessToken);
            var remoteScanRequest = new RemoteGitHubScanRequest(
                options.RemoteGitHubOrganization,
                options.RemoteGitHubUser,
                options.RemoteGitHubRepositories,
                accessToken);
            var remoteReport = await remoteGitHubScanService.ExecuteAsync(remoteScanRequest, catalog);
            remoteReport.Print();
            await reportWriter.WriteAsync(options.ReportDirectory, "remote-github-scan", remoteReport);
            return ScanExitCodeEvaluator.GetExitCode(remoteReport);
        }

        if (options.Auto)
        {
            var autoTriageService = services.GetRequiredService<IAutoTriageService>();
            var autoReport = await autoTriageService.ExecuteAsync(options.RootPath, options.PathProvided, options.GitHubOnly, catalog);
            if (options.SafeDirectoryOnly)
            {
                var assistReport = SafeDirectoryAssistReport.FromAutoTriageReport(autoReport);
                assistReport.Print();
                await ApplySafeDirectoryAssistAsync(autoReport.GetSafeDirectoryPaths(), options.ApplySafeDirectoryAssist);
                await reportWriter.WriteAsync(options.ReportDirectory, "safe-directory-assist", assistReport);
                return ScanExitCodeEvaluator.GetExitCode(autoReport);
            }

            autoReport.Print();
            await ApplySafeDirectoryAssistAsync(autoReport.GetSafeDirectoryPaths(), options.ApplySafeDirectoryAssist);
            PrintSafeDirectoryAssist(autoReport.GetSafeDirectoryCommands(), options.SafeDirectoryAssist);
            await reportWriter.WriteAsync(options.ReportDirectory, "auto-triage", autoReport);
            return ScanExitCodeEvaluator.GetExitCode(autoReport);
        }

        if (options.AllDrives)
        {
            var allDriveScanService = services.GetRequiredService<IAllDriveScanService>();
            var allDriveReport = await allDriveScanService.ExecuteAsync(options.DryRun, options.GitHubOnly, catalog);
            if (options.SafeDirectoryOnly)
            {
                var assistReport = SafeDirectoryAssistReport.FromAllDriveScanReport(allDriveReport);
                assistReport.Print();
                await ApplySafeDirectoryAssistAsync(allDriveReport.GetSafeDirectoryPaths(), options.ApplySafeDirectoryAssist);
                await reportWriter.WriteAsync(options.ReportDirectory, "safe-directory-assist", assistReport);
                return ScanExitCodeEvaluator.GetExitCode(allDriveReport);
            }

            allDriveReport.Print();
            await ApplySafeDirectoryAssistAsync(allDriveReport.GetSafeDirectoryPaths(), options.ApplySafeDirectoryAssist);
            PrintSafeDirectoryAssist(allDriveReport.GetSafeDirectoryCommands(), options.SafeDirectoryAssist);
            await reportWriter.WriteAsync(options.ReportDirectory, "all-drives", allDriveReport);
            return ScanExitCodeEvaluator.GetExitCode(allDriveReport);
        }

        var cleanupService = services.GetRequiredService<IThreatCleanupService>();
        var cleanupReport = await cleanupService.ExecuteAsync(options.RootPath, options.DryRun, catalog, includeHostLevelChecks: options.EnableHostRemediation);
        if (options.SafeDirectoryOnly)
        {
            var assistReport = SafeDirectoryAssistReport.FromCleanupReport(cleanupReport);
            assistReport.Print();
            await ApplySafeDirectoryAssistAsync(cleanupReport.GetSafeDirectoryPaths(), options.ApplySafeDirectoryAssist);
            await reportWriter.WriteAsync(options.ReportDirectory, "safe-directory-assist", assistReport);
            return ScanExitCodeEvaluator.GetExitCode(cleanupReport);
        }

        cleanupReport.Print();
        if (!options.EnableHostRemediation)
        {
            Console.WriteLine();
            Console.WriteLine("Host remediation is disabled by default. Re-run with --host-remediation to sanitize shell profiles and host artifacts.");
        }
        await ApplySafeDirectoryAssistAsync(cleanupReport.GetSafeDirectoryPaths(), options.ApplySafeDirectoryAssist);
        PrintSafeDirectoryAssist(cleanupReport.GetSafeDirectoryCommands(), options.SafeDirectoryAssist);
        await reportWriter.WriteAsync(options.ReportDirectory, "cleanup", cleanupReport);
        return ScanExitCodeEvaluator.GetExitCode(cleanupReport);
    }

    private static void PrintSafeDirectoryAssist(IEnumerable<string> commands, bool enabled)
    {
        if (!enabled)
        {
            return;
        }

        var materialized = commands
            .Where(command => !string.IsNullOrWhiteSpace(command))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        Console.WriteLine();
        Console.WriteLine($"SafeDirectoryAssist: {materialized.Count}");
        foreach (var command in materialized)
        {
            Console.WriteLine($" - {command}");
        }
    }

    private static async Task ApplyProviderIngressMigrationsAsync(IServiceProvider services)
    {
        var dbContextFactory = services.GetRequiredService<IDbContextFactory<ProviderIngressDbContext>>();
        var providerIngressOptions = services.GetRequiredService<IOptions<ProviderIngressOptions>>().Value;
        await using var dbContext = await dbContextFactory.CreateDbContextAsync();
        if (string.Equals(providerIngressOptions.DatabaseProvider, "sqlite", StringComparison.OrdinalIgnoreCase))
        {
            await dbContext.Database.EnsureCreatedAsync();
            return;
        }

        await dbContext.Database.MigrateAsync();
    }

    private static async Task ApplySafeDirectoryAssistAsync(IEnumerable<string> repositoryPaths, bool enabled)
    {
        if (!enabled)
        {
            return;
        }

        var requestedPaths = repositoryPaths
            .Where(path => !string.IsNullOrWhiteSpace(path))
            .Select(path => Path.GetFullPath(path))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (requestedPaths.Count == 0)
        {
            Console.WriteLine();
            Console.WriteLine("SafeDirectoryAssistApply: 0");
            Console.WriteLine("No safe.directory blocks were detected.");
            return;
        }

        var existingPaths = await GetExistingSafeDirectoriesAsync();
        var appliedCount = 0;
        var skippedCount = 0;

        Console.WriteLine();
        Console.WriteLine($"SafeDirectoryAssistApply: {requestedPaths.Count}");

        foreach (var path in requestedPaths)
        {
            var normalized = path.Replace('\\', '/');
            if (existingPaths.Contains(normalized))
            {
                skippedCount++;
                Console.WriteLine($" - skipped: {normalized}");
                continue;
            }

            var result = await RunGitConfigAsync("config", "--global", "--add", "safe.directory", normalized);
            if (!result.Success)
            {
                Console.WriteLine($" - failed: {normalized}");
                Console.WriteLine($"   {result.Error}");
                continue;
            }

            appliedCount++;
            existingPaths.Add(normalized);
            Console.WriteLine($" - applied: {normalized}");
        }

        Console.WriteLine($"SafeDirectoryAssistApplyResult: applied={appliedCount}, skipped={skippedCount}");
    }

    private static async Task<HashSet<string>> GetExistingSafeDirectoriesAsync()
    {
        var result = await RunGitConfigAsync("config", "--global", "--get-all", "safe.directory");
        if (!result.Success)
        {
            return new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        }

        return result.Output
            .Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries)
            .Select(line => line.Trim().Replace('\\', '/'))
            .Where(line => !string.IsNullOrWhiteSpace(line))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
    }

    private static async Task<GitCommandResult> RunGitConfigAsync(params string[] args)
    {
        try
        {
            var startInfo = new ProcessStartInfo
            {
                FileName = "git",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            foreach (var arg in args)
            {
                startInfo.ArgumentList.Add(arg);
            }

            using var process = Process.Start(startInfo);
            if (process is null)
            {
                return new GitCommandResult(false, string.Empty, "Failed to start git.");
            }

            var outputTask = process.StandardOutput.ReadToEndAsync();
            var errorTask = process.StandardError.ReadToEndAsync();
            await process.WaitForExitAsync();
            var output = await outputTask;
            var error = await errorTask;

            return process.ExitCode == 0
                ? new GitCommandResult(true, output, error)
                : new GitCommandResult(false, output, error);
        }
        catch (Exception ex)
        {
            return new GitCommandResult(false, string.Empty, ex.Message);
        }
    }

    private static string BuildHelpText()
    {
        return """
NpmRatPoison

Usage:
  NpmRatPoison --help
  NpmRatPoison --version
  NpmRatPoison --apply-provider-ingress-migrations
  NpmRatPoison --apply-safe-directory-assist [--path <directory> | --all-drives | --auto] [--include-non-github] [--report-dir <directory>]
  NpmRatPoison --generate-provider-api-key --provider-id <provider> [--provider-api-key-name <name>] [--provider-api-key-expiry-days <days>]
  NpmRatPoison --ui [--service] [--urls <url>]
  NpmRatPoison --path <directory> [--dry-run] [--report-dir <directory>]
  NpmRatPoison --all-drives [--include-non-github] [--report-dir <directory>]
  NpmRatPoison --auto [--path <directory>] [--include-non-github] [--report-dir <directory>]
  NpmRatPoison --safe-directory-only [--path <directory> | --all-drives | --auto] [--include-non-github] [--report-dir <directory>]
  NpmRatPoison --simulate-incident --path <directory> [--report-dir <directory>]
  NpmRatPoison --remote-github-scan (--remote-github-org <org> | --remote-github-user <user> | --remote-github-repo <owner/name>...) [--github-token <token>] [--report-dir <directory>]

Options:
  --help                   Show this help text and exit.
  --version                Show the tool version and exit.
  --apply-provider-ingress-migrations
                           Apply EF Core migrations for the provider ingress database and exit.
  --apply-safe-directory-assist
                           Add trusted blocked repositories to git safe.directory automatically.
  --generate-provider-api-key
                           Create a database-backed RSA credential for provider ingress.
  --provider-id <provider> Provider identifier for RSA credential generation.
  --provider-api-key-name <name>
                           Friendly display name for the generated API key.
  --provider-api-key-expiry-days <days>
                           Optional API key lifetime in days.
  --ui                     Start the Blazor operations dashboard.
  --urls <url>             Bind server endpoints for UI and/or service mode.
  --path <directory>       Scan or simulate within a specific directory.
  --dry-run                Report changes without modifying files.
  --all-drives             Discover git repositories across all ready drives.
  --auto                   Auto-select scoped or all-drive triage behavior.
  --include-non-github     Include non-GitHub repositories in discovery scans.
  --report-dir <directory> Write JSON, CSV, and HTML reports to the given directory.
  --catalog <file>         Load a custom threat catalog JSON file.
  --catalog-sha256 <hash>  Validate the loaded threat catalog digest before running.
  --safe-directory-assist  Print git safe.directory commands for blocked repos.
  --safe-directory-only    Output only safe.directory-blocked repositories and commands.
  --host-remediation       Allow shell profile and host artifact cleanup in scoped cleanup mode.
  --simulate-incident      Plant a simulated axios/plain-crypto-js incident in the target path.
  --remote-github-scan     Scan GitHub repositories remotely without cloning.
  --remote-github-org      Scan every repository visible in the given GitHub organization.
  --remote-github-user     Scan every repository visible for the given GitHub user.
  --remote-github-repo     Scan a specific GitHub repository, repeatable.
  --github-token <token>   GitHub token for private repos or higher API rate limits.
  --service                Run background service mode.
  --service-interval-minutes <n>
                           Set service scan interval in minutes.

Notes:
  If no explicit mode is provided, the app defaults to an all-drives dry-run scan.
  --simulate-incident requires --path so the target location is explicit.
  Lockfiles are quarantined and must be regenerated instead of being patched in place.
  Host remediation is opt-in and only applies to scoped cleanup mode.
  Remote GitHub scans prompt for a personal access token when one is not already supplied.
  Provider submissions POST JSON to /api/provider-ingress/v1/submissions using API key id + RSA-PSS signature headers.
  The dashboard binds to http://127.0.0.1:5100 by default when --ui or --service is used without --urls.
  The Blazor dashboard publishes report artifacts under ./artifacts/dashboard-reports.
""";
    }

    private static string BuildVersionText()
    {
        var assembly = typeof(Program).Assembly;
        var informationalVersion = assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
                                   ?? assembly.GetName().Version?.ToString()
                                   ?? "unknown";
        return $"NpmRatPoison {informationalVersion}";
    }

    private sealed record GitCommandResult(bool Success, string Output, string Error);
}
