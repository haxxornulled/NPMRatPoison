using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using VapeCache.Abstractions.Caching;

namespace NpmRatPoison.Tests;

public class ProgramTests
{
    [Fact]
    public void CliOptions_Parse_AutoAndPath_AreCaptured()
    {
        var args = new[] { "--auto", "--path", ".", "--include-non-github", "--safe-directory-assist", "--report-dir", ".\\reports" };

        var options = CliOptions.Parse(args);

        Assert.True(options.Auto);
        Assert.True(options.PathProvided);
        Assert.False(options.GitHubOnly);
        Assert.True(options.SafeDirectoryAssist);
        Assert.True(options.DryRun);
        Assert.False(options.AllDrives);
        Assert.False(string.IsNullOrWhiteSpace(options.ReportDirectory));
    }

    [Fact]
    public void CliOptions_Parse_Help_StopsDefaultScanSelection()
    {
        var options = CliOptions.Parse(["--help"]);

        Assert.True(options.ShowHelp);
        Assert.False(options.AllDrives);
        Assert.False(options.Auto);
    }

    [Fact]
    public void CliOptions_Parse_UiMode_StopsDefaultScanSelection()
    {
        var options = CliOptions.Parse(["--ui", "--urls", "http://127.0.0.1:5099"]);

        Assert.True(options.UiMode);
        Assert.Equal("http://127.0.0.1:5099", options.UiUrls);
        Assert.False(options.AllDrives);
        Assert.False(options.Auto);
    }

    [Fact]
    public void CliOptions_Parse_UiAndServiceMode_AreAllowedTogether()
    {
        var options = CliOptions.Parse(["--ui", "--service", "--urls", "http://127.0.0.1:5099"]);

        Assert.True(options.UiMode);
        Assert.True(options.ServiceMode);
        Assert.Equal("http://127.0.0.1:5099", options.UiUrls);
        Assert.True(options.AllDrives);
        Assert.True(options.Auto);
    }

    [Fact]
    public void CliOptions_Parse_RemoteGitHubScan_CapturesTargets()
    {
        var options = CliOptions.Parse([
            "--remote-github-scan",
            "--remote-github-org", "octo-org",
            "--remote-github-repo", "octo-org/service-a",
            "--remote-github-repo", "octo-org/service-b",
            "--github-token", "test-token"
        ]);

        Assert.True(options.RemoteGitHubScan);
        Assert.Equal("octo-org", options.RemoteGitHubOrganization);
        Assert.Equal(2, options.RemoteGitHubRepositories.Count);
        Assert.Equal("test-token", options.GitHubAccessToken);
        Assert.True(options.DryRun);
    }

    [Fact]
    public void CliOptions_Parse_VersionAndSafetyOptions_AreCaptured()
    {
        var options = CliOptions.Parse([
            "--version",
            "--path", ".",
            "--host-remediation",
            "--catalog", ".\\threat-catalog.json",
            "--catalog-sha256", "abc123"
        ]);

        Assert.True(options.ShowVersion);
        Assert.True(options.EnableHostRemediation);
        Assert.Equal("abc123", options.CatalogSha256);
        Assert.False(string.IsNullOrWhiteSpace(options.CatalogPath));
    }

    [Fact]
    public void GitHubAccessTokenResolver_ReturnsConfiguredTokenWithoutPrompt()
    {
        var prompt = new FakeGitHubCredentialPrompt("prompt-token");
        var resolver = new GitHubAccessTokenResolver(prompt);

        var result = resolver.ResolveAccessToken("configured-token");

        Assert.Equal("configured-token", result);
        Assert.Equal(0, prompt.CallCount);
    }

    [Fact]
    public void GitHubAccessTokenResolver_PromptsWhenConfiguredTokenIsMissing()
    {
        var prompt = new FakeGitHubCredentialPrompt("prompt-token");
        var resolver = new GitHubAccessTokenResolver(prompt);

        var result = resolver.ResolveAccessToken(null);

        Assert.Equal("prompt-token", result);
        Assert.Equal(1, prompt.CallCount);
    }

    [Fact]
    public void ConsoleGitHubCredentialPrompt_ReturnsNullWhenInputIsRedirected()
    {
        var console = new FakeConsoleRuntime(isInputRedirected: true);
        var prompt = new ConsoleGitHubCredentialPrompt(console);

        var result = prompt.PromptForAccessToken();

        Assert.Null(result);
        Assert.Empty(console.Writes);
        Assert.Equal(0, console.ReadKeyCallCount);
    }

    [Fact]
    public void ConsoleGitHubCredentialPrompt_ReturnsNullWhenUserPressesEnter()
    {
        var console = new FakeConsoleRuntime(
            isInputRedirected: false,
            [
                new ConsoleKeyInfo('\r', ConsoleKey.Enter, shift: false, alt: false, control: false)
            ]);
        var prompt = new ConsoleGitHubCredentialPrompt(console);

        var result = prompt.PromptForAccessToken();

        Assert.Null(result);
        Assert.Equal(1, console.ReadKeyCallCount);
        Assert.Contains(console.Writes, value => value.Contains("GitHub authentication", StringComparison.Ordinal));
        Assert.Contains(console.Writes, value => value.Contains("Token (press Enter to continue unauthenticated): ", StringComparison.Ordinal));
    }

    [Fact]
    public void ConsoleGitHubCredentialPrompt_ReturnsTypedTokenAndHonorsBackspace()
    {
        var console = new FakeConsoleRuntime(
            isInputRedirected: false,
            [
                new ConsoleKeyInfo('a', ConsoleKey.A, shift: false, alt: false, control: false),
                new ConsoleKeyInfo('b', ConsoleKey.B, shift: false, alt: false, control: false),
                new ConsoleKeyInfo('\0', ConsoleKey.Backspace, shift: false, alt: false, control: false),
                new ConsoleKeyInfo('c', ConsoleKey.C, shift: false, alt: false, control: false),
                new ConsoleKeyInfo('\r', ConsoleKey.Enter, shift: false, alt: false, control: false)
            ]);
        var prompt = new ConsoleGitHubCredentialPrompt(console);

        var result = prompt.PromptForAccessToken();

        Assert.Equal("ac", result);
        Assert.Equal(5, console.ReadKeyCallCount);
    }

    [Fact]
    public void CliOptions_Parse_GenerateProviderApiKey_CapturesArguments()
    {
        var options = CliOptions.Parse([
            "--generate-provider-api-key",
            "--provider-id", "step-security",
            "--provider-api-key-name", "Primary feed credential",
            "--provider-api-key-expiry-days", "90"
        ]);

        Assert.True(options.GenerateProviderApiKey);
        Assert.Equal("step-security", options.ProviderId);
        Assert.Equal("Primary feed credential", options.ProviderApiKeyName);
        Assert.Equal(90, options.ProviderApiKeyExpiryDays);
        Assert.False(options.AllDrives);
    }

    [Fact]
    public void CliOptions_Parse_ApplyProviderIngressMigrations_IsCaptured()
    {
        var options = CliOptions.Parse([
            "--apply-provider-ingress-migrations"
        ]);

        Assert.True(options.ApplyProviderIngressMigrations);
        Assert.False(options.AllDrives);
    }

    [Fact]
    public void CliOptions_Parse_ApplySafeDirectoryAssist_IsCaptured()
    {
        var options = CliOptions.Parse([
            "--all-drives",
            "--apply-safe-directory-assist"
        ]);

        Assert.True(options.ApplySafeDirectoryAssist);
        Assert.True(options.SafeDirectoryAssist);
        Assert.True(options.AllDrives);
    }

    [Fact]
    public async Task ProviderIngressDatabaseInitializerHostedService_StartAsync_DoesNotThrowWhenDatabaseIsUnavailable()
    {
        var options = Options.Create(new ProviderIngressOptions
        {
            Enabled = true,
            AutoInitializeDatabase = true,
            DatabaseProvider = "postgres"
        });

        var service = new ProviderIngressDatabaseInitializerHostedService(
            new ThrowingProviderIngressDbContextFactory(),
            options,
            NullLogger<ProviderIngressDatabaseInitializerHostedService>.Instance);

        await service.StartAsync(CancellationToken.None);
    }

    [Fact]
    public async Task ProviderApiKeyService_GenerateAsync_PersistsRsaCredential_AndValidateSignatureAsync_Succeeds()
    {
        var root = CreateTempDirectory();

        try
        {
            var dbPath = Path.Combine(root, "provider-ingress.db");
            var providerOptions = Options.Create(CreateProviderIngressOptions());
            var dbContextFactory = CreateProviderIngressDbContextFactory(dbPath);
            await EnsureProviderIngressDatabaseAsync(dbContextFactory);

            var service = new ProviderApiKeyService(dbContextFactory, new FakeVapeCache(), NullLogger<ProviderApiKeyService>.Instance);
            var generated = await service.GenerateAsync(new ProviderApiKeyGenerationRequest("step-security", "Primary RSA credential", DateTimeOffset.UtcNow.AddDays(30)));

            Assert.Equal("step-security", generated.ProviderId);
            Assert.Contains("BEGIN PRIVATE KEY", generated.PrivateKeyPem, StringComparison.Ordinal);
            Assert.Contains("BEGIN RSA PUBLIC KEY", generated.PublicKeyPem, StringComparison.Ordinal);

            var body = """
            {
              "schemaVersion": "1.0",
              "documentType": "vulnerability-advisory",
              "providerDocumentId": "rsa-demo-001",
              "publishedUtc": "2026-04-03T00:00:00Z",
              "payload": {
                "packages": [ "axios" ]
              }
            }
            """;
            var timestamp = DateTimeOffset.UtcNow.ToString("O");
            var signature = GenerateRsaSignature(generated.PrivateKeyPem, "step-security", timestamp, body);

            var validation = await service.ValidateSignatureAsync(
                generated.KeyId,
                "step-security",
                timestamp,
                Encoding.UTF8.GetBytes(body),
                signature);

            Assert.True(validation.IsValid);
            Assert.Equal(generated.KeyId, validation.KeyId);
        }
        finally
        {
            DeleteDirectoryRobust(root);
        }
    }

    [Fact]
    public async Task ProviderIngressService_AcceptAsync_StoresValidatedSubmissionInDatabase()
    {
        var root = CreateTempDirectory();

        try
        {
            var dbPath = Path.Combine(root, "provider-ingress.db");
            var dbContextFactory = CreateProviderIngressDbContextFactory(dbPath);
            await EnsureProviderIngressDatabaseAsync(dbContextFactory);
            var service = CreateProviderIngressService(Options.Create(CreateProviderIngressOptions()), dbContextFactory);

            var payload = """
            {
              "schemaVersion": "1.0",
              "documentType": "vulnerability-advisory",
              "providerDocumentId": "demo-001",
              "publishedUtc": "2026-04-03T00:00:00Z",
              "title": "Axios compromise advisory",
              "summary": "Demo advisory payload",
              "severity": "critical",
              "tags": [ "npm", "axios" ],
              "payload": {
                "packages": [ "axios" ]
              }
            }
            """;

            var result = await service.AcceptAsync(new ProviderIngressSubmission(
                ProviderId: "step-security",
                ApiKeyId: "pak_test_001",
                Timestamp: DateTimeOffset.UtcNow.ToString("O"),
                Signature: "rsa-pss-sha256=unused-at-service-layer",
                BodyUtf8: Encoding.UTF8.GetBytes(payload),
                ContentType: "application/json",
                RemoteIp: "127.0.0.1",
                UserAgent: "provider-test"));

            Assert.True(result.Accepted);
            Assert.Equal(202, result.StatusCode);
            Assert.StartsWith("db://provider_ingress_documents/", result.StoredPath, StringComparison.Ordinal);
            Assert.Equal("demo-001", result.ProviderDocumentId);

            await using var dbContext = await dbContextFactory.CreateDbContextAsync();
            var stored = await dbContext.ProviderIngressDocuments.SingleAsync();
            Assert.Equal("step-security", stored.ProviderId);
            Assert.Equal("pak_test_001", stored.ApiKeyId);
            Assert.Equal("vulnerability-advisory", stored.DocumentType);
            Assert.Contains("\"ProviderDocumentId\":\"demo-001\"", stored.EnvelopeJson, StringComparison.Ordinal);
        }
        finally
        {
            DeleteDirectoryRobust(root);
        }
    }

    [Fact]
    public async Task ProviderIngressService_AcceptAsync_RejectsStaleTimestamp()
    {
        var root = CreateTempDirectory();

        try
        {
            var dbContextFactory = CreateProviderIngressDbContextFactory(Path.Combine(root, "provider-ingress.db"));
            await EnsureProviderIngressDatabaseAsync(dbContextFactory);
            var service = CreateProviderIngressService(
                Options.Create(CreateProviderIngressOptions(allowedClockSkewMinutes: 1)),
                dbContextFactory);

            var result = await service.AcceptAsync(new ProviderIngressSubmission(
                ProviderId: "step-security",
                ApiKeyId: "pak_test_001",
                Timestamp: DateTimeOffset.UtcNow.AddMinutes(-15).ToString("O"),
                Signature: "rsa-pss-sha256=unused-at-service-layer",
                BodyUtf8: Encoding.UTF8.GetBytes("""
                {
                  "schemaVersion": "1.0",
                  "documentType": "patch-bundle",
                  "providerDocumentId": "demo-003",
                  "publishedUtc": "2026-04-03T00:00:00Z",
                  "payload": {
                    "patches": [ "1.14.0" ]
                  }
                }
                """),
                ContentType: "application/json",
                RemoteIp: "127.0.0.1",
                UserAgent: "provider-test"));

            Assert.False(result.Accepted);
            Assert.Equal(401, result.StatusCode);
            Assert.Contains("clock skew", result.Message, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            DeleteDirectoryRobust(root);
        }
    }

    [Fact]
    public async Task ProviderIngressService_AcceptAsync_AcknowledgesDuplicateSubmissionWithoutPersistingAgain()
    {
        var root = CreateTempDirectory();

        try
        {
            var dbContextFactory = CreateProviderIngressDbContextFactory(Path.Combine(root, "provider-ingress.db"));
            await EnsureProviderIngressDatabaseAsync(dbContextFactory);
            var service = CreateProviderIngressService(
                Options.Create(CreateProviderIngressOptions(replayCacheMinutes: 60, allowedDocumentTypes: [ "catalog-delta" ])),
                dbContextFactory);

            var payload = """
            {
              "schemaVersion": "1.0",
              "documentType": "catalog-delta",
              "providerDocumentId": "demo-004",
              "publishedUtc": "2026-04-03T00:00:00Z",
              "payload": {
                "packages": [ "axios" ]
              }
            }
            """;

            var first = await service.AcceptAsync(new ProviderIngressSubmission(
                "step-security",
                "pak_test_001",
                DateTimeOffset.UtcNow.ToString("O"),
                "rsa-pss-sha256=unused-at-service-layer",
                Encoding.UTF8.GetBytes(payload),
                "application/json",
                "127.0.0.1",
                "provider-test"));

            var second = await service.AcceptAsync(new ProviderIngressSubmission(
                "step-security",
                "pak_test_001",
                DateTimeOffset.UtcNow.ToString("O"),
                "rsa-pss-sha256=unused-at-service-layer",
                Encoding.UTF8.GetBytes(payload),
                "application/json",
                "127.0.0.1",
                "provider-test"));

            Assert.True(first.Accepted);
            Assert.False(first.IsDuplicate);
            Assert.True(second.Accepted);
            Assert.True(second.IsDuplicate);

            await using var dbContext = await dbContextFactory.CreateDbContextAsync();
            Assert.Equal(1, await dbContext.ProviderIngressDocuments.CountAsync());
        }
        finally
        {
            DeleteDirectoryRobust(root);
        }
    }

    [Fact]
    public async Task ProviderIngressService_AcceptAsync_RejectsDisallowedDocumentTypeForProvider()
    {
        var root = CreateTempDirectory();

        try
        {
            var dbContextFactory = CreateProviderIngressDbContextFactory(Path.Combine(root, "provider-ingress.db"));
            await EnsureProviderIngressDatabaseAsync(dbContextFactory);
            var service = CreateProviderIngressService(
                Options.Create(CreateProviderIngressOptions(allowedDocumentTypes: [ "patch-bundle" ])),
                dbContextFactory);

            var result = await service.AcceptAsync(new ProviderIngressSubmission(
                "step-security",
                "pak_test_001",
                DateTimeOffset.UtcNow.ToString("O"),
                "rsa-pss-sha256=unused-at-service-layer",
                Encoding.UTF8.GetBytes("""
                {
                  "schemaVersion": "1.0",
                  "documentType": "indicator-bundle",
                  "providerDocumentId": "demo-006",
                  "publishedUtc": "2026-04-03T00:00:00Z",
                  "payload": {
                    "indicators": [ "bad.example" ]
                  }
                }
                """),
                "application/json",
                "127.0.0.1",
                "provider-test"));

            Assert.False(result.Accepted);
            Assert.Equal(403, result.StatusCode);
            Assert.Contains("not allowed", result.Message, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            DeleteDirectoryRobust(root);
        }
    }

    [Fact]
    public void CleanupReport_HasFindings_FalseWhenEmpty_TrueWhenAnySectionHasData()
    {
        var report = new CleanupReport(dryRun: true, rootPath: "C:\\temp");
        Assert.False(report.HasFindings());

        report.Flags.Add("hit");
        Assert.True(report.HasFindings());
    }

    [Fact]
    public void ScanExitCodeEvaluator_MapsCleanupSeverityToExpectedExitCodes()
    {
        var clean = new CleanupReport(dryRun: true, rootPath: "C:\\clean");
        var critical = new CleanupReport(dryRun: true, rootPath: "C:\\critical");
        critical.Flags.Add("flag");
        var errored = new CleanupReport(dryRun: true, rootPath: "C:\\error");
        errored.Errors.Add("error");

        Assert.Equal(ScanExitCodeEvaluator.Success, ScanExitCodeEvaluator.GetExitCode(clean));
        Assert.Equal(ScanExitCodeEvaluator.CriticalFindings, ScanExitCodeEvaluator.GetExitCode(critical));
        Assert.Equal(ScanExitCodeEvaluator.ExecutionErrors, ScanExitCodeEvaluator.GetExitCode(errored));
    }

    [Fact]
    public void CleanupReport_AddGitAccessIssue_CapturesTypedReasonAndSafeDirectoryCommand()
    {
        var report = new CleanupReport(dryRun: true, rootPath: "D:\\Recovered\\Repo");

        report.AddGitAccessIssue(
            "Unable to query git history: fatal: detected dubious ownership in repository.",
            GitQueryBlockReason.SafeDirectory,
            "D:\\Recovered\\Repo");

        Assert.Single(report.GitIssues);
        Assert.Equal(GitIssueKind.QueryBlocked, report.GitIssues[0].Kind);
        Assert.Equal(GitQueryBlockReason.SafeDirectory, report.GitIssues[0].QueryBlockReason);
        Assert.Single(report.GetSafeDirectoryCommands());
        Assert.Contains("git config --global --add safe.directory", report.GetSafeDirectoryCommands()[0], StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task AxiosCompromiseCleaner_LiveRun_RemediatesPackageJsonAndDeletesSuspiciousDirectory()
    {
        var root = CreateTempDirectory();

        try
        {
            var packageJsonPath = Path.Combine(root, "package.json");
            File.WriteAllText(packageJsonPath, """
            {
              "dependencies": {
                "axios": "1.14.1",
                "plain-crypto-js": "4.2.1"
              }
            }
            """);

            var suspiciousDir = Path.Combine(root, "node_modules", "plain-crypto-js");
            Directory.CreateDirectory(suspiciousDir);

            var cleaner = new ThreatCleanupService(new TestProgressPublisher(), NullLogger<ThreatCleanupService>.Instance);
            var report = await cleaner.ExecuteAsync(root, dryRun: false, catalog: ThreatCatalog.CreateDefault(), includeHostLevelChecks: false);

            var rootNode = JsonNode.Parse(File.ReadAllText(packageJsonPath))!.AsObject();
            var dependencies = rootNode["dependencies"]!.AsObject();

            Assert.Equal("1.14.0", dependencies["axios"]!.GetValue<string>());
            Assert.False(dependencies.ContainsKey("plain-crypto-js"));
            Assert.False(Directory.Exists(suspiciousDir));
            Assert.True(report.Remediations.Count > 0);
            Assert.True(report.Removals.Count > 0);
        }
        finally
        {
            DeleteDirectoryRobust(root);
        }
    }

    [Fact]
    public async Task ThreatCleanupService_LiveRun_QuarantinesCompromisedLockfileInsteadOfPatchingIt()
    {
        var root = CreateTempDirectory();

        try
        {
            var lockfilePath = Path.Combine(root, "package-lock.json");
            File.WriteAllText(lockfilePath, """
            {
              "packages": {
                "": {
                  "dependencies": {
                    "axios": "1.14.1",
                    "plain-crypto-js": "4.2.1"
                  }
                },
                "node_modules/axios": {
                  "version": "1.14.1",
                  "resolved": "https://registry.npmjs.org/axios/-/axios-1.14.1.tgz"
                },
                "node_modules/plain-crypto-js": {
                  "version": "4.2.1",
                  "resolved": "http://sfrclak.com:8000/plain-crypto-js-4.2.1.tgz"
                }
              }
            }
            """);

            var cleaner = new ThreatCleanupService(new TestProgressPublisher(), NullLogger<ThreatCleanupService>.Instance);
            var report = await cleaner.ExecuteAsync(root, dryRun: false, catalog: ThreatCatalog.CreateDefault(), includeHostLevelChecks: false);

            Assert.False(File.Exists(lockfilePath));
            var quarantinedLockfiles = Directory.GetFiles(Path.Combine(root, ".npmratpoison", "quarantine"), "package-lock.json", SearchOption.AllDirectories);
            Assert.Single(quarantinedLockfiles);
            Assert.Contains(report.Remediations, item => item.Contains("Quarantined compromised lockfile", StringComparison.OrdinalIgnoreCase));
            Assert.Contains(report.Removals, item => item.Contains("Removed compromised lockfile", StringComparison.OrdinalIgnoreCase));
        }
        finally
        {
            DeleteDirectoryRobust(root);
        }
    }

    [Fact]
    public async Task ThreatCleanupService_LiveRun_DoesNotRescanToolQuarantineDirectory()
    {
        var root = CreateTempDirectory();

        try
        {
            File.WriteAllText(Path.Combine(root, "package-lock.json"), """
            { "packages": { "node_modules/plain-crypto-js": { "version": "4.2.1" } } }
            """);
            File.WriteAllText(Path.Combine(root, "yarn.lock"), """
            plain-crypto-js@4.2.1:
              resolved "http://sfrclak.com:8000/plain-crypto-js-4.2.1.tgz"
            """);
            File.WriteAllText(Path.Combine(root, "pnpm-lock.yaml"), """
            packages:
              /plain-crypto-js/4.2.1:
                resolution: { tarball: http://sfrclak.com:8000/plain-crypto-js-4.2.1.tgz }
            """);

            var cleaner = new ThreatCleanupService(new TestProgressPublisher(), NullLogger<ThreatCleanupService>.Instance);
            await cleaner.ExecuteAsync(root, dryRun: false, catalog: ThreatCatalog.CreateDefault(), includeHostLevelChecks: false);

            var quarantinedFiles = Directory.GetFiles(Path.Combine(root, ".npmratpoison", "quarantine"), "*.*", SearchOption.AllDirectories)
                .Where(path => path.EndsWith(".json", StringComparison.OrdinalIgnoreCase)
                               || path.EndsWith(".lock", StringComparison.OrdinalIgnoreCase)
                               || path.EndsWith(".yaml", StringComparison.OrdinalIgnoreCase))
                .ToList();

            Assert.Equal(3, quarantinedFiles.Count);
            Assert.Contains(quarantinedFiles, path => path.EndsWith("package-lock.json", StringComparison.OrdinalIgnoreCase));
            Assert.Contains(quarantinedFiles, path => path.EndsWith("yarn.lock", StringComparison.OrdinalIgnoreCase));
            Assert.Contains(quarantinedFiles, path => path.EndsWith("pnpm-lock.yaml", StringComparison.OrdinalIgnoreCase));
        }
        finally
        {
            DeleteDirectoryRobust(root);
        }
    }

    [Fact]
    public async Task AutoTriageRunner_ScopedPath_HonorsGitHubOnlyFilter()
    {
        var root = CreateTempDirectory();

        try
        {
            var githubRepo = Path.Combine(root, "repo-github");
            var otherRepo = Path.Combine(root, "repo-other");

            CreateRepoSkeleton(githubRepo, "url = https://github.com/org/repo.git");
            CreateRepoSkeleton(otherRepo, "url = https://gitlab.com/org/repo.git");

            File.WriteAllText(Path.Combine(githubRepo, "package.json"), """
            {
              "dependencies": {
                "axios": "1.14.1"
              }
            }
            """);

            File.WriteAllText(Path.Combine(otherRepo, "package.json"), """
            {
              "dependencies": {
                "axios": "1.14.1"
              }
            }
            """);

            var cleanupService = new ThreatCleanupService(new TestProgressPublisher(), NullLogger<ThreatCleanupService>.Instance);
            var allDriveService = new AllDriveScanService(cleanupService, new TestProgressPublisher());
            var runner = new AutoTriageService(allDriveService, cleanupService, new TestProgressPublisher());
            var report = await runner.ExecuteAsync(root, pathProvided: true, gitHubOnly: true, ThreatCatalog.CreateDefault());

            Assert.Equal("Scoped path discovery", report.Mode);
            Assert.Equal(2, report.RepositoriesDiscovered);
            Assert.Equal(1, report.RepositoriesScanned);
            Assert.True(report.RepositoriesWithFindings >= 1);
            Assert.Contains(report.RepoSummaries, s => s.Contains("repo-github", StringComparison.OrdinalIgnoreCase));
            Assert.DoesNotContain(report.RepoSummaries, s => s.Contains("repo-other", StringComparison.OrdinalIgnoreCase));
        }
        finally
        {
            DeleteDirectoryRobust(root);
        }
    }

    [Fact]
    public async Task ThreatCatalog_CustomHotItemRules_AreLoadedWithoutCodeChanges()
    {
        var root = CreateTempDirectory();

        try
        {
            var catalogPath = Path.Combine(root, "hot-items.json");
            File.WriteAllText(catalogPath, """
            {
              "packages": [
                {
                  "packageName": "left-pad",
                  "replacementVersions": {
                    "9.9.9": "1.3.0"
                  },
                  "lockPackagePaths": [
                    "node_modules/left-pad"
                  ],
                  "textIndicators": [
                    "\"left-pad\": \"9.9.9\""
                  ]
                },
                {
                  "packageName": "evil-package",
                  "removeWhenPresent": true,
                  "directoryNames": [
                    "evil-package"
                  ],
                  "lockPackagePaths": [
                    "node_modules/evil-package"
                  ],
                  "textIndicators": [
                    "evil-package"
                  ]
                }
              ],
              "commonIndicators": [
                "bad.example"
              ],
              "shellProfileIndicators": [
                "bad.example"
              ],
              "workspaceArtifactNames": [
                "dropper.bin"
              ],
              "hostArtifacts": [],
              "gitIndicators": [
                "bad.example"
              ],
              "gitExposureWindows": [
                {
                  "startUtc": "2026-04-01T00:00:00Z",
                  "endUtc": "2026-04-01T01:00:00Z"
                }
              ],
              "reportAffectedItems": [
                "left-pad 9.9.9",
                "evil-package"
              ]
            }
            """);

            var catalog = ThreatCatalog.LoadFromFile(catalogPath);
            var packageJsonPath = Path.Combine(root, "package.json");
            File.WriteAllText(packageJsonPath, """
            {
              "dependencies": {
                "left-pad": "9.9.9",
                "evil-package": "1.0.0"
              }
            }
            """);

            var suspiciousDir = Path.Combine(root, "node_modules", "evil-package");
            Directory.CreateDirectory(suspiciousDir);
            File.WriteAllText(Path.Combine(root, "yarn.lock"), """
            left-pad@9.9.9:
              version "9.9.9"

            # callback bad.example
            """);

            var cleaner = new ThreatCleanupService(new TestProgressPublisher(), NullLogger<ThreatCleanupService>.Instance);
            var report = await cleaner.ExecuteAsync(root, dryRun: false, catalog, includeHostLevelChecks: false);

            var rootNode = JsonNode.Parse(File.ReadAllText(packageJsonPath))!.AsObject();
            var dependencies = rootNode["dependencies"]!.AsObject();

            Assert.Equal("1.3.0", dependencies["left-pad"]!.GetValue<string>());
            Assert.False(dependencies.ContainsKey("evil-package"));
            Assert.False(Directory.Exists(suspiciousDir));
            Assert.Contains(report.Flags, flag => flag.Contains("yarn.lock", StringComparison.OrdinalIgnoreCase));
        }
        finally
        {
            DeleteDirectoryRobust(root);
        }
    }

    [Fact]
    public void ThreatCatalog_LoadFromFile_ComputesMetadataAndSupportsShaValidation()
    {
        var root = CreateTempDirectory();

        try
        {
            var catalogPath = Path.Combine(root, "catalog.json");
            var json = """
            {
              "metadata": {
                "catalogId": "custom-hot-items",
                "version": "2026.04.02.5",
                "publishedUtc": "2026-04-02T00:00:00Z"
              },
              "packages": [],
              "commonIndicators": [ "bad.example" ],
              "shellProfileIndicators": [],
              "workspaceArtifactNames": [],
              "hostArtifacts": [],
              "gitIndicators": [],
              "gitExposureWindows": [],
              "reportAffectedItems": []
            }
            """;
            File.WriteAllText(catalogPath, json);

            var catalog = ThreatCatalog.LoadFromFile(catalogPath);
            var expectedSha = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(json))).ToLowerInvariant();
            catalog.ValidateSha256(expectedSha);

            Assert.Equal("custom-hot-items", catalog.Info.CatalogId);
            Assert.Equal("2026.04.02.5", catalog.Info.Version);
            Assert.Equal(expectedSha, catalog.Info.Sha256);
            Assert.Equal(CatalogIntegrityStatus.Verified, catalog.Info.IntegrityStatus);
        }
        finally
        {
            DeleteDirectoryRobust(root);
        }
    }

    [Fact]
    public async Task JsonReportWriter_WriteAsync_AllDriveReport_WritesJsonAndCsv()
    {
        var reportDirectory = CreateTempDirectory();

        try
        {
            var report = new AllDriveScanReport(dryRun: true, gitHubOnly: false);
            report.RepositorySummaries.Add(new RepositoryScanSummary(
                "D:\\Recovered\\Repo",
                LiveFlags: 0,
                GitBreadcrumbs: 0,
                GitAccessIssues: 1,
                GitRootIssues: 0,
                Remediations: 0,
                Removals: 0,
                Errors: 0,
                SafeDirectoryCommands: ["git config --global --add safe.directory 'D:/Recovered/Repo'"]));

            var writer = new JsonReportWriter(NullLogger<JsonReportWriter>.Instance);
            await writer.WriteAsync(reportDirectory, "triage", report);

            var jsonFile = Directory.GetFiles(reportDirectory, "triage-*.json").Single();
            var csvFile = Directory.GetFiles(reportDirectory, "triage-*.csv").Single();
            var htmlFile = Directory.GetFiles(reportDirectory, "triage-*.html").Single();

            Assert.Contains("\"RepositoryPath\"", File.ReadAllText(jsonFile), StringComparison.Ordinal);
            var csv = File.ReadAllText(csvFile);
            Assert.Contains("\"RepositoryPath\"", csv, StringComparison.Ordinal);
            Assert.Contains("safe.directory", csv, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("All-Drive Scan Report", File.ReadAllText(htmlFile), StringComparison.Ordinal);
        }
        finally
        {
            DeleteDirectoryRobust(reportDirectory);
        }
    }

    [Fact]
    public async Task IncidentSimulationService_PlantAsync_CreatesAdvisoryShapedFixtureDetectedByCleanup()
    {
        var root = CreateTempDirectory();

        try
        {
            var simulator = new IncidentSimulationService();
            var simulation = await simulator.PlantAsync(root, ThreatCatalog.CreateDefault());

            Assert.NotEmpty(simulation.FilesCreated);
            Assert.Contains(simulation.FilesCreated, path => path.EndsWith("package.json", StringComparison.OrdinalIgnoreCase));

            var cleanup = new ThreatCleanupService(new TestProgressPublisher(), NullLogger<ThreatCleanupService>.Instance);
            var report = await cleanup.ExecuteAsync(root, dryRun: true, ThreatCatalog.CreateDefault(), includeHostLevelChecks: false);

            Assert.True(report.Flags.Count > 0 || report.Removals.Count > 0 || report.Remediations.Count > 0);
            Assert.Contains(report.Removals, item => item.Contains("plain-crypto-js", StringComparison.OrdinalIgnoreCase));
        }
        finally
        {
            DeleteDirectoryRobust(root);
        }
    }

    [Fact]
    public async Task RemoteGitHubScanService_ExecuteAsync_FlagsCompromisedRemoteFiles()
    {
        var gateway = new FakeGitHubRepositoryGateway();
        gateway.RepositoryNames.Add("octo-org/sample-repo");
        gateway.Repositories["octo-org/sample-repo"] = new GitHubRepositoryDescriptor(
            "octo-org/sample-repo",
            "main",
            IsPrivate: false,
            IsArchived: false,
            "https://github.com/octo-org/sample-repo");
        gateway.Trees["octo-org/sample-repo"] = new GitHubRepositoryTree(
            [
                "package.json",
                "package-lock.json",
                "yarn.lock",
                "scripts/6202033.ps1"
            ],
            IsTruncated: false);
        gateway.Commits["octo-org/sample-repo"] =
        [
            new GitHubCommitSummary(
                "deadbeef",
                DateTimeOffset.Parse("2026-03-31T00:25:00Z"),
                "Introduce compromised axios payload")
        ];
        gateway.CommitDiffs[("octo-org/sample-repo", "deadbeef")] =
        [
            "+    \"axios\": \"1.14.1\"",
            "+    \"plain-crypto-js\": \"4.2.1\""
        ];
        gateway.Contents[("octo-org/sample-repo", "package.json")] = """
        {
          "dependencies": {
            "axios": "1.14.1",
            "plain-crypto-js": "4.2.1"
          }
        }
        """;
        gateway.Contents[("octo-org/sample-repo", "package-lock.json")] = """
        {
          "packages": {
            "": {
              "dependencies": {
                "axios": "1.14.1",
                "plain-crypto-js": "4.2.1"
              }
            },
            "node_modules/axios": {
              "version": "1.14.1"
            },
            "node_modules/plain-crypto-js": {
              "version": "4.2.1"
            }
          }
        }
        """;
        gateway.Contents[("octo-org/sample-repo", "yarn.lock")] = """
        plain-crypto-js@4.2.1:
          resolved "http://sfrclak.com:8000/plain-crypto-js-4.2.1.tgz"
        """;

        var service = new RemoteGitHubScanService(gateway, new TestProgressPublisher(), NullLogger<RemoteGitHubScanService>.Instance);
        var request = new RemoteGitHubScanRequest(null, null, ["octo-org/sample-repo"], null);

        var report = await service.ExecuteAsync(request, ThreatCatalog.CreateDefault());

        Assert.Equal(1, report.RepositoriesDiscovered);
        Assert.Equal(1, report.RepositoriesScanned);
        Assert.Equal(1, report.RepositoriesWithFindings);
        Assert.Single(report.RepositorySummaries);
        Assert.True(report.RepositorySummaries[0].Findings.Count > 0);
        Assert.True(report.RepositorySummaries[0].GitBreadcrumbs > 0);
        Assert.Contains(report.RepositorySummaries[0].Findings, item => item.Contains("axios", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(report.RepositorySummaries[0].Findings, item => item.Contains("6202033.ps1", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(report.RepositorySummaries[0].Findings, item => item.Contains("Remote commit in exposure window", StringComparison.OrdinalIgnoreCase));
    }

    private static string CreateTempDirectory()
    {
        var path = Path.Combine(Path.GetTempPath(), "NpmRatPoisonTests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path);
        return path;
    }

    private static void DeleteDirectoryRobust(string path)
    {
        if (!Directory.Exists(path))
        {
            return;
        }

        foreach (var file in Directory.EnumerateFiles(path, "*", SearchOption.AllDirectories))
        {
            File.SetAttributes(file, FileAttributes.Normal);
        }

        foreach (var directory in Directory.EnumerateDirectories(path, "*", SearchOption.AllDirectories))
        {
            File.SetAttributes(directory, FileAttributes.Normal);
        }

        for (var attempt = 0; attempt < 5; attempt++)
        {
            try
            {
                Directory.Delete(path, recursive: true);
                return;
            }
            catch (IOException) when (attempt < 4)
            {
                GC.Collect();
                GC.WaitForPendingFinalizers();
                Thread.Sleep(100);
            }
            catch (UnauthorizedAccessException) when (attempt < 4)
            {
                GC.Collect();
                GC.WaitForPendingFinalizers();
                Thread.Sleep(100);
            }
        }
    }

    private static void CreateRepoSkeleton(string repoRoot, string configUrlLine)
    {
        Directory.CreateDirectory(repoRoot);
        var gitDir = Path.Combine(repoRoot, ".git");
        Directory.CreateDirectory(gitDir);

        File.WriteAllText(Path.Combine(gitDir, "config"), $"""
        [remote \"origin\"]
            {configUrlLine}
        """);

        File.WriteAllText(Path.Combine(gitDir, "HEAD"), "ref: refs/heads/main");
    }

    private static ProviderIngressOptions CreateProviderIngressOptions(int allowedClockSkewMinutes = 10, int replayCacheMinutes = 30, IReadOnlyList<string>? allowedDocumentTypes = null)
    {
        return new ProviderIngressOptions
        {
            Enabled = true,
            DatabaseProvider = "sqlite",
            AllowedClockSkewMinutes = allowedClockSkewMinutes,
            ReplayCacheMinutes = replayCacheMinutes,
            Providers = new Dictionary<string, ProviderIngressProviderOptions>(StringComparer.OrdinalIgnoreCase)
            {
                ["step-security"] = new ProviderIngressProviderOptions
                {
                    DisplayName = "StepSecurity",
                    Contact = "security@example.invalid",
                    AllowedDocumentTypes = allowedDocumentTypes?.ToList() ?? [ "vulnerability-advisory", "indicator-bundle", "patch-bundle", "catalog-delta" ]
                }
            }
        };
    }

    private static IDbContextFactory<ProviderIngressDbContext> CreateProviderIngressDbContextFactory(string databasePath)
    {
        var options = new DbContextOptionsBuilder<ProviderIngressDbContext>()
            .UseSqlite($"Data Source={databasePath};Pooling=False")
            .Options;
        return new TestProviderIngressDbContextFactory(options);
    }

    private static async Task EnsureProviderIngressDatabaseAsync(IDbContextFactory<ProviderIngressDbContext> dbContextFactory)
    {
        await using var dbContext = await dbContextFactory.CreateDbContextAsync();
        await dbContext.Database.EnsureCreatedAsync();
    }

    private static ProviderIngressService CreateProviderIngressService(IOptions<ProviderIngressOptions> options, IDbContextFactory<ProviderIngressDbContext> dbContextFactory)
    {
        return new ProviderIngressService(options, dbContextFactory, new FakeVapeCache(), NullLogger<ProviderIngressService>.Instance);
    }

    private static string GenerateRsaSignature(string privateKeyPem, string providerId, string timestamp, string body)
    {
        using var rsa = RSA.Create();
        rsa.ImportFromPem(privateKeyPem);
        var canonical = Encoding.UTF8.GetBytes($"{providerId}\n{timestamp}\n{body}");
        var signature = rsa.SignData(canonical, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        return "rsa-pss-sha256=" + Convert.ToBase64String(signature);
    }

    private sealed class TestProgressPublisher : IScanProgressPublisher
    {
        public void Publish(string stage, string? drive, string? path, string message)
        {
        }
    }

    private sealed class TestProviderIngressDbContextFactory : IDbContextFactory<ProviderIngressDbContext>
    {
        private readonly DbContextOptions<ProviderIngressDbContext> _options;

        public TestProviderIngressDbContextFactory(DbContextOptions<ProviderIngressDbContext> options)
        {
            _options = options;
        }

        public ProviderIngressDbContext CreateDbContext()
        {
            return new ProviderIngressDbContext(_options);
        }

        public Task<ProviderIngressDbContext> CreateDbContextAsync(CancellationToken cancellationToken = default)
        {
            return Task.FromResult(new ProviderIngressDbContext(_options));
        }
    }

    private sealed class ThrowingProviderIngressDbContextFactory : IDbContextFactory<ProviderIngressDbContext>
    {
        public ProviderIngressDbContext CreateDbContext()
        {
            throw new InvalidOperationException("Simulated database startup failure.");
        }

        public Task<ProviderIngressDbContext> CreateDbContextAsync(CancellationToken cancellationToken = default)
        {
            throw new InvalidOperationException("Simulated database startup failure.");
        }
    }

    private sealed class FakeGitHubRepositoryGateway : IGitHubRepositoryGateway
    {
        public List<string> RepositoryNames { get; } = [];

        public Dictionary<string, GitHubRepositoryDescriptor> Repositories { get; } = new(StringComparer.OrdinalIgnoreCase);

        public Dictionary<string, GitHubRepositoryTree> Trees { get; } = new(StringComparer.OrdinalIgnoreCase);

        public Dictionary<(string Repository, string Path), string> Contents { get; } = new();

        public Dictionary<string, IReadOnlyList<GitHubCommitSummary>> Commits { get; } = new(StringComparer.OrdinalIgnoreCase);

        public Dictionary<(string Repository, string CommitSha), IReadOnlyList<string>> CommitDiffs { get; } = new();

        public Task<IReadOnlyList<string>> ResolveRepositoryNamesAsync(RemoteGitHubScanRequest request, CancellationToken cancellationToken = default)
        {
            IReadOnlyList<string> result = request.RepositoryNames.Count > 0 ? request.RepositoryNames : RepositoryNames;
            return Task.FromResult(result);
        }

        public Task<GitHubRepositoryDescriptor> GetRepositoryAsync(string repositoryFullName, string? accessToken, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(Repositories[repositoryFullName]);
        }

        public Task<GitHubRepositoryTree> GetRepositoryTreeAsync(string repositoryFullName, string gitReference, string? accessToken, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(Trees[repositoryFullName]);
        }

        public Task<GitHubContentFile?> GetContentFileAsync(string repositoryFullName, string path, string gitReference, string? accessToken, CancellationToken cancellationToken = default)
        {
            if (!Contents.TryGetValue((repositoryFullName, path), out var content))
            {
                return Task.FromResult<GitHubContentFile?>(null);
            }

            return Task.FromResult<GitHubContentFile?>(new GitHubContentFile(path, content));
        }

        public Task<IReadOnlyList<GitHubCommitSummary>> GetRecentDependencyCommitsAsync(string repositoryFullName, string? accessToken, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(Commits.TryGetValue(repositoryFullName, out var commits)
                ? commits
                : (IReadOnlyList<GitHubCommitSummary>)[]);
        }

        public Task<IReadOnlyList<string>> GetCommitDiffLinesAsync(string repositoryFullName, string commitSha, string? accessToken, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(CommitDiffs.TryGetValue((repositoryFullName, commitSha), out var diff)
                ? diff
                : (IReadOnlyList<string>)[]);
        }
    }

    private sealed class FakeGitHubCredentialPrompt : IGitHubCredentialPrompt
    {
        private readonly string? _token;

        public FakeGitHubCredentialPrompt(string? token)
        {
            _token = token;
        }

        public int CallCount { get; private set; }

        public string? PromptForAccessToken()
        {
            CallCount++;
            return _token;
        }
    }

    private sealed class FakeVapeCache : IVapeCache
    {
        private readonly Dictionary<string, object?> _entries = new(StringComparer.Ordinal);

        public ICacheRegion Region(string name)
        {
            throw new NotSupportedException();
        }

        public ValueTask<T?> GetAsync<T>(CacheKey<T> key, CancellationToken cancellationToken = default)
        {
            if (_entries.TryGetValue(key.Value, out var value) && value is T typed)
            {
                return ValueTask.FromResult<T?>(typed);
            }

            return ValueTask.FromResult<T?>(default);
        }

        public ValueTask SetAsync<T>(CacheKey<T> key, T value, CacheEntryOptions options, CancellationToken cancellationToken = default)
        {
            _entries[key.Value] = value;
            return ValueTask.CompletedTask;
        }

        public async ValueTask<T> GetOrCreateAsync<T>(CacheKey<T> key, Func<CancellationToken, ValueTask<T>> factory, CacheEntryOptions options, CancellationToken cancellationToken = default)
        {
            if (_entries.TryGetValue(key.Value, out var value) && value is T typed)
            {
                return typed;
            }

            var created = await factory(cancellationToken);
            _entries[key.Value] = created;
            return created;
        }

        public ValueTask<bool> RemoveAsync(CacheKey key, CancellationToken cancellationToken = default)
        {
            return ValueTask.FromResult(_entries.Remove(key.Value));
        }

        public ValueTask<long> InvalidateTagAsync(string tag, CancellationToken cancellationToken = default)
        {
            return ValueTask.FromResult(0L);
        }

        public ValueTask<long> GetTagVersionAsync(string tag, CancellationToken cancellationToken = default)
        {
            return ValueTask.FromResult(0L);
        }

        public ValueTask<long> InvalidateZoneAsync(string zone, CancellationToken cancellationToken = default)
        {
            return ValueTask.FromResult(0L);
        }

        public ValueTask<long> GetZoneVersionAsync(string zone, CancellationToken cancellationToken = default)
        {
            return ValueTask.FromResult(0L);
        }
    }

    private sealed class FakeConsoleRuntime : IConsoleRuntime
    {
        private readonly Queue<ConsoleKeyInfo> _keys;

        public FakeConsoleRuntime(bool isInputRedirected, IEnumerable<ConsoleKeyInfo>? keys = null)
        {
            IsInputRedirected = isInputRedirected;
            _keys = new Queue<ConsoleKeyInfo>(keys ?? []);
        }

        public bool IsInputRedirected { get; }

        public int ReadKeyCallCount { get; private set; }

        public List<string> Writes { get; } = [];

        public void WriteLine()
        {
            Writes.Add(Environment.NewLine);
        }

        public void WriteLine(string value)
        {
            Writes.Add(value);
        }

        public void Write(string value)
        {
            Writes.Add(value);
        }

        public ConsoleKeyInfo ReadKey(bool intercept)
        {
            ReadKeyCallCount++;
            if (_keys.Count == 0)
            {
                throw new InvalidOperationException("No more keys were queued for the fake console.");
            }

            return _keys.Dequeue();
        }
    }
}
