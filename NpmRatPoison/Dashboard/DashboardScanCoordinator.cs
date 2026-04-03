using Microsoft.Extensions.DependencyInjection;

public sealed class DashboardScanCoordinator
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly ScanDashboardState _dashboardState;
    private readonly SemaphoreSlim _singleRun = new(1, 1);

    public DashboardScanCoordinator(IServiceScopeFactory scopeFactory, ScanDashboardState dashboardState)
    {
        _scopeFactory = scopeFactory;
        _dashboardState = dashboardState;
    }

    public string DefaultRootPath => Directory.GetCurrentDirectory();

    public string ReportDirectory => Path.Combine(Directory.GetCurrentDirectory(), "artifacts", "dashboard-reports");

    public async Task RefreshArtifactsAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var artifacts = EnumerateArtifacts().ToList();
        _dashboardState.ReplaceArtifacts(artifacts);
    }

    public Task RunScopedDryRunAsync(string rootPath, bool enableHostRemediation, CancellationToken cancellationToken = default)
    {
        return RunExclusiveAsync(
            $"Scoped cleanup: {rootPath}",
            "cleanup",
            async services =>
            {
                var catalog = LoadCatalog(services);
                var cleanupService = services.GetRequiredService<IThreatCleanupService>();
                var reportWriter = services.GetRequiredService<IReportWriter>();
                var report = await cleanupService.ExecuteAsync(rootPath, dryRun: true, catalog, includeHostLevelChecks: enableHostRemediation);
                await reportWriter.WriteAsync(ReportDirectory, "dashboard-cleanup", report, cancellationToken);
                return (ScanExitCodeEvaluator.GetExitCode(report), $"Severity={report.GetSeverity()} LiveFlags={report.Flags.Count} Remediations={report.Remediations.Count} Removals={report.Removals.Count}");
            },
            cancellationToken);
    }

    public Task RunAllDrivesDryRunAsync(bool gitHubOnly, CancellationToken cancellationToken = default)
    {
        return RunExclusiveAsync(
            gitHubOnly ? "All-drive dry run (GitHub only)" : "All-drive dry run",
            "all-drives",
            async services =>
            {
                var catalog = LoadCatalog(services);
                var scanService = services.GetRequiredService<IAllDriveScanService>();
                var reportWriter = services.GetRequiredService<IReportWriter>();
                var report = await scanService.ExecuteAsync(dryRun: true, gitHubOnly, catalog, cancellationToken);
                await reportWriter.WriteAsync(ReportDirectory, "dashboard-all-drives", report, cancellationToken);
                return (ScanExitCodeEvaluator.GetExitCode(report), $"Severity={report.GetSeverity()} ReposScanned={report.ReposScanned} Findings={report.ReposWithFindings}");
            },
            cancellationToken);
    }

    public Task RunRemoteGitHubRepoAsync(string repository, string? accessToken, CancellationToken cancellationToken = default)
    {
        return RunExclusiveAsync(
            $"Remote GitHub scan: {repository}",
            "remote-github",
            async services =>
            {
                var catalog = LoadCatalog(services);
                var remoteScanService = services.GetRequiredService<IRemoteGitHubScanService>();
                var reportWriter = services.GetRequiredService<IReportWriter>();
                var request = new RemoteGitHubScanRequest(
                    null,
                    null,
                    [repository],
                    ResolveAccessToken(accessToken));
                var report = await remoteScanService.ExecuteAsync(request, catalog, cancellationToken);
                await reportWriter.WriteAsync(ReportDirectory, "dashboard-remote-github", report, cancellationToken);
                return (ScanExitCodeEvaluator.GetExitCode(report), $"Severity={report.GetSeverity()} Repositories={report.RepositoriesScanned} Findings={report.RepositoriesWithFindings}");
            },
            cancellationToken);
    }

    private async Task RunExclusiveAsync(
        string title,
        string mode,
        Func<IServiceProvider, Task<(int ExitCode, string Summary)>> action,
        CancellationToken cancellationToken)
    {
        await _singleRun.WaitAsync(cancellationToken);
        var run = _dashboardState.StartRun(title, mode);

        try
        {
            await using var scope = _scopeFactory.CreateAsyncScope();
            var result = await action(scope.ServiceProvider);
            await RefreshArtifactsAsync(cancellationToken);
            var latestArtifacts = _dashboardState.GetArtifacts().Take(6).Select(item => item.Url);
            _dashboardState.CompleteRun(run.Id, result.ExitCode, result.Summary, latestArtifacts);
        }
        catch (Exception ex)
        {
            await RefreshArtifactsAsync(cancellationToken);
            _dashboardState.FailRun(run.Id, ex.Message, _dashboardState.GetArtifacts().Take(6).Select(item => item.Url));
        }
        finally
        {
            _singleRun.Release();
        }
    }

    private static ThreatCatalog LoadCatalog(IServiceProvider services)
    {
        var catalogProvider = services.GetRequiredService<IThreatCatalogProvider>();
        return catalogProvider.Load(null);
    }

    private static string? ResolveAccessToken(string? accessToken)
    {
        if (!string.IsNullOrWhiteSpace(accessToken))
        {
            return accessToken;
        }

        return Environment.GetEnvironmentVariable("GITHUB_TOKEN")
               ?? Environment.GetEnvironmentVariable("GH_TOKEN");
    }

    private IEnumerable<DashboardArtifactFile> EnumerateArtifacts()
    {
        if (!Directory.Exists(ReportDirectory))
        {
            return [];
        }

        return Directory.EnumerateFiles(ReportDirectory, "*.*", SearchOption.TopDirectoryOnly)
            .Where(path => path.EndsWith(".html", StringComparison.OrdinalIgnoreCase)
                           || path.EndsWith(".json", StringComparison.OrdinalIgnoreCase)
                           || path.EndsWith(".csv", StringComparison.OrdinalIgnoreCase))
            .Select(path => new FileInfo(path))
            .OrderByDescending(file => file.LastWriteTimeUtc)
            .Take(24)
            .Select(file => new DashboardArtifactFile(
                file.Name,
                $"/artifacts/dashboard-reports/{Uri.EscapeDataString(file.Name)}",
                new DateTimeOffset(file.LastWriteTimeUtc, TimeSpan.Zero)));
    }
}
