public sealed class AutoTriageService : IAutoTriageService
{
    private readonly IAllDriveScanService _allDriveScanService;
    private readonly IThreatCleanupService _cleanupService;
    private readonly IScanProgressPublisher _progressPublisher;

    public AutoTriageService(IAllDriveScanService allDriveScanService, IThreatCleanupService cleanupService, IScanProgressPublisher progressPublisher)
    {
        _allDriveScanService = allDriveScanService;
        _cleanupService = cleanupService;
        _progressPublisher = progressPublisher;
    }

    public async Task<AutoTriageReport> ExecuteAsync(string rootPath, bool pathProvided, bool gitHubOnly, ThreatCatalog catalog, CancellationToken cancellationToken = default)
    {
        var report = new AutoTriageReport(rootPath, pathProvided, gitHubOnly)
        {
            Catalog = catalog.Info
        };

        if (!pathProvided)
        {
            var allDriveReport = await _allDriveScanService.ExecuteAsync(dryRun: true, gitHubOnly: gitHubOnly, catalog: catalog, cancellationToken: cancellationToken);
            report.Mode = "Global all-drive discovery";
            report.DrivesScanned.AddRange(allDriveReport.DrivesScanned);
            report.RepositoriesDiscovered = allDriveReport.ReposDiscovered;
            report.RepositoriesScanned = allDriveReport.ReposScanned;
            report.RepositoriesWithFindings = allDriveReport.ReposWithFindings;
            report.RepositoriesWithLiveIndicators = allDriveReport.ReposWithLiveIndicators;
            report.RepositoriesWithGitBreadcrumbs = allDriveReport.ReposWithGitBreadcrumbs;
            report.RepositoriesWithGitAccessIssues = allDriveReport.ReposWithGitAccessIssues;
            report.RepositoriesWithRemediationActions = allDriveReport.ReposWithRemediationActions;
            report.RepositorySummaries.AddRange(allDriveReport.RepositorySummaries);
            report.RepoSummaries.AddRange(allDriveReport.FindingSummaries);
            report.Errors.AddRange(allDriveReport.Errors);
            return report;
        }

        report.Mode = "Scoped path discovery";
        _progressPublisher.Publish("auto", null, rootPath, "Auto triage root");
        foreach (var repositoryRoot in GitRepositoryTraversal.EnumerateGitRepos(rootPath))
        {
            cancellationToken.ThrowIfCancellationRequested();
            report.RepositoriesDiscovered++;
            _progressPublisher.Publish("folder", null, repositoryRoot, "Current folder");

            var isGitHubRepo = GitRepositoryTraversal.IsGitHubRepo(repositoryRoot);
            if (gitHubOnly && !isGitHubRepo)
            {
                continue;
            }

            report.RepositoriesScanned++;
            try
            {
                var repositoryReport = await _cleanupService.ExecuteAsync(repositoryRoot, dryRun: true, catalog: catalog, includeHostLevelChecks: false);
                if (!repositoryReport.HasFindings())
                {
                    continue;
                }

                var summary = new RepositoryScanSummary(
                    repositoryRoot,
                    repositoryReport.Flags.Count,
                    repositoryReport.GitHistoryBreadcrumbs.Count,
                    repositoryReport.GitAccessIssues.Count,
                    repositoryReport.GitRootIssues.Count,
                    repositoryReport.Remediations.Count,
                    repositoryReport.Removals.Count,
                    repositoryReport.Errors.Count,
                    repositoryReport.GetSafeDirectoryCommands().ToList());

                report.RepositoriesWithFindings++;
                if (summary.LiveFlags > 0)
                {
                    report.RepositoriesWithLiveIndicators++;
                }

                if (summary.GitBreadcrumbs > 0)
                {
                    report.RepositoriesWithGitBreadcrumbs++;
                }

                if (summary.GitAccessIssues > 0)
                {
                    report.RepositoriesWithGitAccessIssues++;
                }

                if (summary.Remediations > 0 || summary.Removals > 0)
                {
                    report.RepositoriesWithRemediationActions++;
                }

                report.RepositorySummaries.Add(summary);
                report.RepoSummaries.Add(summary.ToDisplayString());
            }
            catch (Exception ex)
            {
                report.Errors.Add($"Auto scan failure ({repositoryRoot}): {ex.Message}");
            }
        }

        return report;
    }
}
