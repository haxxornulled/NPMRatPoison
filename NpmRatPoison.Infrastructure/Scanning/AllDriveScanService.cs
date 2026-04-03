public sealed class AllDriveScanService : IAllDriveScanService
{
    private readonly IThreatCleanupService _cleanupService;
    private readonly IScanProgressPublisher _progressPublisher;

    public AllDriveScanService(IThreatCleanupService cleanupService, IScanProgressPublisher progressPublisher)
    {
        _cleanupService = cleanupService;
        _progressPublisher = progressPublisher;
    }

    public async Task<AllDriveScanReport> ExecuteAsync(bool dryRun, bool gitHubOnly, ThreatCatalog catalog, CancellationToken cancellationToken = default)
    {
        var report = new AllDriveScanReport(dryRun, gitHubOnly)
        {
            Catalog = catalog.Info
        };
        var sync = new Lock();

        foreach (var drive in DriveInfo.GetDrives())
        {
            if (!drive.IsReady)
            {
                continue;
            }

            report.DrivesScanned.Add(drive.Name);
            _progressPublisher.Publish("drive", drive.Name, drive.RootDirectory.FullName, "Scanning drive");

            var repositories = GitRepositoryTraversal.EnumerateGitRepos(drive.RootDirectory.FullName).ToList();
            await Parallel.ForEachAsync(repositories, new ParallelOptions
            {
                MaxDegreeOfParallelism = Math.Max(2, Environment.ProcessorCount / 2),
                CancellationToken = cancellationToken
            }, async (repositoryRoot, token) =>
            {
                token.ThrowIfCancellationRequested();
                _progressPublisher.Publish("repository", drive.Name, repositoryRoot, "Scanning repository");

                lock (sync)
                {
                    report.ReposDiscovered++;
                }

                var isGitHubRepo = GitRepositoryTraversal.IsGitHubRepo(repositoryRoot);
                if (gitHubOnly && !isGitHubRepo)
                {
                    return;
                }

                lock (sync)
                {
                    report.ReposScanned++;
                }

                try
                {
                    var repositoryReport = await _cleanupService.ExecuteAsync(repositoryRoot, dryRun: true, catalog: catalog, includeHostLevelChecks: false);
                    if (!repositoryReport.HasFindings())
                    {
                        return;
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

                    lock (sync)
                    {
                        report.ReposWithFindings++;
                        if (summary.LiveFlags > 0)
                        {
                            report.ReposWithLiveIndicators++;
                        }

                        if (summary.GitBreadcrumbs > 0)
                        {
                            report.ReposWithGitBreadcrumbs++;
                        }

                        if (summary.GitAccessIssues > 0)
                        {
                            report.ReposWithGitAccessIssues++;
                        }

                        if (summary.Remediations > 0 || summary.Removals > 0)
                        {
                            report.ReposWithRemediationActions++;
                        }

                        report.RepositorySummaries.Add(summary);
                        report.FindingSummaries.Add(summary.ToDisplayString());
                    }
                }
                catch (Exception ex)
                {
                    lock (sync)
                    {
                        report.Errors.Add($"Scan failure ({repositoryRoot}): {ex.Message}");
                    }
                }
            });
        }

        return report;
    }
}
