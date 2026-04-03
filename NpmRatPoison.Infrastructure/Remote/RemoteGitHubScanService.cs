using Microsoft.Extensions.Logging;

public sealed class RemoteGitHubScanService : IRemoteGitHubScanService
{
    private static readonly string[] TargetFileNames =
    [
        "package.json",
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml"
    ];

    private readonly IGitHubRepositoryGateway _gitHubRepositoryGateway;
    private readonly IScanProgressPublisher _progressPublisher;
    private readonly ILogger<RemoteGitHubScanService> _logger;

    public RemoteGitHubScanService(
        IGitHubRepositoryGateway gitHubRepositoryGateway,
        IScanProgressPublisher progressPublisher,
        ILogger<RemoteGitHubScanService> logger)
    {
        _gitHubRepositoryGateway = gitHubRepositoryGateway;
        _progressPublisher = progressPublisher;
        _logger = logger;
    }

    public async Task<RemoteGitHubScanReport> ExecuteAsync(RemoteGitHubScanRequest request, ThreatCatalog catalog, CancellationToken cancellationToken = default)
    {
        var report = new RemoteGitHubScanReport
        {
            Scope = BuildScope(request),
            Catalog = catalog.Info
        };

        var repositoryNames = await _gitHubRepositoryGateway.ResolveRepositoryNamesAsync(request, cancellationToken);
        report.RepositoriesDiscovered = repositoryNames.Count;

        foreach (var repositoryFullName in repositoryNames)
        {
            cancellationToken.ThrowIfCancellationRequested();
            _progressPublisher.Publish("remote-repository", null, repositoryFullName, "Scanning remote GitHub repository");
            report.RepositoriesScanned++;

            try
            {
                var descriptor = await _gitHubRepositoryGateway.GetRepositoryAsync(repositoryFullName, request.AccessToken, cancellationToken);
                var tree = await _gitHubRepositoryGateway.GetRepositoryTreeAsync(repositoryFullName, descriptor.DefaultBranch, request.AccessToken, cancellationToken);
                var findings = new List<string>();
                var errors = new List<string>();
                var flaggedFiles = 0;
                var gitBreadcrumbs = 0;
                var candidatePaths = tree.FilePaths
                    .Where(path => TargetFileNames.Contains(Path.GetFileName(path), StringComparer.OrdinalIgnoreCase))
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToList();

                foreach (var path in tree.FilePaths)
                {
                    findings.AddRange(RemoteThreatAnalyzer.AnalyzeTreePath(repositoryFullName, path, catalog));
                }

                foreach (var path in candidatePaths)
                {
                    _progressPublisher.Publish("remote-file", null, $"{repositoryFullName}:{path}", "Fetching remote file");
                    try
                    {
                        var contentFile = await _gitHubRepositoryGateway.GetContentFileAsync(repositoryFullName, path, descriptor.DefaultBranch, request.AccessToken, cancellationToken);
                        if (contentFile is null)
                        {
                            continue;
                        }

                        var fileFindings = RemoteThreatAnalyzer.Analyze(repositoryFullName, path, contentFile.Content, catalog);
                        if (fileFindings.Count > 0)
                        {
                            flaggedFiles++;
                            findings.AddRange(fileFindings);
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Remote file fetch failed for {Repository} {Path}", repositoryFullName, path);
                        errors.Add($"File fetch failure ({path}): {ex.Message}");
                    }
                }

                try
                {
                    var commits = await _gitHubRepositoryGateway.GetRecentDependencyCommitsAsync(repositoryFullName, request.AccessToken, cancellationToken);
                    foreach (var commit in commits)
                    {
                        if (catalog.IsWithinExposureWindow(commit.TimestampUtc))
                        {
                            findings.Add($"Remote commit in exposure window ({commit.TimestampUtc:O}, {commit.Sha}): {commit.Message}");
                            gitBreadcrumbs++;
                        }

                        var diffLines = await _gitHubRepositoryGateway.GetCommitDiffLinesAsync(repositoryFullName, commit.Sha, request.AccessToken, cancellationToken);
                        foreach (var line in diffLines)
                        {
                            if (!catalog.IsGitIndicatorMatch(line))
                            {
                                continue;
                            }

                            findings.Add($"Remote IoC in commit patch ({commit.TimestampUtc:O}, {commit.Sha}): {line.Trim()}");
                            gitBreadcrumbs++;
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Remote Git history scan failed for {Repository}", repositoryFullName);
                    errors.Add($"Git history fetch failure: {ex.Message}");
                }

                if (tree.IsTruncated)
                {
                    errors.Add("Repository tree enumeration was truncated by GitHub; findings may be incomplete.");
                }

                var summary = new RemoteGitHubRepositorySummary(
                    descriptor.FullName,
                    descriptor.DefaultBranch,
                    descriptor.IsPrivate,
                    descriptor.IsArchived,
                    tree.FilePaths.Count,
                    candidatePaths.Count,
                    flaggedFiles,
                    gitBreadcrumbs,
                    tree.IsTruncated,
                    findings.Distinct(StringComparer.OrdinalIgnoreCase).ToList(),
                    errors);

                if (summary.Findings.Count > 0)
                {
                    report.RepositoriesWithFindings++;
                }

                if (summary.Errors.Count > 0)
                {
                    report.RepositoriesWithErrors++;
                }

                report.RepositorySummaries.Add(summary);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Remote GitHub scan failed for {Repository}", repositoryFullName);
                report.RepositoriesWithErrors++;
                report.Errors.Add($"Remote scan failure ({repositoryFullName}): {ex.Message}");
            }
        }

        return report;
    }

    private static string BuildScope(RemoteGitHubScanRequest request)
    {
        var parts = new List<string>();
        if (!string.IsNullOrWhiteSpace(request.Organization))
        {
            parts.Add($"org:{request.Organization}");
        }

        if (!string.IsNullOrWhiteSpace(request.User))
        {
            parts.Add($"user:{request.User}");
        }

        if (request.RepositoryNames.Count > 0)
        {
            parts.Add($"repos:{string.Join(", ", request.RepositoryNames)}");
        }

        return parts.Count == 0 ? "GitHub remote scan" : string.Join(" | ", parts);
    }
}
