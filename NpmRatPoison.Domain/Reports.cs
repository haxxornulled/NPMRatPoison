using System.Text.Json.Serialization;

public sealed record ScanStatus(string Stage, string? Drive, string? Path, string Message);

public enum ScanSeverity
{
    None = 0,
    Informational = 1,
    Warning = 2,
    Critical = 3,
    Error = 4
}

public enum GitIssueKind
{
    Breadcrumb = 0,
    QueryBlocked = 1,
    RootMissing = 2
}

public enum GitQueryBlockReason
{
    None = 0,
    SafeDirectory = 1,
    GitUnavailable = 2,
    AccessDenied = 3,
    Unknown = 4
}

public sealed record GitIssueDetail(
    GitIssueKind Kind,
    string Message,
    GitQueryBlockReason QueryBlockReason = GitQueryBlockReason.None,
    string? RepositoryPath = null,
    string? SafeDirectoryCommand = null)
{
    public static GitIssueDetail CreateBreadcrumb(string message, string? repositoryPath = null)
    {
        return new GitIssueDetail(GitIssueKind.Breadcrumb, message, RepositoryPath: repositoryPath);
    }

    public static GitIssueDetail CreateRootMissing(string message, string? repositoryPath = null)
    {
        return new GitIssueDetail(GitIssueKind.RootMissing, message, RepositoryPath: repositoryPath);
    }

    public static GitIssueDetail CreateQueryBlocked(string message, GitQueryBlockReason reason, string? repositoryPath = null)
    {
        var safeDirectoryCommand = reason == GitQueryBlockReason.SafeDirectory && !string.IsNullOrWhiteSpace(repositoryPath)
            ? BuildSafeDirectoryCommand(repositoryPath)
            : null;

        return new GitIssueDetail(
            GitIssueKind.QueryBlocked,
            message,
            reason,
            repositoryPath,
            safeDirectoryCommand);
    }

    public static GitIssueDetail FromLegacy(string message, string? repositoryPath = null)
    {
        if (message.StartsWith("No .git repository found", StringComparison.OrdinalIgnoreCase))
        {
            return CreateRootMissing(message, repositoryPath);
        }

        if (message.StartsWith("Unable to query git history:", StringComparison.OrdinalIgnoreCase))
        {
            return CreateQueryBlocked(message, InferBlockReason(message), repositoryPath);
        }

        return CreateBreadcrumb(message, repositoryPath);
    }

    private static GitQueryBlockReason InferBlockReason(string message)
    {
        if (message.Contains("safe.directory", StringComparison.OrdinalIgnoreCase)
            || message.Contains("dubious ownership", StringComparison.OrdinalIgnoreCase))
        {
            return GitQueryBlockReason.SafeDirectory;
        }

        if (message.Contains("permission denied", StringComparison.OrdinalIgnoreCase)
            || message.Contains("access is denied", StringComparison.OrdinalIgnoreCase))
        {
            return GitQueryBlockReason.AccessDenied;
        }

        if (message.Contains("failed to start git process", StringComparison.OrdinalIgnoreCase)
            || message.Contains("not recognized as an internal or external command", StringComparison.OrdinalIgnoreCase)
            || message.Contains("no such file or directory", StringComparison.OrdinalIgnoreCase))
        {
            return GitQueryBlockReason.GitUnavailable;
        }

        return GitQueryBlockReason.Unknown;
    }

    private static string BuildSafeDirectoryCommand(string repositoryPath)
    {
        var normalized = repositoryPath.Replace('\\', '/');
        var escaped = normalized.Replace("'", "''");
        return $"git config --global --add safe.directory '{escaped}'";
    }
}

public sealed class CleanupReport
{
    private readonly ThreatCatalog _catalog;

    public CleanupReport(bool dryRun, string rootPath)
        : this(dryRun, rootPath, ThreatCatalog.CreateDefault())
    {
    }

    [JsonConstructor]
    public CleanupReport(
        bool dryRun,
        string rootPath,
        List<string>? flags = null,
        List<string>? gitBreadcrumbs = null,
        List<GitIssueDetail>? gitIssues = null,
        List<string>? removals = null,
        List<string>? remediations = null,
        List<string>? errors = null)
        : this(dryRun, rootPath, ThreatCatalog.CreateDefault())
    {
        if (flags is not null)
        {
            Flags.AddRange(flags);
        }

        if (gitIssues is not null)
        {
            GitIssues.AddRange(gitIssues);
        }

        if (gitBreadcrumbs is not null)
        {
            foreach (var legacyIssue in gitBreadcrumbs)
            {
                GitIssues.Add(GitIssueDetail.FromLegacy(legacyIssue, rootPath));
            }
        }

        if (removals is not null)
        {
            Removals.AddRange(removals);
        }

        if (remediations is not null)
        {
            Remediations.AddRange(remediations);
        }

        if (errors is not null)
        {
            Errors.AddRange(errors);
        }
    }

    public CleanupReport(bool dryRun, string rootPath, ThreatCatalog catalog)
    {
        DryRun = dryRun;
        RootPath = rootPath;
        _catalog = catalog;
        Catalog = catalog.Info;
    }

    public bool DryRun { get; }

    public string RootPath { get; }

    public ThreatCatalogInfo Catalog { get; }

    public List<string> Flags { get; } = [];

    public List<GitIssueDetail> GitIssues { get; } = [];

    public List<string> Removals { get; } = [];

    public List<string> Remediations { get; } = [];

    public List<string> Errors { get; } = [];

    [JsonIgnore]
    public IReadOnlyList<string> GitBreadcrumbs => GitIssues.Select(issue => issue.Message).ToList();

    [JsonIgnore]
    public IReadOnlyList<string> GitHistoryBreadcrumbs => GitIssues
        .Where(issue => issue.Kind == GitIssueKind.Breadcrumb)
        .Select(issue => issue.Message)
        .ToList();

    [JsonIgnore]
    public IReadOnlyList<string> GitAccessIssues => GitIssues
        .Where(issue => issue.Kind == GitIssueKind.QueryBlocked)
        .Select(issue => issue.Message)
        .ToList();

    [JsonIgnore]
    public IReadOnlyList<string> GitRootIssues => GitIssues
        .Where(issue => issue.Kind == GitIssueKind.RootMissing)
        .Select(issue => issue.Message)
        .ToList();

    [JsonIgnore]
    public IReadOnlyList<string> SafeDirectoryCommands => GitIssues
        .Where(issue => issue.QueryBlockReason == GitQueryBlockReason.SafeDirectory
                        && !string.IsNullOrWhiteSpace(issue.SafeDirectoryCommand))
        .Select(issue => issue.SafeDirectoryCommand!)
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .ToList();

    [JsonIgnore]
    public IReadOnlyList<string> SafeDirectoryPaths => GitIssues
        .Where(issue => issue.QueryBlockReason == GitQueryBlockReason.SafeDirectory
                        && !string.IsNullOrWhiteSpace(issue.RepositoryPath))
        .Select(issue => issue.RepositoryPath!)
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .ToList();

    public void AddGitBreadcrumb(string message, string? repositoryPath = null)
    {
        GitIssues.Add(GitIssueDetail.CreateBreadcrumb(message, repositoryPath));
    }

    public void AddGitRootIssue(string message, string? repositoryPath = null)
    {
        GitIssues.Add(GitIssueDetail.CreateRootMissing(message, repositoryPath));
    }

    public void AddGitAccessIssue(string message, GitQueryBlockReason reason, string? repositoryPath = null)
    {
        GitIssues.Add(GitIssueDetail.CreateQueryBlocked(message, reason, repositoryPath));
    }

    public IReadOnlyList<string> GetSafeDirectoryCommands()
    {
        return SafeDirectoryCommands;
    }

    public IReadOnlyList<string> GetSafeDirectoryPaths()
    {
        return SafeDirectoryPaths;
    }

    public ScanSeverity GetSeverity()
    {
        if (Errors.Count > 0)
        {
            return ScanSeverity.Error;
        }

        if (Flags.Count > 0 || Removals.Count > 0 || Remediations.Count > 0)
        {
            return ScanSeverity.Critical;
        }

        if (GitAccessIssues.Count > 0 || GitRootIssues.Count > 0)
        {
            return ScanSeverity.Warning;
        }

        if (GitHistoryBreadcrumbs.Count > 0)
        {
            return ScanSeverity.Informational;
        }

        return ScanSeverity.None;
    }

    public IReadOnlyList<string> GetRecommendedActions()
    {
        if (GetSeverity() >= ScanSeverity.Critical)
        {
            return
            [
                "Treat the repository as potentially compromised until dependencies are reinstalled from a trusted source.",
                "Rotate secrets that may have been exposed on affected workstations or CI runners.",
                "Review developer machines and CI systems separately from repository cleanup."
            ];
        }

        if (GetSeverity() == ScanSeverity.Warning)
        {
            return
            [
                "Resolve git access issues before declaring the repository clean.",
                "Re-run the scan after safe.directory or git access problems are fixed."
            ];
        }

        if (GetSeverity() == ScanSeverity.Informational)
        {
            return
            [
                "Review the git breadcrumb hits to determine whether the exposure window affected this repository.",
                "Escalate to deeper triage only if the breadcrumbs align with install-time execution."
            ];
        }

        return
        [
            "No actionable findings were detected in this run."
        ];
    }

    public void Print()
    {
        Console.WriteLine("Axios supply-chain compromise cleanup utility");
        Console.WriteLine($"Mode: {(DryRun ? "DRY RUN" : "LIVE CLEANUP")}");
        Console.WriteLine($"Root: {RootPath}");
        Console.WriteLine($"Severity: {GetSeverity()}");
        Console.WriteLine($"Catalog: {Catalog.CatalogId} {Catalog.Version} sha256={Catalog.Sha256}");
        if (!string.IsNullOrWhiteSpace(Catalog.ValidationMessage))
        {
            Console.WriteLine($"CatalogValidation: {Catalog.ValidationMessage}");
        }
        Console.WriteLine();

        Console.WriteLine($"Summary: LiveFlags={Flags.Count}, GitBreadcrumbs={GitHistoryBreadcrumbs.Count}, GitAccessIssues={GitAccessIssues.Count}, GitRootIssues={GitRootIssues.Count}, Remediations={Remediations.Count}, Removals={Removals.Count}, Errors={Errors.Count}");
        Console.WriteLine();

        PrintSection("Flags", Flags);
        PrintSection("GitBreadcrumbs", GitHistoryBreadcrumbs);
        PrintSection("GitAccessIssues", GitAccessIssues);
        PrintSection("GitRootIssues", GitRootIssues);
        PrintSection("Removals", Removals);
        PrintSection("Remediations", Remediations);
        PrintSection("Errors", Errors);

        Console.WriteLine();
        Console.WriteLine("If anything was found, rotate exposed credentials immediately.");
        Console.WriteLine(_catalog.GetAffectedItemsSummary());
        Console.WriteLine();
        PrintSection("RecommendedActions", GetRecommendedActions());
    }

    public bool HasFindings()
    {
        return Flags.Count > 0
               || GitIssues.Count > 0
               || Removals.Count > 0
               || Remediations.Count > 0
               || Errors.Count > 0;
    }

    private static void PrintSection(string title, IEnumerable<string> items)
    {
        var materialized = items.ToList();
        Console.WriteLine($"{title}: {materialized.Count}");
        foreach (var item in materialized)
        {
            Console.WriteLine($" - {item}");
        }

        Console.WriteLine();
    }
}

public sealed class AllDriveScanReport
{
    public AllDriveScanReport(bool dryRun, bool gitHubOnly)
    {
        DryRun = dryRun;
        GitHubOnly = gitHubOnly;
    }

    public bool DryRun { get; }

    public bool GitHubOnly { get; }

    public ThreatCatalogInfo? Catalog { get; set; }

    public List<string> DrivesScanned { get; } = [];

    public int ReposDiscovered { get; set; }

    public int ReposScanned { get; set; }

    public int ReposWithFindings { get; set; }

    public int ReposWithLiveIndicators { get; set; }

    public int ReposWithGitBreadcrumbs { get; set; }

    public int ReposWithGitAccessIssues { get; set; }

    public int ReposWithRemediationActions { get; set; }

    public List<string> FindingSummaries { get; } = [];

    public List<RepositoryScanSummary> RepositorySummaries { get; } = [];

    public List<string> Errors { get; } = [];

    public IReadOnlyList<string> GetSafeDirectoryCommands()
    {
        return RepositorySummaries
            .SelectMany(summary => summary.SafeDirectoryCommands)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    public IReadOnlyList<string> GetSafeDirectoryPaths()
    {
        return RepositorySummaries
            .Where(summary => summary.SafeDirectoryCommands.Count > 0)
            .Select(summary => summary.RepositoryPath)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    public ScanSeverity GetSeverity()
    {
        if (Errors.Count > 0)
        {
            return ScanSeverity.Error;
        }

        if (ReposWithLiveIndicators > 0 || ReposWithRemediationActions > 0)
        {
            return ScanSeverity.Critical;
        }

        if (ReposWithGitAccessIssues > 0)
        {
            return ScanSeverity.Warning;
        }

        if (ReposWithGitBreadcrumbs > 0)
        {
            return ScanSeverity.Informational;
        }

        return ScanSeverity.None;
    }

    public void Print()
    {
        Console.WriteLine("All-drive git repository scanner");
        Console.WriteLine($"Mode: {(DryRun ? "DRY RUN" : "LIVE")} (all-drives scan always uses dry-run cleanup behavior)");
        Console.WriteLine($"Scope: {(GitHubOnly ? "GitHub-linked repos only" : "All git repos")}");
        Console.WriteLine($"Severity: {GetSeverity()}");
        if (Catalog is not null)
        {
            Console.WriteLine($"Catalog: {Catalog.CatalogId} {Catalog.Version} sha256={Catalog.Sha256}");
        }
        Console.WriteLine($"Drives scanned: {string.Join(", ", DrivesScanned)}");
        Console.WriteLine($"Repositories discovered: {ReposDiscovered}");
        Console.WriteLine($"Repositories scanned: {ReposScanned}");
        Console.WriteLine($"Repositories with findings: {ReposWithFindings}");
        Console.WriteLine($"Repositories with live indicators: {ReposWithLiveIndicators}");
        Console.WriteLine($"Repositories with git breadcrumbs: {ReposWithGitBreadcrumbs}");
        Console.WriteLine($"Repositories with git access issues: {ReposWithGitAccessIssues}");
        Console.WriteLine($"Repositories with remediation actions: {ReposWithRemediationActions}");
        Console.WriteLine();

        PrintRepositorySection(
            "RepositoriesWithLiveIndicators",
            RepositorySummaries.Where(summary => summary.LiveFlags > 0 || summary.Removals > 0 || summary.Remediations > 0 || summary.Errors > 0));
        PrintRepositorySection(
            "RepositoriesWithGitBreadcrumbsOnly",
            RepositorySummaries.Where(summary => summary.LiveFlags == 0
                                                && summary.Removals == 0
                                                && summary.Remediations == 0
                                                && summary.Errors == 0
                                                && summary.GitBreadcrumbs > 0));
        PrintRepositorySection(
            "RepositoriesWithGitAccessIssues",
            RepositorySummaries.Where(summary => summary.GitAccessIssues > 0));

        Console.WriteLine($"FindingSummaries: {FindingSummaries.Count}");
        foreach (var item in FindingSummaries)
        {
            Console.WriteLine($" - {item}");
        }

        Console.WriteLine();
        Console.WriteLine($"Errors: {Errors.Count}");
        foreach (var item in Errors)
        {
            Console.WriteLine($" - {item}");
        }
    }

    private static void PrintRepositorySection(string title, IEnumerable<RepositoryScanSummary> items)
    {
        var materialized = items.ToList();
        Console.WriteLine($"{title}: {materialized.Count}");
        foreach (var item in materialized)
        {
            Console.WriteLine($" - {item.ToDisplayString()}");
        }

        Console.WriteLine();
    }
}

public sealed class AutoTriageReport
{
    public AutoTriageReport(string rootPath, bool pathProvided, bool gitHubOnly)
    {
        RootPath = rootPath;
        PathProvided = pathProvided;
        GitHubOnly = gitHubOnly;
    }

    public string RootPath { get; }

    public bool PathProvided { get; }

    public bool GitHubOnly { get; }

    public ThreatCatalogInfo? Catalog { get; set; }

    public string Mode { get; set; } = "Auto";

    public List<string> DrivesScanned { get; } = [];

    public int RepositoriesDiscovered { get; set; }

    public int RepositoriesScanned { get; set; }

    public int RepositoriesWithFindings { get; set; }

    public int RepositoriesWithLiveIndicators { get; set; }

    public int RepositoriesWithGitBreadcrumbs { get; set; }

    public int RepositoriesWithGitAccessIssues { get; set; }

    public int RepositoriesWithRemediationActions { get; set; }

    public List<string> RepoSummaries { get; } = [];

    public List<RepositoryScanSummary> RepositorySummaries { get; } = [];

    public List<string> Errors { get; } = [];

    public IReadOnlyList<string> GetSafeDirectoryCommands()
    {
        return RepositorySummaries
            .SelectMany(summary => summary.SafeDirectoryCommands)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    public IReadOnlyList<string> GetSafeDirectoryPaths()
    {
        return RepositorySummaries
            .Where(summary => summary.SafeDirectoryCommands.Count > 0)
            .Select(summary => summary.RepositoryPath)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    public ScanSeverity GetSeverity()
    {
        if (Errors.Count > 0)
        {
            return ScanSeverity.Error;
        }

        if (RepositoriesWithLiveIndicators > 0 || RepositoriesWithRemediationActions > 0)
        {
            return ScanSeverity.Critical;
        }

        if (RepositoriesWithGitAccessIssues > 0)
        {
            return ScanSeverity.Warning;
        }

        if (RepositoriesWithGitBreadcrumbs > 0)
        {
            return ScanSeverity.Informational;
        }

        return ScanSeverity.None;
    }

    public void Print()
    {
        Console.WriteLine("Auto triage mode");
        Console.WriteLine($"Mode: {Mode}");
        Console.WriteLine($"Root: {RootPath}");
        Console.WriteLine($"Scope: {(GitHubOnly ? "GitHub-linked repos only" : "All git repos")}");
        Console.WriteLine($"Severity: {GetSeverity()}");
        if (Catalog is not null)
        {
            Console.WriteLine($"Catalog: {Catalog.CatalogId} {Catalog.Version} sha256={Catalog.Sha256}");
        }
        if (DrivesScanned.Count > 0)
        {
            Console.WriteLine($"Drives scanned: {string.Join(", ", DrivesScanned)}");
        }

        Console.WriteLine($"Repositories discovered: {RepositoriesDiscovered}");
        Console.WriteLine($"Repositories scanned: {RepositoriesScanned}");
        Console.WriteLine($"Repositories with findings: {RepositoriesWithFindings}");
        Console.WriteLine($"Repositories with live indicators: {RepositoriesWithLiveIndicators}");
        Console.WriteLine($"Repositories with git breadcrumbs: {RepositoriesWithGitBreadcrumbs}");
        Console.WriteLine($"Repositories with git access issues: {RepositoriesWithGitAccessIssues}");
        Console.WriteLine($"Repositories with remediation actions: {RepositoriesWithRemediationActions}");
        Console.WriteLine();

        Console.WriteLine($"RepositorySummariesDetailed: {RepositorySummaries.Count}");
        foreach (var item in RepositorySummaries)
        {
            Console.WriteLine($" - {item.ToDisplayString()}");
        }

        Console.WriteLine();
        Console.WriteLine($"RepoSummaries: {RepoSummaries.Count}");
        foreach (var item in RepoSummaries)
        {
            Console.WriteLine($" - {item}");
        }

        Console.WriteLine();
        Console.WriteLine($"Errors: {Errors.Count}");
        foreach (var item in Errors)
        {
            Console.WriteLine($" - {item}");
        }
    }
}

public sealed record RepositoryScanSummary(
    string RepositoryPath,
    int LiveFlags,
    int GitBreadcrumbs,
    int GitAccessIssues,
    int GitRootIssues,
    int Remediations,
    int Removals,
    int Errors,
    List<string> SafeDirectoryCommands)
{
    public string ToDisplayString()
    {
        return $"{RepositoryPath} | LiveFlags={LiveFlags}, GitBreadcrumbs={GitBreadcrumbs}, GitAccessIssues={GitAccessIssues}, GitRootIssues={GitRootIssues}, Remediations={Remediations}, Removals={Removals}, Errors={Errors}, SafeDirectoryCommands={SafeDirectoryCommands.Count}";
    }
}

public sealed class SafeDirectoryAssistReport
{
    public string Scope { get; set; } = string.Empty;

    public int RepositoriesWithSafeDirectoryBlocks { get; set; }

    public List<RepositoryScanSummary> RepositorySummaries { get; } = [];

    public List<string> SafeDirectoryCommands { get; } = [];

    public void Print()
    {
        Console.WriteLine("Safe-directory assist report");
        Console.WriteLine($"Scope: {Scope}");
        Console.WriteLine($"Repositories with safe.directory blocks: {RepositoriesWithSafeDirectoryBlocks}");
        Console.WriteLine();

        Console.WriteLine($"BlockedRepositories: {RepositorySummaries.Count}");
        foreach (var item in RepositorySummaries)
        {
            Console.WriteLine($" - {item.ToDisplayString()}");
        }

        Console.WriteLine();
        Console.WriteLine($"SafeDirectoryCommands: {SafeDirectoryCommands.Count}");
        foreach (var command in SafeDirectoryCommands)
        {
            Console.WriteLine($" - {command}");
        }
    }

    public static SafeDirectoryAssistReport FromCleanupReport(CleanupReport report)
    {
        var result = new SafeDirectoryAssistReport
        {
            Scope = report.RootPath
        };

        var commands = report.GetSafeDirectoryCommands();
        result.RepositoriesWithSafeDirectoryBlocks = commands.Count > 0 ? 1 : 0;
        result.SafeDirectoryCommands.AddRange(commands);

        if (commands.Count > 0)
        {
            result.RepositorySummaries.Add(new RepositoryScanSummary(
                report.RootPath,
                report.Flags.Count,
                report.GitHistoryBreadcrumbs.Count,
                report.GitAccessIssues.Count,
                report.GitRootIssues.Count,
                report.Remediations.Count,
                report.Removals.Count,
                report.Errors.Count,
                commands.ToList()));
        }

        return result;
    }

    public static SafeDirectoryAssistReport FromAllDriveScanReport(AllDriveScanReport report)
    {
        return FromRepositorySummaries(report.GitHubOnly ? "All drives (GitHub only)" : "All drives", report.RepositorySummaries);
    }

    public static SafeDirectoryAssistReport FromAutoTriageReport(AutoTriageReport report)
    {
        return FromRepositorySummaries(report.Mode, report.RepositorySummaries);
    }

    private static SafeDirectoryAssistReport FromRepositorySummaries(string scope, IEnumerable<RepositoryScanSummary> summaries)
    {
        var blocked = summaries
            .Where(summary => summary.SafeDirectoryCommands.Count > 0)
            .ToList();

        var result = new SafeDirectoryAssistReport
        {
            Scope = scope,
            RepositoriesWithSafeDirectoryBlocks = blocked.Count
        };

        result.RepositorySummaries.AddRange(blocked);
        result.SafeDirectoryCommands.AddRange(
            blocked.SelectMany(summary => summary.SafeDirectoryCommands)
                .Distinct(StringComparer.OrdinalIgnoreCase));
        return result;
    }
}

public sealed class IncidentSimulationReport
{
    public string RootPath { get; set; } = string.Empty;

    public ThreatCatalogInfo? Catalog { get; set; }

    public bool GitHistorySeeded { get; set; }

    public List<string> FilesCreated { get; } = [];

    public List<string> CommandsExecuted { get; } = [];

    public List<string> Warnings { get; } = [];

    public List<string> Errors { get; } = [];

    public void Print()
    {
        Console.WriteLine("Simulated incident planted");
        Console.WriteLine($"Root: {RootPath}");
        Console.WriteLine($"Git history seeded: {GitHistorySeeded}");
        if (Catalog is not null)
        {
            Console.WriteLine($"Catalog: {Catalog.CatalogId} {Catalog.Version} sha256={Catalog.Sha256}");
        }
        Console.WriteLine();

        Console.WriteLine($"FilesCreated: {FilesCreated.Count}");
        foreach (var file in FilesCreated)
        {
            Console.WriteLine($" - {file}");
        }

        Console.WriteLine();
        Console.WriteLine($"CommandsExecuted: {CommandsExecuted.Count}");
        foreach (var command in CommandsExecuted)
        {
            Console.WriteLine($" - {command}");
        }

        Console.WriteLine();
        Console.WriteLine($"Warnings: {Warnings.Count}");
        foreach (var warning in Warnings)
        {
            Console.WriteLine($" - {warning}");
        }

        Console.WriteLine();
        Console.WriteLine($"Errors: {Errors.Count}");
        foreach (var error in Errors)
        {
            Console.WriteLine($" - {error}");
        }
    }
}

public sealed class RemoteGitHubScanReport
{
    public string Scope { get; set; } = string.Empty;

    public ThreatCatalogInfo? Catalog { get; set; }

    public int RepositoriesDiscovered { get; set; }

    public int RepositoriesScanned { get; set; }

    public int RepositoriesWithFindings { get; set; }

    public int RepositoriesWithErrors { get; set; }

    public List<RemoteGitHubRepositorySummary> RepositorySummaries { get; } = [];

    public List<string> Errors { get; } = [];

    public ScanSeverity GetSeverity()
    {
        if (RepositoriesWithErrors > 0 || Errors.Count > 0)
        {
            return ScanSeverity.Error;
        }

        if (RepositoriesWithFindings > 0)
        {
            return ScanSeverity.Critical;
        }

        return ScanSeverity.None;
    }

    public void Print()
    {
        Console.WriteLine("Remote GitHub repository scan");
        Console.WriteLine($"Scope: {Scope}");
        Console.WriteLine($"Severity: {GetSeverity()}");
        if (Catalog is not null)
        {
            Console.WriteLine($"Catalog: {Catalog.CatalogId} {Catalog.Version} sha256={Catalog.Sha256}");
        }
        Console.WriteLine($"Repositories discovered: {RepositoriesDiscovered}");
        Console.WriteLine($"Repositories scanned: {RepositoriesScanned}");
        Console.WriteLine($"Repositories with findings: {RepositoriesWithFindings}");
        Console.WriteLine($"Repositories with errors: {RepositoriesWithErrors}");
        Console.WriteLine();

        Console.WriteLine($"RepositorySummaries: {RepositorySummaries.Count}");
        foreach (var item in RepositorySummaries)
        {
            Console.WriteLine($" - {item.ToDisplayString()}");
        }

        Console.WriteLine();
        Console.WriteLine($"Errors: {Errors.Count}");
        foreach (var error in Errors)
        {
            Console.WriteLine($" - {error}");
        }
    }
}

public sealed record RemoteGitHubRepositorySummary(
    string RepositoryFullName,
    string DefaultBranch,
    bool IsPrivate,
    bool IsArchived,
    int FilesDiscovered,
    int FilesExamined,
    int FlaggedFiles,
    int GitBreadcrumbs,
    bool TreeTruncated,
    List<string> Findings,
    List<string> Errors)
{
    public string ToDisplayString()
    {
        return $"{RepositoryFullName}@{DefaultBranch} | FilesDiscovered={FilesDiscovered}, FilesExamined={FilesExamined}, FlaggedFiles={FlaggedFiles}, GitBreadcrumbs={GitBreadcrumbs}, Findings={Findings.Count}, Errors={Errors.Count}, TreeTruncated={TreeTruncated}";
    }
}
