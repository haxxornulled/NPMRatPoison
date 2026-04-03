using System.Text;
using System.Text.Json;
using System.Net;
using Microsoft.Extensions.Logging;

public sealed class JsonReportWriter : IReportWriter
{
    private readonly ILogger<JsonReportWriter> _logger;

    public JsonReportWriter(ILogger<JsonReportWriter> logger)
    {
        _logger = logger;
    }

    public async Task WriteAsync<T>(string? reportDirectory, string prefix, T report, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(reportDirectory))
        {
            return;
        }

        Directory.CreateDirectory(reportDirectory);
        var filePrefix = Path.Combine(reportDirectory, $"{prefix}-{DateTimeOffset.UtcNow:yyyyMMdd-HHmmssfff}");
        var jsonFile = $"{filePrefix}.json";
        var json = JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true });
        await File.WriteAllTextAsync(jsonFile, json, cancellationToken);
        _logger.LogInformation("Report written: {ReportPath}", jsonFile);

        var csv = BuildCsv(report);
        if (csv is not null)
        {
            var csvFile = $"{filePrefix}.csv";
            await File.WriteAllTextAsync(csvFile, csv, cancellationToken);
            _logger.LogInformation("CSV report written: {ReportPath}", csvFile);
        }

        var htmlFile = $"{filePrefix}.html";
        var html = BuildHtml(report, json);
        await File.WriteAllTextAsync(htmlFile, html, cancellationToken);
        _logger.LogInformation("HTML report written: {ReportPath}", htmlFile);
    }

    private static string? BuildCsv<T>(T report)
    {
        return report switch
        {
            CleanupReport cleanupReport => BuildCleanupCsv(cleanupReport),
            AllDriveScanReport allDriveScanReport => BuildRepositorySummaryCsv(allDriveScanReport.RepositorySummaries),
            AutoTriageReport autoTriageReport => BuildRepositorySummaryCsv(autoTriageReport.RepositorySummaries),
            SafeDirectoryAssistReport safeDirectoryAssistReport => BuildSafeDirectoryAssistCsv(safeDirectoryAssistReport),
            IncidentSimulationReport incidentSimulationReport => BuildIncidentSimulationCsv(incidentSimulationReport),
            RemoteGitHubScanReport remoteGitHubScanReport => BuildRemoteGitHubScanCsv(remoteGitHubScanReport),
            _ => null
        };
    }

    private static string BuildCleanupCsv(CleanupReport report)
    {
        var builder = new StringBuilder();
        AppendRow(builder, "Category", "Kind", "QueryBlockReason", "RepositoryPath", "Message", "SafeDirectoryCommand");

        foreach (var flag in report.Flags)
        {
            AppendRow(builder, "Flag", string.Empty, string.Empty, report.RootPath, flag, string.Empty);
        }

        foreach (var issue in report.GitIssues)
        {
            AppendRow(
                builder,
                "GitIssue",
                issue.Kind.ToString(),
                issue.QueryBlockReason == GitQueryBlockReason.None ? string.Empty : issue.QueryBlockReason.ToString(),
                issue.RepositoryPath ?? report.RootPath,
                issue.Message,
                issue.SafeDirectoryCommand ?? string.Empty);
        }

        foreach (var remediation in report.Remediations)
        {
            AppendRow(builder, "Remediation", string.Empty, string.Empty, report.RootPath, remediation, string.Empty);
        }

        foreach (var removal in report.Removals)
        {
            AppendRow(builder, "Removal", string.Empty, string.Empty, report.RootPath, removal, string.Empty);
        }

        foreach (var error in report.Errors)
        {
            AppendRow(builder, "Error", string.Empty, string.Empty, report.RootPath, error, string.Empty);
        }

        return builder.ToString();
    }

    private static string BuildRepositorySummaryCsv(IEnumerable<RepositoryScanSummary> summaries)
    {
        var builder = new StringBuilder();
        AppendRow(
            builder,
            "RepositoryPath",
            "LiveFlags",
            "GitBreadcrumbs",
            "GitAccessIssues",
            "GitRootIssues",
            "Remediations",
            "Removals",
            "Errors",
            "SafeDirectoryCommands");

        foreach (var summary in summaries)
        {
            AppendRow(
                builder,
                summary.RepositoryPath,
                summary.LiveFlags.ToString(),
                summary.GitBreadcrumbs.ToString(),
                summary.GitAccessIssues.ToString(),
                summary.GitRootIssues.ToString(),
                summary.Remediations.ToString(),
                summary.Removals.ToString(),
                summary.Errors.ToString(),
                string.Join(" | ", summary.SafeDirectoryCommands));
        }

        return builder.ToString();
    }

    private static string BuildSafeDirectoryAssistCsv(SafeDirectoryAssistReport report)
    {
        var builder = new StringBuilder();
        AppendRow(builder, "RepositoryPath", "GitAccessIssues", "SafeDirectoryCommands");

        foreach (var summary in report.RepositorySummaries)
        {
            AppendRow(
                builder,
                summary.RepositoryPath,
                summary.GitAccessIssues.ToString(),
                string.Join(" | ", summary.SafeDirectoryCommands));
        }

        return builder.ToString();
    }

    private static string BuildIncidentSimulationCsv(IncidentSimulationReport report)
    {
        var builder = new StringBuilder();
        AppendRow(builder, "Category", "RootPath", "Value");

        foreach (var file in report.FilesCreated)
        {
            AppendRow(builder, "FileCreated", report.RootPath, file);
        }

        foreach (var command in report.CommandsExecuted)
        {
            AppendRow(builder, "CommandExecuted", report.RootPath, command);
        }

        foreach (var warning in report.Warnings)
        {
            AppendRow(builder, "Warning", report.RootPath, warning);
        }

        foreach (var error in report.Errors)
        {
            AppendRow(builder, "Error", report.RootPath, error);
        }

        return builder.ToString();
    }

    private static string BuildRemoteGitHubScanCsv(RemoteGitHubScanReport report)
    {
        var builder = new StringBuilder();
        AppendRow(
            builder,
            "RepositoryFullName",
            "DefaultBranch",
            "FilesDiscovered",
            "FilesExamined",
            "FlaggedFiles",
            "GitBreadcrumbs",
            "TreeTruncated",
            "Findings",
            "Errors");

        foreach (var summary in report.RepositorySummaries)
        {
            AppendRow(
                builder,
                summary.RepositoryFullName,
                summary.DefaultBranch,
                summary.FilesDiscovered.ToString(),
                summary.FilesExamined.ToString(),
                summary.FlaggedFiles.ToString(),
                summary.GitBreadcrumbs.ToString(),
                summary.TreeTruncated.ToString(),
                string.Join(" | ", summary.Findings),
                string.Join(" | ", summary.Errors));
        }

        return builder.ToString();
    }

    private static void AppendRow(StringBuilder builder, params string[] columns)
    {
        builder.AppendLine(string.Join(",", columns.Select(EscapeCsv)));
    }

    private static string EscapeCsv(string value)
    {
        var sanitized = value.Replace("\"", "\"\"");
        return $"\"{sanitized}\"";
    }

    private static string BuildHtml<T>(T report, string json)
    {
        var title = report switch
        {
            CleanupReport => "Scoped Cleanup Report",
            AllDriveScanReport => "All-Drive Scan Report",
            AutoTriageReport => "Auto-Triage Report",
            SafeDirectoryAssistReport => "Safe Directory Assist Report",
            IncidentSimulationReport => "Incident Simulation Report",
            RemoteGitHubScanReport => "Remote GitHub Scan Report",
            _ => "NpmRatPoison Report"
        };

        var summaryRows = GetSummaryRows(report)
            .Select(row => $"<tr><th>{WebUtility.HtmlEncode(row.Label)}</th><td>{WebUtility.HtmlEncode(row.Value)}</td></tr>");

        return $$"""
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>{{WebUtility.HtmlEncode(title)}}</title>
  <style>
    :root { color-scheme: light; }
    body { font-family: "Segoe UI", sans-serif; margin: 32px; color: #18212b; background: #f6f8fb; }
    h1, h2 { margin-bottom: 12px; }
    .card { background: #fff; border: 1px solid #d8e0ea; border-radius: 12px; padding: 20px; margin-bottom: 20px; box-shadow: 0 8px 20px rgba(15, 23, 42, 0.05); }
    table { border-collapse: collapse; width: 100%; }
    th, td { text-align: left; padding: 10px 12px; border-bottom: 1px solid #e5ebf2; vertical-align: top; }
    th { width: 30%; color: #314254; }
    pre { white-space: pre-wrap; word-break: break-word; background: #0f172a; color: #e2e8f0; padding: 16px; border-radius: 10px; overflow-x: auto; }
  </style>
</head>
<body>
  <div class="card">
    <h1>{{WebUtility.HtmlEncode(title)}}</h1>
    <table>
      {{string.Join(Environment.NewLine, summaryRows)}}
    </table>
  </div>
  <div class="card">
    <h2>Raw JSON</h2>
    <pre>{{WebUtility.HtmlEncode(json)}}</pre>
  </div>
</body>
</html>
""";
    }

    private static IReadOnlyList<(string Label, string Value)> GetSummaryRows<T>(T report)
    {
        return report switch
        {
            CleanupReport cleanupReport =>
            [
                ("Severity", cleanupReport.GetSeverity().ToString()),
                ("Root", cleanupReport.RootPath),
                ("Catalog", $"{cleanupReport.Catalog.CatalogId} {cleanupReport.Catalog.Version}"),
                ("Flags", cleanupReport.Flags.Count.ToString()),
                ("Remediations", cleanupReport.Remediations.Count.ToString()),
                ("Removals", cleanupReport.Removals.Count.ToString()),
                ("Errors", cleanupReport.Errors.Count.ToString())
            ],
            AllDriveScanReport allDriveScanReport =>
            [
                ("Severity", allDriveScanReport.GetSeverity().ToString()),
                ("Scope", allDriveScanReport.GitHubOnly ? "GitHub repos only" : "All git repos"),
                ("Catalog", allDriveScanReport.Catalog is null ? "n/a" : $"{allDriveScanReport.Catalog.CatalogId} {allDriveScanReport.Catalog.Version}"),
                ("Repos Discovered", allDriveScanReport.ReposDiscovered.ToString()),
                ("Repos Scanned", allDriveScanReport.ReposScanned.ToString()),
                ("Repos With Findings", allDriveScanReport.ReposWithFindings.ToString()),
                ("Errors", allDriveScanReport.Errors.Count.ToString())
            ],
            AutoTriageReport autoTriageReport =>
            [
                ("Severity", autoTriageReport.GetSeverity().ToString()),
                ("Mode", autoTriageReport.Mode),
                ("Catalog", autoTriageReport.Catalog is null ? "n/a" : $"{autoTriageReport.Catalog.CatalogId} {autoTriageReport.Catalog.Version}"),
                ("Repos Discovered", autoTriageReport.RepositoriesDiscovered.ToString()),
                ("Repos Scanned", autoTriageReport.RepositoriesScanned.ToString()),
                ("Repos With Findings", autoTriageReport.RepositoriesWithFindings.ToString()),
                ("Errors", autoTriageReport.Errors.Count.ToString())
            ],
            RemoteGitHubScanReport remoteGitHubScanReport =>
            [
                ("Severity", remoteGitHubScanReport.GetSeverity().ToString()),
                ("Scope", remoteGitHubScanReport.Scope),
                ("Catalog", remoteGitHubScanReport.Catalog is null ? "n/a" : $"{remoteGitHubScanReport.Catalog.CatalogId} {remoteGitHubScanReport.Catalog.Version}"),
                ("Repositories Discovered", remoteGitHubScanReport.RepositoriesDiscovered.ToString()),
                ("Repositories Scanned", remoteGitHubScanReport.RepositoriesScanned.ToString()),
                ("Repositories With Findings", remoteGitHubScanReport.RepositoriesWithFindings.ToString()),
                ("Repositories With Errors", remoteGitHubScanReport.RepositoriesWithErrors.ToString())
            ],
            IncidentSimulationReport incidentSimulationReport =>
            [
                ("Root", incidentSimulationReport.RootPath),
                ("Catalog", incidentSimulationReport.Catalog is null ? "n/a" : $"{incidentSimulationReport.Catalog.CatalogId} {incidentSimulationReport.Catalog.Version}"),
                ("Files Created", incidentSimulationReport.FilesCreated.Count.ToString()),
                ("Warnings", incidentSimulationReport.Warnings.Count.ToString()),
                ("Errors", incidentSimulationReport.Errors.Count.ToString())
            ],
            SafeDirectoryAssistReport safeDirectoryAssistReport =>
            [
                ("Scope", safeDirectoryAssistReport.Scope),
                ("Repositories With Blocks", safeDirectoryAssistReport.RepositoriesWithSafeDirectoryBlocks.ToString()),
                ("Commands", safeDirectoryAssistReport.SafeDirectoryCommands.Count.ToString())
            ],
            _ =>
            [
                ("Type", typeof(T).Name)
            ]
        };
    }
}
