using System.Diagnostics;

internal sealed class GitBreadcrumbScanner
{
    private readonly ThreatCatalog _catalog;

    public GitBreadcrumbScanner(ThreatCatalog catalog)
    {
        _catalog = catalog;
    }

    public void Scan(string scanRoot, CleanupReport report)
    {
        var gitRoot = GitRepositoryTraversal.ResolveGitRoot(scanRoot);
        if (gitRoot is null)
        {
            report.AddGitRootIssue("No .git repository found in path ancestry.", scanRoot);
            return;
        }

        var dotGit = Path.Combine(gitRoot, ".git");
        ScanGitTextMetadata(dotGit, report);
        ScanGitHistory(gitRoot, report);
    }

    private void ScanGitTextMetadata(string dotGitPath, CleanupReport report)
    {
        var candidatePaths = new List<string>();
        var logsDir = Path.Combine(dotGitPath, "logs");
        var hooksDir = Path.Combine(dotGitPath, "hooks");

        if (Directory.Exists(logsDir))
        {
            candidatePaths.AddRange(FileSystemTraversal.EnumerateFiles(logsDir, "*"));
        }

        if (Directory.Exists(hooksDir))
        {
            candidatePaths.AddRange(Directory.EnumerateFiles(hooksDir, "*", SearchOption.TopDirectoryOnly)
                .Where(file => !file.EndsWith(".sample", StringComparison.OrdinalIgnoreCase)));
        }

        foreach (var topLevel in new[] { "HEAD", "config", "packed-refs" })
        {
            var fullPath = Path.Combine(dotGitPath, topLevel);
            if (File.Exists(fullPath))
            {
                candidatePaths.Add(fullPath);
            }
        }

        foreach (var path in candidatePaths.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            try
            {
                var content = File.ReadAllText(path);
                var hits = _catalog.GitIndicators.Where(indicator => content.Contains(indicator, StringComparison.OrdinalIgnoreCase)).ToList();
                if (hits.Count > 0)
                {
                    report.AddGitBreadcrumb($".git metadata indicator hit in {path}: {string.Join(", ", hits)}", dotGitPath);
                }
            }
            catch
            {
            }
        }
    }

    private void ScanGitHistory(string gitRoot, CleanupReport report)
    {
        var logResult = RunGit(
            gitRoot,
            "log",
            "--all",
            "--date=iso-strict",
            "--pretty=format:COMMIT:%H|%aI|%s",
            "-p",
            "--",
            "package.json",
            "package-lock.json",
            "yarn.lock",
            "pnpm-lock.yaml");

        if (!logResult.Success)
        {
            report.AddGitAccessIssue($"Unable to query git history: {logResult.Error}".Trim(), DetermineBlockReason(logResult.Error), gitRoot);
            return;
        }

        var lines = logResult.Output.Split('\n');
        string? currentCommit = null;
        DateTimeOffset? currentTime = null;

        foreach (var raw in lines)
        {
            var line = raw.TrimEnd('\r');

            if (line.StartsWith("COMMIT:", StringComparison.Ordinal))
            {
                var parts = line[7..].Split('|', 3);
                currentCommit = parts.Length > 0 ? parts[0] : null;
                currentTime = null;

                if (parts.Length > 1 && DateTimeOffset.TryParse(parts[1], out var parsed))
                {
                    currentTime = parsed.ToUniversalTime();
                    if (_catalog.IsWithinExposureWindow(currentTime.Value))
                    {
                        report.AddGitBreadcrumb($"Commit in exposure window: {currentCommit} at {currentTime:O}", gitRoot);
                    }
                }

                continue;
            }

            if (string.IsNullOrEmpty(currentCommit) || !_catalog.IsGitIndicatorMatch(line))
            {
                continue;
            }

            var stamp = currentTime.HasValue ? currentTime.Value.ToString("O") : "unknown-time";
            report.AddGitBreadcrumb($"IoC in git patch ({stamp}, {currentCommit}): {line.Trim()}", gitRoot);
        }

        var reflogResult = RunGit(gitRoot, "reflog", "--date=iso-strict", "--all");
        if (!reflogResult.Success)
        {
            return;
        }

        foreach (var line in reflogResult.Output.Split('\n'))
        {
            if (!TryExtractIsoDate(line, out var stamp))
            {
                continue;
            }

            if (_catalog.IsWithinExposureWindow(stamp.ToUniversalTime()))
            {
                report.AddGitBreadcrumb($"Reflog activity during exposure window: {line.Trim()}", gitRoot);
            }
        }
    }

    private static GitQueryBlockReason DetermineBlockReason(string error)
    {
        if (error.Contains("safe.directory", StringComparison.OrdinalIgnoreCase)
            || error.Contains("dubious ownership", StringComparison.OrdinalIgnoreCase))
        {
            return GitQueryBlockReason.SafeDirectory;
        }

        if (error.Contains("permission denied", StringComparison.OrdinalIgnoreCase)
            || error.Contains("access is denied", StringComparison.OrdinalIgnoreCase))
        {
            return GitQueryBlockReason.AccessDenied;
        }

        if (error.Contains("failed to start git process", StringComparison.OrdinalIgnoreCase)
            || error.Contains("not recognized as an internal or external command", StringComparison.OrdinalIgnoreCase)
            || error.Contains("no such file or directory", StringComparison.OrdinalIgnoreCase))
        {
            return GitQueryBlockReason.GitUnavailable;
        }

        return GitQueryBlockReason.Unknown;
    }

    private static bool TryExtractIsoDate(string line, out DateTimeOffset stamp)
    {
        stamp = default;
        var firstDigit = line.IndexOfAny("0123456789".ToCharArray());
        if (firstDigit < 0)
        {
            return false;
        }

        var candidate = line[firstDigit..];
        var pieces = candidate.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        foreach (var piece in pieces)
        {
            if (DateTimeOffset.TryParse(piece, out stamp))
            {
                return true;
            }
        }

        return false;
    }

    private static GitResult RunGit(string workingDirectory, params string[] args)
    {
        try
        {
            var startInfo = new ProcessStartInfo
            {
                FileName = "git",
                WorkingDirectory = workingDirectory,
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
                return new GitResult(false, string.Empty, "Failed to start git process.");
            }

            var output = process.StandardOutput.ReadToEnd();
            var error = process.StandardError.ReadToEnd();
            process.WaitForExit();

            return process.ExitCode == 0
                ? new GitResult(true, output, error)
                : new GitResult(false, output, error);
        }
        catch (Exception ex)
        {
            return new GitResult(false, string.Empty, ex.Message);
        }
    }

    private sealed record GitResult(bool Success, string Output, string Error);
}
