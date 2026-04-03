using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging;

public sealed class ThreatCleanupService : IThreatCleanupService
{
    private readonly IScanProgressPublisher _progressPublisher;
    private readonly ILogger<ThreatCleanupService> _logger;

    public ThreatCleanupService(IScanProgressPublisher progressPublisher, ILogger<ThreatCleanupService> logger)
    {
        _progressPublisher = progressPublisher;
        _logger = logger;
    }

    public async Task<CleanupReport> ExecuteAsync(string rootPath, bool dryRun, ThreatCatalog catalog, bool includeHostLevelChecks = true)
    {
        _progressPublisher.Publish("folder", null, rootPath, "Scanning folder");
        var report = new CleanupReport(dryRun, rootPath, catalog);

        ScanGitBreadcrumbs(rootPath, catalog, report);
        await HandlePackageJsonFilesAsync(rootPath, dryRun, catalog, report);
        await HandlePackageLockFilesAsync(rootPath, dryRun, catalog, report);
        await HandleTextLockFilesAsync(rootPath, report, catalog, "yarn.lock");
        await HandleTextLockFilesAsync(rootPath, report, catalog, "pnpm-lock.yaml");

        foreach (var directoryName in catalog.DirectoryNames)
        {
            RemoveNamedDirectories(rootPath, dryRun, report, directoryName);
        }

        if (includeHostLevelChecks)
        {
            RemoveKnownArtifacts(rootPath, dryRun, report, catalog);
            await SanitizeShellProfilesAsync(dryRun, report, catalog);
        }

        return report;
    }

    private void ScanGitBreadcrumbs(string rootPath, ThreatCatalog catalog, CleanupReport report)
    {
        try
        {
            var scanner = new GitBreadcrumbScanner(catalog);
            scanner.Scan(rootPath, report);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Git breadcrumb scan failure for {RootPath}", rootPath);
            report.Errors.Add($"Git breadcrumb scan failure: {ex.Message}");
        }
    }

    private static async Task HandlePackageJsonFilesAsync(string rootPath, bool dryRun, ThreatCatalog catalog, CleanupReport report)
    {
        foreach (var file in FileSystemTraversal.EnumerateFiles(rootPath, "package.json"))
        {
            try
            {
                var rootNode = JsonNode.Parse(await File.ReadAllTextAsync(file)) as JsonObject;
                if (rootNode is null)
                {
                    continue;
                }

                var modified = false;
                modified |= SanitizeDependencyMap(rootNode, "dependencies", catalog, report, file);
                modified |= SanitizeDependencyMap(rootNode, "devDependencies", catalog, report, file);
                modified |= SanitizeDependencyMap(rootNode, "optionalDependencies", catalog, report, file);
                modified |= SanitizeDependencyMap(rootNode, "peerDependencies", catalog, report, file);
                modified |= SanitizeDependencyMap(rootNode, "overrides", catalog, report, file);
                modified |= SanitizeDependencyMap(rootNode, "resolutions", catalog, report, file);

                if (modified)
                {
                    await WriteJsonAsync(file, rootNode, dryRun, report);
                }
            }
            catch (Exception ex)
            {
                report.Errors.Add($"package.json parse failure: {file} ({ex.Message})");
            }
        }
    }

    private static async Task HandlePackageLockFilesAsync(string rootPath, bool dryRun, ThreatCatalog catalog, CleanupReport report)
    {
        foreach (var file in FileSystemTraversal.EnumerateFiles(rootPath, "package-lock.json"))
        {
            try
            {
                var content = await File.ReadAllTextAsync(file);
                var rootNode = JsonNode.Parse(content) as JsonObject;
                if (rootNode is null)
                {
                    continue;
                }

                if (ShouldQuarantinePackageLock(rootNode, content, catalog))
                {
                    await QuarantineLockFileAsync(rootPath, file, dryRun, report, "package-lock.json contains compromised dependency metadata and must be regenerated from a trusted registry.");
                }
            }
            catch (Exception ex)
            {
                report.Errors.Add($"package-lock parse failure: {file} ({ex.Message})");
            }
        }
    }

    private static bool ShouldQuarantinePackageLock(JsonObject rootNode, string content, ThreatCatalog catalog)
    {
        if (rootNode["packages"] is not JsonObject packages)
        {
            return catalog.IsTextIndicatorMatch(content);
        }

        foreach (var rule in catalog.Packages)
        {
            foreach (var lockPackagePath in rule.LockPackagePaths)
            {
                if (!packages.ContainsKey(lockPackagePath))
                {
                    continue;
                }

                return true;
            }
        }

        if (rootNode["dependencies"] is not JsonObject dependencies)
        {
            return catalog.IsTextIndicatorMatch(content);
        }

        foreach (var entry in dependencies)
        {
            if (catalog.ShouldRemovePackage(entry.Key))
            {
                return true;
            }

            if (entry.Value is not JsonObject dependencyNode)
            {
                continue;
            }

            var version = dependencyNode["version"]?.GetValue<string>();
            if (catalog.TryGetReplacementVersion(entry.Key, version, out _))
            {
                return true;
            }

            if (dependencyNode["dependencies"] is JsonObject childDependencies)
            {
                if (ShouldQuarantineNestedDependencyObject(childDependencies, catalog))
                {
                    return true;
                }
            }
        }

        return catalog.IsTextIndicatorMatch(content);
    }

    private static bool SanitizeDependencyMap(JsonObject rootNode, string sectionName, ThreatCatalog catalog, CleanupReport report, string file)
    {
        if (rootNode[sectionName] is not JsonObject section)
        {
            return false;
        }

        var modified = false;
        var keys = section.Select(kvp => kvp.Key).ToList();

        foreach (var key in keys)
        {
            if (catalog.ShouldRemovePackage(key))
            {
                section.Remove(key);
                report.Removals.Add($"Removed {key} from {sectionName} in {file}");
                modified = true;
                continue;
            }

            if (!TryGetStringValue(section[key], out var value))
            {
                continue;
            }

            if (!catalog.TryRewritePackageSpec(key, value, out var safeValue))
            {
                continue;
            }

            section[key] = safeValue;
            report.Remediations.Add($"Downgraded {key} spec '{value}' -> '{safeValue}' in {sectionName} ({file})");
            modified = true;
        }

        return modified;
    }

    private static bool ShouldQuarantineNestedDependencyObject(JsonObject dependencies, ThreatCatalog catalog)
    {
        foreach (var entry in dependencies)
        {
            if (catalog.ShouldRemovePackage(entry.Key))
            {
                return true;
            }

            if (entry.Value is not JsonObject dependencyNode)
            {
                continue;
            }

            var version = dependencyNode["version"]?.GetValue<string>();
            if (catalog.TryGetReplacementVersion(entry.Key, version, out _))
            {
                return true;
            }

            if (dependencyNode["dependencies"] is JsonObject nested && ShouldQuarantineNestedDependencyObject(nested, catalog))
            {
                return true;
            }
        }

        return false;
    }

    private static async Task HandleTextLockFilesAsync(string rootPath, CleanupReport report, ThreatCatalog catalog, string fileName)
    {
        foreach (var file in FileSystemTraversal.EnumerateFiles(rootPath, fileName))
        {
            try
            {
                var content = await File.ReadAllTextAsync(file);
                if (catalog.IsTextIndicatorMatch(content))
                {
                    await QuarantineLockFileAsync(rootPath, file, report.DryRun, report, $"{fileName} contains compromise indicators and must be regenerated from a trusted registry.");
                }
            }
            catch (Exception ex)
            {
                report.Errors.Add($"Text lock parse failure: {file} ({ex.Message})");
            }
        }
    }

    private static void RemoveNamedDirectories(string rootPath, bool dryRun, CleanupReport report, string name)
    {
        foreach (var directory in FileSystemTraversal.EnumerateDirectoriesByName(rootPath, name))
        {
            DeletePath(directory, dryRun, report, $"Deleted suspicious directory: {directory}");
        }
    }

    private static void RemoveKnownArtifacts(string rootPath, bool dryRun, CleanupReport report, ThreatCatalog catalog)
    {
        foreach (var path in catalog.GetHostArtifactPathsForCurrentOs())
        {
            if (Directory.Exists(path))
            {
                DeletePath(path, dryRun, report, $"Deleted suspicious directory artifact: {path}");
            }
            else if (File.Exists(path))
            {
                DeletePath(path, dryRun, report, $"Deleted suspicious file artifact: {path}");
            }
        }

        foreach (var fileName in catalog.WorkspaceArtifactNames)
        {
            foreach (var file in FileSystemTraversal.EnumerateFiles(rootPath, fileName))
            {
                DeletePath(file, dryRun, report, $"Deleted suspicious workspace artifact: {file}");
            }
        }
    }

    private static async Task SanitizeShellProfilesAsync(bool dryRun, CleanupReport report, ThreatCatalog catalog)
    {
        var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        if (string.IsNullOrWhiteSpace(home))
        {
            return;
        }

        foreach (var profile in new[] { ".bashrc", ".zshrc" })
        {
            var fullPath = Path.Combine(home, profile);
            if (!File.Exists(fullPath))
            {
                continue;
            }

            try
            {
                var lines = await File.ReadAllLinesAsync(fullPath);
                var filtered = lines.Where(line => !catalog.IsShellProfileIndicatorMatch(line)).ToArray();

                if (filtered.Length == lines.Length)
                {
                    continue;
                }

                if (!dryRun)
                {
                    await File.WriteAllLinesAsync(fullPath, filtered);
                }

                report.Remediations.Add($"Sanitized suspicious persistence lines in {fullPath}");
            }
            catch (Exception ex)
            {
                report.Errors.Add($"Profile sanitization failure: {fullPath} ({ex.Message})");
            }
        }
    }

    private static void DeletePath(string path, bool dryRun, CleanupReport report, string message)
    {
        try
        {
            if (!dryRun)
            {
                if (Directory.Exists(path))
                {
                    Directory.Delete(path, true);
                }
                else if (File.Exists(path))
                {
                    File.Delete(path);
                }
            }

            report.Removals.Add(message);
        }
        catch (Exception ex)
        {
            report.Errors.Add($"Delete failure: {path} ({ex.Message})");
        }
    }

    private static async Task WriteJsonAsync(string file, JsonObject rootNode, bool dryRun, CleanupReport report)
    {
        if (dryRun)
        {
            report.Remediations.Add($"Would update {file}");
            return;
        }

        var output = JsonSerializer.Serialize(rootNode, new JsonSerializerOptions { WriteIndented = true });
        await File.WriteAllTextAsync(file, output);
        report.Remediations.Add($"Updated {file}");
    }

    private static async Task QuarantineLockFileAsync(string rootPath, string file, bool dryRun, CleanupReport report, string reason)
    {
        var quarantineRoot = Path.Combine(rootPath, ".npmratpoison", "quarantine", DateTimeOffset.UtcNow.ToString("yyyyMMdd-HHmmss"));
        var relativePath = Path.GetRelativePath(rootPath, file);
        var quarantinePath = Path.Combine(quarantineRoot, relativePath);

        if (dryRun)
        {
            report.Remediations.Add($"Would quarantine compromised lockfile: {file}");
            report.Remediations.Add($"Would require clean dependency reinstall after removing {file}");
            report.Flags.Add(reason);
            return;
        }

        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(quarantinePath)!);
            File.Move(file, quarantinePath, overwrite: false);
            report.Remediations.Add($"Quarantined compromised lockfile: {file} -> {quarantinePath}");
            report.Removals.Add($"Removed compromised lockfile from active tree: {file}");
            report.Flags.Add(reason);
            await File.WriteAllTextAsync(
                $"{quarantinePath}.metadata.txt",
                $"OriginalPath: {file}{Environment.NewLine}QuarantinedAtUtc: {DateTimeOffset.UtcNow:O}{Environment.NewLine}Reason: {reason}{Environment.NewLine}");
        }
        catch (Exception ex)
        {
            report.Errors.Add($"Lockfile quarantine failure: {file} ({ex.Message})");
        }
    }

    private static bool TryGetStringValue(JsonNode? node, out string value)
    {
        value = string.Empty;
        if (node is null)
        {
            return false;
        }

        try
        {
            value = node.GetValue<string>();
            return true;
        }
        catch
        {
            return false;
        }
    }
}
