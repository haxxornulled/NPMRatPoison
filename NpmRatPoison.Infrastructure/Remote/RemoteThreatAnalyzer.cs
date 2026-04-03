using System.Text.Json.Nodes;

internal static class RemoteThreatAnalyzer
{
    private static readonly string[] DependencySections =
    [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
        "overrides",
        "resolutions"
    ];

    public static List<string> Analyze(string repositoryFullName, string path, string content, ThreatCatalog catalog)
    {
        var findings = new List<string>();
        var fileName = Path.GetFileName(path);

        if (string.Equals(fileName, "package.json", StringComparison.OrdinalIgnoreCase))
        {
            AnalyzePackageJson(findings, repositoryFullName, path, content, catalog);
            return findings;
        }

        if (string.Equals(fileName, "package-lock.json", StringComparison.OrdinalIgnoreCase))
        {
            AnalyzePackageLock(findings, repositoryFullName, path, content, catalog);
            return findings;
        }

        if (catalog.IsTextIndicatorMatch(content))
        {
            findings.Add($"Compromise indicators found in {repositoryFullName}:{path}");
        }

        return findings;
    }

    public static List<string> AnalyzeTreePath(string repositoryFullName, string path, ThreatCatalog catalog)
    {
        var findings = new List<string>();
        var fileName = Path.GetFileName(path);

        if (catalog.WorkspaceArtifactNames.Any(name => string.Equals(name, fileName, StringComparison.OrdinalIgnoreCase)))
        {
            findings.Add($"Suspicious workspace artifact committed in {repositoryFullName}:{path}");
        }

        foreach (var directoryName in catalog.DirectoryNames)
        {
            if (path.Split('/').Any(segment => string.Equals(segment, directoryName, StringComparison.OrdinalIgnoreCase)))
            {
                findings.Add($"Suspicious directory path committed in {repositoryFullName}:{path}");
                break;
            }
        }

        return findings;
    }

    private static void AnalyzePackageJson(List<string> findings, string repositoryFullName, string path, string content, ThreatCatalog catalog)
    {
        JsonObject? rootNode;
        try
        {
            rootNode = JsonNode.Parse(content) as JsonObject;
        }
        catch (Exception ex)
        {
            findings.Add($"Unable to parse {repositoryFullName}:{path}: {ex.Message}");
            return;
        }

        if (rootNode is null)
        {
            return;
        }

        foreach (var sectionName in DependencySections)
        {
            if (rootNode[sectionName] is not JsonObject section)
            {
                continue;
            }

            foreach (var entry in section)
            {
                if (catalog.ShouldRemovePackage(entry.Key))
                {
                    findings.Add($"Suspicious package '{entry.Key}' declared in {repositoryFullName}:{path} ({sectionName})");
                    continue;
                }

                if (!TryGetStringValue(entry.Value, out var value))
                {
                    continue;
                }

                if (catalog.TryRewritePackageSpec(entry.Key, value, out var safeValue))
                {
                    findings.Add($"Compromised package spec '{entry.Key}={value}' in {repositoryFullName}:{path} ({sectionName}); suggested safe value '{safeValue}'");
                }
            }
        }

        if (catalog.IsTextIndicatorMatch(content))
        {
            findings.Add($"Compromise indicators found in {repositoryFullName}:{path}");
        }
    }

    private static void AnalyzePackageLock(List<string> findings, string repositoryFullName, string path, string content, ThreatCatalog catalog)
    {
        JsonObject? rootNode;
        try
        {
            rootNode = JsonNode.Parse(content) as JsonObject;
        }
        catch (Exception ex)
        {
            findings.Add($"Unable to parse {repositoryFullName}:{path}: {ex.Message}");
            return;
        }

        if (rootNode is null)
        {
            return;
        }

        if (rootNode["packages"] is JsonObject packages)
        {
            foreach (var rule in catalog.Packages)
            {
                foreach (var lockPackagePath in rule.LockPackagePaths)
                {
                    if (!packages.TryGetPropertyValue(lockPackagePath, out var node))
                    {
                        continue;
                    }

                    if (rule.RemoveWhenPresent)
                    {
                        findings.Add($"Suspicious lockfile package path '{lockPackagePath}' in {repositoryFullName}:{path}");
                        continue;
                    }

                    if (node is not JsonObject packageNode)
                    {
                        continue;
                    }

                    var currentVersion = packageNode["version"]?.GetValue<string>();
                    if (catalog.TryGetReplacementVersion(rule.PackageName, currentVersion, out var safeVersion))
                    {
                        findings.Add($"Compromised lockfile version '{rule.PackageName}={currentVersion}' in {repositoryFullName}:{path}; suggested safe version '{safeVersion}'");
                    }
                }
            }
        }

        if (rootNode["dependencies"] is JsonObject dependencies)
        {
            AnalyzeDependencyObject(findings, repositoryFullName, path, dependencies, catalog);
        }

        if (catalog.IsTextIndicatorMatch(content))
        {
            findings.Add($"Compromise indicators found in {repositoryFullName}:{path}");
        }
    }

    private static void AnalyzeDependencyObject(List<string> findings, string repositoryFullName, string path, JsonObject dependencies, ThreatCatalog catalog)
    {
        foreach (var entry in dependencies)
        {
            if (catalog.ShouldRemovePackage(entry.Key))
            {
                findings.Add($"Suspicious dependency '{entry.Key}' in {repositoryFullName}:{path}");
                continue;
            }

            if (entry.Value is not JsonObject dependencyNode)
            {
                continue;
            }

            var version = dependencyNode["version"]?.GetValue<string>();
            if (catalog.TryGetReplacementVersion(entry.Key, version, out var safeVersion))
            {
                findings.Add($"Compromised dependency '{entry.Key}={version}' in {repositoryFullName}:{path}; suggested safe version '{safeVersion}'");
            }

            if (dependencyNode["dependencies"] is JsonObject nested)
            {
                AnalyzeDependencyObject(findings, repositoryFullName, path, nested, catalog);
            }
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
