using System.Diagnostics;
using System.Text.Json;

public sealed class IncidentSimulationService : IIncidentSimulationService
{
    public async Task<IncidentSimulationReport> PlantAsync(string rootPath, ThreatCatalog catalog, CancellationToken cancellationToken = default)
    {
        var report = new IncidentSimulationReport
        {
            RootPath = Path.GetFullPath(rootPath),
            Catalog = catalog.Info
        };

        Directory.CreateDirectory(report.RootPath);

        var compromisedPackage = catalog.Packages.FirstOrDefault(rule => rule.ReplacementVersions.Count > 0);
        var droppedPackage = catalog.Packages.FirstOrDefault(rule => rule.RemoveWhenPresent);
        var c2Indicator = catalog.TextIndicators.FirstOrDefault(indicator => indicator.Contains("sfrclak.com", StringComparison.OrdinalIgnoreCase))
                          ?? catalog.TextIndicators.FirstOrDefault()
                          ?? "sfrclak.com";
        var compromisedVersion = compromisedPackage?.ReplacementVersions.Keys.FirstOrDefault() ?? "1.14.1";

        var packageJsonPath = Path.Combine(report.RootPath, "package.json");
        var packageJson = new
        {
            name = "simulated-incident",
            version = "1.0.0",
            dependencies = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                [compromisedPackage?.PackageName ?? "axios"] = compromisedVersion,
                [droppedPackage?.PackageName ?? "plain-crypto-js"] = "4.2.1"
            },
            scripts = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["postinstall"] = "node node_modules/plain-crypto-js/setup.js"
            }
        };
        await WriteJsonAsync(packageJsonPath, packageJson, report, cancellationToken);

        var packageLockPath = Path.Combine(report.RootPath, "package-lock.json");
        var packageLock = new
        {
            name = "simulated-incident",
            lockfileVersion = 3,
            requires = true,
            packages = new Dictionary<string, object?>
            {
                [""] = new
                {
                    name = "simulated-incident",
                    version = "1.0.0",
                    dependencies = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                    {
                        [compromisedPackage?.PackageName ?? "axios"] = compromisedVersion,
                        [droppedPackage?.PackageName ?? "plain-crypto-js"] = "4.2.1"
                    }
                },
                [$"node_modules/{compromisedPackage?.PackageName ?? "axios"}"] = new
                {
                    version = compromisedVersion,
                    resolved = $"https://registry.npmjs.org/{compromisedPackage?.PackageName ?? "axios"}/-/{compromisedPackage?.PackageName ?? "axios"}-{compromisedVersion}.tgz",
                    integrity = "sha512-simulated"
                },
                [$"node_modules/{droppedPackage?.PackageName ?? "plain-crypto-js"}"] = new
                {
                    version = "4.2.1",
                    resolved = $"http://{c2Indicator}:8000/plain-crypto-js-4.2.1.tgz",
                    integrity = "sha512-compromised"
                }
            },
            dependencies = new Dictionary<string, object?>
            {
                [compromisedPackage?.PackageName ?? "axios"] = new
                {
                    version = compromisedVersion
                },
                [droppedPackage?.PackageName ?? "plain-crypto-js"] = new
                {
                    version = "4.2.1"
                }
            }
        };
        await WriteJsonAsync(packageLockPath, packageLock, report, cancellationToken);

        var yarnLockPath = Path.Combine(report.RootPath, "yarn.lock");
        await WriteTextAsync(
            yarnLockPath,
            $"{compromisedPackage?.PackageName ?? "axios"}@{compromisedVersion}:\n  version \"{compromisedVersion}\"\n\n{droppedPackage?.PackageName ?? "plain-crypto-js"}@4.2.1:\n  version \"4.2.1\"\n  resolved \"http://sfrclak.com:8000/plain-crypto-js-4.2.1.tgz\"\n",
            report,
            cancellationToken);

        var pnpmLockPath = Path.Combine(report.RootPath, "pnpm-lock.yaml");
        await WriteTextAsync(
            pnpmLockPath,
            $"packages:\n  /{compromisedPackage?.PackageName ?? "axios"}/{compromisedVersion}:\n    resolution: {{integrity: sha512-simulated}}\n  /{droppedPackage?.PackageName ?? "plain-crypto-js"}/4.2.1:\n    resolution: {{tarball: http://sfrclak.com:8000/plain-crypto-js-4.2.1.tgz}}\n",
            report,
            cancellationToken);

        var droppedPackageDir = Path.Combine(report.RootPath, "node_modules", droppedPackage?.PackageName ?? "plain-crypto-js");
        Directory.CreateDirectory(droppedPackageDir);
        report.FilesCreated.Add(droppedPackageDir);
        await WriteTextAsync(Path.Combine(droppedPackageDir, "package.json"), "{\"name\":\"plain-crypto-js\",\"version\":\"4.2.1\"}", report, cancellationToken);
        await WriteTextAsync(
            Path.Combine(droppedPackageDir, "setup.js"),
            $"const endpoint = 'http://sfrclak.com:8000';\nconsole.log('contacting ' + endpoint);\n",
            report,
            cancellationToken);

        var workspaceArtifactPath = Path.Combine(report.RootPath, GetWorkspaceArtifactNameForCurrentOs(catalog));
        await WriteTextAsync(workspaceArtifactPath, $"# simulated artifact\n# callback {c2Indicator}\n", report, cancellationToken);

        await InitializeGitHistoryAsync(report.RootPath, catalog, report, cancellationToken);
        return report;
    }

    private static string GetWorkspaceArtifactNameForCurrentOs(ThreatCatalog catalog)
    {
        if (OperatingSystem.IsWindows())
        {
            return catalog.WorkspaceArtifactNames.FirstOrDefault(name => name.EndsWith(".ps1", StringComparison.OrdinalIgnoreCase))
                   ?? catalog.WorkspaceArtifactNames.FirstOrDefault()
                   ?? "6202033.ps1";
        }

        if (OperatingSystem.IsLinux())
        {
            return catalog.WorkspaceArtifactNames.FirstOrDefault(name => name.EndsWith(".py", StringComparison.OrdinalIgnoreCase))
                   ?? "ld.py";
        }

        return catalog.WorkspaceArtifactNames.FirstOrDefault() ?? "wt.exe";
    }

    private static async Task WriteJsonAsync(string path, object payload, IncidentSimulationReport report, CancellationToken cancellationToken)
    {
        var json = JsonSerializer.Serialize(payload, new JsonSerializerOptions { WriteIndented = true });
        await File.WriteAllTextAsync(path, json, cancellationToken);
        report.FilesCreated.Add(path);
    }

    private static async Task WriteTextAsync(string path, string content, IncidentSimulationReport report, CancellationToken cancellationToken)
    {
        var directory = Path.GetDirectoryName(path);
        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }

        await File.WriteAllTextAsync(path, content, cancellationToken);
        report.FilesCreated.Add(path);
    }

    private static async Task InitializeGitHistoryAsync(string rootPath, ThreatCatalog catalog, IncidentSimulationReport report, CancellationToken cancellationToken)
    {
        var initResult = await RunGitAsync(rootPath, cancellationToken, "init");
        if (!initResult.Success)
        {
            report.Warnings.Add($"Git history was not seeded: {initResult.Error}");
            return;
        }

        report.CommandsExecuted.Add("git init");
        await RunGitAsync(rootPath, cancellationToken, "config", "user.email", "incident-sim@example.test");
        await RunGitAsync(rootPath, cancellationToken, "config", "user.name", "Incident Simulator");

        var exposureStamp = catalog.ExposureWindows.FirstOrDefault();
        var commitTime = exposureStamp is not null && exposureStamp.IsValid()
            ? exposureStamp.StartUtc.AddMinutes(5)
            : DateTimeOffset.UtcNow;

        var env = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["GIT_AUTHOR_DATE"] = commitTime.ToString("O"),
            ["GIT_COMMITTER_DATE"] = commitTime.ToString("O")
        };

        var addResult = await RunGitAsync(rootPath, cancellationToken, "add", ".");
        if (!addResult.Success)
        {
            report.Warnings.Add($"Git add failed: {addResult.Error}");
            return;
        }

        var commitResult = await RunGitAsync(rootPath, cancellationToken, env, "commit", "-m", "Plant simulated axios compromise");
        if (!commitResult.Success)
        {
            report.Warnings.Add($"Git commit failed: {commitResult.Error}");
            return;
        }

        report.CommandsExecuted.Add("git add .");
        report.CommandsExecuted.Add("git commit -m \"Plant simulated axios compromise\"");
        report.GitHistorySeeded = true;
    }

    private static Task<GitCommandResult> RunGitAsync(string rootPath, CancellationToken cancellationToken, params string[] args)
    {
        return RunGitAsync(rootPath, cancellationToken, environmentVariables: null, args);
    }

    private static async Task<GitCommandResult> RunGitAsync(string rootPath, CancellationToken cancellationToken, IDictionary<string, string>? environmentVariables, params string[] args)
    {
        try
        {
            var startInfo = new ProcessStartInfo
            {
                FileName = "git",
                WorkingDirectory = rootPath,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            foreach (var arg in args)
            {
                startInfo.ArgumentList.Add(arg);
            }

            if (environmentVariables is not null)
            {
                foreach (var entry in environmentVariables)
                {
                    startInfo.Environment[entry.Key] = entry.Value;
                }
            }

            using var process = Process.Start(startInfo);
            if (process is null)
            {
                return new GitCommandResult(false, string.Empty, "Failed to start git.");
            }

            var outputTask = process.StandardOutput.ReadToEndAsync(cancellationToken);
            var errorTask = process.StandardError.ReadToEndAsync(cancellationToken);
            await process.WaitForExitAsync(cancellationToken);

            return process.ExitCode == 0
                ? new GitCommandResult(true, await outputTask, await errorTask)
                : new GitCommandResult(false, await outputTask, await errorTask);
        }
        catch (Exception ex)
        {
            return new GitCommandResult(false, string.Empty, ex.Message);
        }
    }

    private sealed record GitCommandResult(bool Success, string Output, string Error);
}
