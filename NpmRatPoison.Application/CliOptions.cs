public sealed record CliOptions(
    string RootPath,
    bool DryRun,
    bool AllDrives,
    bool GitHubOnly,
    bool Auto,
    bool PathProvided,
    bool ShowHelp,
    bool ShowVersion,
    bool UiMode,
    string? UiUrls,
    bool SafeDirectoryAssist,
    bool SafeDirectoryOnly,
    bool EnableHostRemediation,
    bool SimulateIncident,
    bool RemoteGitHubScan,
    string? RemoteGitHubOrganization,
    string? RemoteGitHubUser,
    IReadOnlyList<string> RemoteGitHubRepositories,
    string? GitHubAccessToken,
    bool GenerateProviderApiKey,
    bool ApplyProviderIngressMigrations,
    string? ProviderId,
    string? ProviderApiKeyName,
    int? ProviderApiKeyExpiryDays,
    bool ServiceMode,
    int ServiceIntervalMinutes,
    string? ReportDirectory,
    string? CatalogPath,
    string? CatalogSha256)
{
    public static CliOptions Parse(string[] args)
    {
        var root = Directory.GetCurrentDirectory();
        var dryRun = false;
        var allDrives = false;
        var gitHubOnly = true;
        var auto = false;
        var pathProvided = false;
        var showHelp = false;
        var showVersion = false;
        var uiMode = false;
        string? uiUrls = null;
        var safeDirectoryAssist = false;
        var safeDirectoryOnly = false;
        var enableHostRemediation = false;
        var simulateIncident = false;
        var remoteGitHubScan = false;
        string? remoteGitHubOrganization = null;
        string? remoteGitHubUser = null;
        var remoteGitHubRepositories = new List<string>();
        string? gitHubAccessToken = null;
        var generateProviderApiKey = false;
        var applyProviderIngressMigrations = false;
        string? providerId = null;
        string? providerApiKeyName = null;
        int? providerApiKeyExpiryDays = null;
        var serviceMode = false;
        var serviceIntervalMinutes = 15;
        string? reportDirectory = null;
        string? catalogPath = null;
        string? catalogSha256 = null;

        for (var i = 0; i < args.Length; i++)
        {
            var arg = args[i];

            if (string.Equals(arg, "--dry-run", StringComparison.OrdinalIgnoreCase))
            {
                dryRun = true;
                continue;
            }

            if (string.Equals(arg, "--help", StringComparison.OrdinalIgnoreCase)
                || string.Equals(arg, "-h", StringComparison.OrdinalIgnoreCase)
                || string.Equals(arg, "/?", StringComparison.OrdinalIgnoreCase))
            {
                showHelp = true;
                continue;
            }

            if (string.Equals(arg, "--version", StringComparison.OrdinalIgnoreCase))
            {
                showVersion = true;
                continue;
            }

            if (string.Equals(arg, "--ui", StringComparison.OrdinalIgnoreCase))
            {
                uiMode = true;
                continue;
            }

            if (string.Equals(arg, "--urls", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
            {
                uiUrls = args[++i];
                continue;
            }

            if (string.Equals(arg, "--all-drives", StringComparison.OrdinalIgnoreCase))
            {
                allDrives = true;
                dryRun = true;
                continue;
            }

            if (string.Equals(arg, "--auto", StringComparison.OrdinalIgnoreCase))
            {
                auto = true;
                dryRun = true;
                continue;
            }

            if (string.Equals(arg, "--include-non-github", StringComparison.OrdinalIgnoreCase))
            {
                gitHubOnly = false;
                continue;
            }

            if (string.Equals(arg, "--service", StringComparison.OrdinalIgnoreCase))
            {
                serviceMode = true;
                auto = true;
                dryRun = true;
                allDrives = true;
                continue;
            }

            if (string.Equals(arg, "--safe-directory-assist", StringComparison.OrdinalIgnoreCase))
            {
                safeDirectoryAssist = true;
                continue;
            }

            if (string.Equals(arg, "--safe-directory-only", StringComparison.OrdinalIgnoreCase))
            {
                safeDirectoryOnly = true;
                continue;
            }

            if (string.Equals(arg, "--host-remediation", StringComparison.OrdinalIgnoreCase))
            {
                enableHostRemediation = true;
                continue;
            }

            if (string.Equals(arg, "--simulate-incident", StringComparison.OrdinalIgnoreCase))
            {
                simulateIncident = true;
                continue;
            }

            if (string.Equals(arg, "--remote-github-scan", StringComparison.OrdinalIgnoreCase))
            {
                remoteGitHubScan = true;
                dryRun = true;
                continue;
            }

            if (string.Equals(arg, "--remote-github-org", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
            {
                remoteGitHubOrganization = args[++i];
                remoteGitHubScan = true;
                dryRun = true;
                continue;
            }

            if (string.Equals(arg, "--remote-github-user", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
            {
                remoteGitHubUser = args[++i];
                remoteGitHubScan = true;
                dryRun = true;
                continue;
            }

            if (string.Equals(arg, "--remote-github-repo", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
            {
                remoteGitHubRepositories.Add(args[++i]);
                remoteGitHubScan = true;
                dryRun = true;
                continue;
            }

            if (string.Equals(arg, "--github-token", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
            {
                gitHubAccessToken = args[++i];
                continue;
            }

            if (string.Equals(arg, "--generate-provider-api-key", StringComparison.OrdinalIgnoreCase))
            {
                generateProviderApiKey = true;
                continue;
            }

            if (string.Equals(arg, "--apply-provider-ingress-migrations", StringComparison.OrdinalIgnoreCase))
            {
                applyProviderIngressMigrations = true;
                continue;
            }

            if (string.Equals(arg, "--provider-id", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
            {
                providerId = args[++i];
                continue;
            }

            if (string.Equals(arg, "--provider-api-key-name", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
            {
                providerApiKeyName = args[++i];
                continue;
            }

            if (string.Equals(arg, "--provider-api-key-expiry-days", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
            {
                var rawExpiryDays = args[++i];
                if (int.TryParse(rawExpiryDays, out var parsedExpiryDays) && parsedExpiryDays >= 1)
                {
                    providerApiKeyExpiryDays = parsedExpiryDays;
                }

                continue;
            }

            if (string.Equals(arg, "--service-interval-minutes", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
            {
                var raw = args[++i];
                if (int.TryParse(raw, out var parsed) && parsed >= 1)
                {
                    serviceIntervalMinutes = parsed;
                }

                continue;
            }

            if (string.Equals(arg, "--path", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
            {
                root = args[++i];
                pathProvided = true;
                continue;
            }

            if (string.Equals(arg, "--report-dir", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
            {
                reportDirectory = args[++i];
                continue;
            }

            if (string.Equals(arg, "--catalog", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
            {
                catalogPath = args[++i];
                continue;
            }

            if (string.Equals(arg, "--catalog-sha256", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
            {
                catalogSha256 = args[++i];
            }
        }

        if (!string.IsNullOrWhiteSpace(reportDirectory))
        {
            reportDirectory = Path.GetFullPath(reportDirectory);
        }

        if (!string.IsNullOrWhiteSpace(catalogPath))
        {
            catalogPath = Path.GetFullPath(catalogPath);
        }

        gitHubAccessToken ??= Environment.GetEnvironmentVariable("GITHUB_TOKEN")
                            ?? Environment.GetEnvironmentVariable("GH_TOKEN");

        if (showHelp)
        {
            return new CliOptions(
                Path.GetFullPath(root),
                dryRun,
                allDrives,
                gitHubOnly,
                auto,
                pathProvided,
                showHelp,
                showVersion,
                uiMode,
                uiUrls,
                safeDirectoryAssist,
                safeDirectoryOnly,
                enableHostRemediation,
                simulateIncident,
                remoteGitHubScan,
                remoteGitHubOrganization,
                remoteGitHubUser,
                remoteGitHubRepositories,
                gitHubAccessToken,
                generateProviderApiKey,
                applyProviderIngressMigrations,
                providerId,
                providerApiKeyName,
                providerApiKeyExpiryDays,
                serviceMode,
                serviceIntervalMinutes,
                reportDirectory,
                catalogPath,
                catalogSha256);
        }

        if (!showVersion && !uiMode && !serviceMode && !auto && !allDrives && !pathProvided && !simulateIncident && !remoteGitHubScan && !generateProviderApiKey && !applyProviderIngressMigrations)
        {
            allDrives = true;
            dryRun = true;
        }

        return new CliOptions(
            Path.GetFullPath(root),
            dryRun,
            allDrives,
            gitHubOnly,
            auto,
            pathProvided,
            showHelp,
            showVersion,
            uiMode,
            uiUrls,
            safeDirectoryAssist,
            safeDirectoryOnly,
            enableHostRemediation,
            simulateIncident,
            remoteGitHubScan,
            remoteGitHubOrganization,
            remoteGitHubUser,
            remoteGitHubRepositories,
            gitHubAccessToken,
            generateProviderApiKey,
            applyProviderIngressMigrations,
            providerId,
            providerApiKeyName,
            providerApiKeyExpiryDays,
            serviceMode,
            serviceIntervalMinutes,
            reportDirectory,
            catalogPath,
            catalogSha256);
    }
}

public sealed record ServiceScanOptions(int IntervalMinutes, bool GitHubOnly, string? ReportDirectory, string? CatalogPath);
