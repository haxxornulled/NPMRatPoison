using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

public enum CatalogIntegrityStatus
{
    NotValidated = 0,
    Verified = 1,
    ValidationFailed = 2
}

public sealed record ThreatCatalogInfo(
    string CatalogId,
    string Version,
    DateTimeOffset? PublishedUtc,
    string? SourcePath,
    string Sha256,
    CatalogIntegrityStatus IntegrityStatus,
    string? ValidationMessage);

public sealed class ThreatCatalog
{
    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true
    };

    private readonly Dictionary<string, ThreatPackageRule> _packagesByName;
    private readonly HashSet<string> _directoryNames;
    private readonly HashSet<string> _workspaceArtifactNames;

    private ThreatCatalog(ThreatCatalogDocument document)
    {
        Packages = (document.Packages ?? [])
            .Where(rule => !string.IsNullOrWhiteSpace(rule.PackageName))
            .Select(rule => rule.Normalize())
            .ToArray();

        _packagesByName = Packages.ToDictionary(rule => rule.PackageName, StringComparer.OrdinalIgnoreCase);
        _directoryNames = new HashSet<string>(Packages.SelectMany(rule => rule.DirectoryNames), StringComparer.OrdinalIgnoreCase);
        _workspaceArtifactNames = new HashSet<string>(document.WorkspaceArtifactNames ?? [], StringComparer.OrdinalIgnoreCase);

        TextIndicators = Distinct(document.CommonIndicators, Packages.SelectMany(rule => rule.TextIndicators));
        GitIndicators = Distinct(document.GitIndicators, TextIndicators);
        ShellProfileIndicators = Distinct(document.ShellProfileIndicators, document.CommonIndicators);
        HostArtifacts = (document.HostArtifacts ?? []).Where(artifact => !string.IsNullOrWhiteSpace(artifact.Path)).ToArray();
        ExposureWindows = (document.GitExposureWindows ?? []).Where(window => window.IsValid()).ToArray();
        ReportAffectedItems = (document.ReportAffectedItems ?? []).Where(item => !string.IsNullOrWhiteSpace(item)).ToArray();
        Info = CreateCatalogInfo(document.Metadata);
    }

    public IReadOnlyList<ThreatPackageRule> Packages { get; }

    public IReadOnlyList<string> TextIndicators { get; }

    public IReadOnlyList<string> GitIndicators { get; }

    public IReadOnlyList<string> ShellProfileIndicators { get; }

    public IReadOnlyList<HostArtifactRule> HostArtifacts { get; }

    public IReadOnlyList<ThreatExposureWindow> ExposureWindows { get; }

    public IReadOnlyList<string> ReportAffectedItems { get; }

    public IEnumerable<string> DirectoryNames => _directoryNames;

    public IEnumerable<string> WorkspaceArtifactNames => _workspaceArtifactNames;

    public ThreatCatalogInfo Info { get; private set; }

    public static ThreatCatalog Load(string? catalogPath)
    {
        if (!string.IsNullOrWhiteSpace(catalogPath))
        {
            return LoadFromFile(Path.GetFullPath(catalogPath));
        }

        var defaultCatalogPath = Path.Combine(AppContext.BaseDirectory, "threat-catalog.json");
        if (File.Exists(defaultCatalogPath))
        {
            return LoadFromFile(defaultCatalogPath);
        }

        return CreateDefault();
    }

    public static ThreatCatalog LoadFromFile(string path)
    {
        var json = File.ReadAllText(path);
        var document = JsonSerializer.Deserialize<ThreatCatalogDocument>(json, SerializerOptions)
            ?? throw new InvalidOperationException($"Threat catalog '{path}' is empty or invalid.");

        var catalog = new ThreatCatalog(document);
        var digest = ComputeSha256Hex(json);
        catalog.Info = catalog.Info with
        {
            SourcePath = Path.GetFullPath(path),
            Sha256 = digest
        };
        return catalog;
    }

    public static ThreatCatalog CreateDefault()
    {
        var document = new ThreatCatalogDocument
        {
            Metadata = new ThreatCatalogMetadataDocument
            {
                CatalogId = "npmratpoison-default",
                Version = "2026.04.02.1",
                PublishedUtc = DateTimeOffset.Parse("2026-04-02T00:00:00Z")
            },
            Packages =
            [
                new ThreatPackageRule
                {
                    PackageName = "axios",
                    ReplacementVersions = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                    {
                        ["1.14.1"] = "1.14.0",
                        ["0.30.4"] = "0.30.3"
                    },
                    LockPackagePaths =
                    [
                        "node_modules/axios"
                    ],
                    TextIndicators =
                    [
                        "axios@1.14.1",
                        "axios@0.30.4",
                        "\"axios\": \"1.14.1\"",
                        "\"axios\": \"0.30.4\"",
                        "version \"1.14.1\"",
                        "version \"0.30.4\""
                    ]
                },
                new ThreatPackageRule
                {
                    PackageName = "plain-crypto-js",
                    RemoveWhenPresent = true,
                    LockPackagePaths =
                    [
                        "node_modules/plain-crypto-js"
                    ],
                    DirectoryNames =
                    [
                        "plain-crypto-js"
                    ],
                    TextIndicators =
                    [
                        "plain-crypto-js"
                    ]
                }
            ],
            CommonIndicators =
            [
                "sfrclak.com",
                "142.11.206.73",
                "packages.npm.org/product0",
                "packages.npm.org/product1",
                "packages.npm.org/product2"
            ],
            ShellProfileIndicators =
            [
                "sfrclak.com",
                "142.11.206.73",
                "packages.npm.org/product0",
                "packages.npm.org/product1",
                "packages.npm.org/product2"
            ],
            WorkspaceArtifactNames =
            [
                "wt.exe",
                "6202033.vbs",
                "6202033.ps1",
                "ld.py"
            ],
            HostArtifacts =
            [
                new HostArtifactRule
                {
                    OperatingSystems =
                    [
                        "windows"
                    ],
                    Path = "%PROGRAMDATA%\\wt.exe"
                },
                new HostArtifactRule
                {
                    OperatingSystems =
                    [
                        "windows"
                    ],
                    Path = "%TEMP%\\6202033.vbs"
                },
                new HostArtifactRule
                {
                    OperatingSystems =
                    [
                        "windows"
                    ],
                    Path = "%TEMP%\\6202033.ps1"
                },
                new HostArtifactRule
                {
                    OperatingSystems =
                    [
                        "linux"
                    ],
                    Path = "/tmp/ld.py"
                },
                new HostArtifactRule
                {
                    OperatingSystems =
                    [
                        "macos"
                    ],
                    Path = "/Library/Caches/com.apple.act.mond"
                }
            ],
            GitIndicators =
            [
                "plain-crypto-js",
                "axios@1.14.1",
                "axios@0.30.4",
                "\"axios\": \"1.14.1\"",
                "\"axios\": \"0.30.4\"",
                "sfrclak.com",
                "142.11.206.73",
                "packages.npm.org/product0",
                "packages.npm.org/product1",
                "packages.npm.org/product2"
            ],
            GitExposureWindows =
            [
                new ThreatExposureWindow
                {
                    StartUtc = DateTimeOffset.Parse("2026-03-31T00:21:00Z"),
                    EndUtc = DateTimeOffset.Parse("2026-03-31T03:15:00Z")
                }
            ],
            ReportAffectedItems =
            [
                "axios 1.14.1",
                "axios 0.30.4",
                "plain-crypto-js"
            ]
        };

        var catalog = new ThreatCatalog(document);
        catalog.Info = catalog.Info with
        {
            SourcePath = "builtin",
            Sha256 = ComputeSha256Hex(JsonSerializer.Serialize(document, SerializerOptions))
        };
        return catalog;
    }

    public void ValidateSha256(string expectedSha256)
    {
        if (string.IsNullOrWhiteSpace(expectedSha256))
        {
            return;
        }

        var normalizedExpected = NormalizeSha256(expectedSha256);
        var normalizedActual = NormalizeSha256(Info.Sha256);
        var matched = string.Equals(normalizedExpected, normalizedActual, StringComparison.OrdinalIgnoreCase);

        Info = Info with
        {
            IntegrityStatus = matched ? CatalogIntegrityStatus.Verified : CatalogIntegrityStatus.ValidationFailed,
            ValidationMessage = matched
                ? $"Catalog SHA-256 verified: {normalizedActual}"
                : $"Catalog SHA-256 mismatch. Expected {normalizedExpected}, actual {normalizedActual}."
        };
    }

    public bool ShouldRemovePackage(string packageName)
        => _packagesByName.TryGetValue(packageName, out var rule) && rule.RemoveWhenPresent;

    public bool TryGetReplacementVersion(string packageName, string? version, out string replacementVersion)
    {
        replacementVersion = string.Empty;
        if (string.IsNullOrWhiteSpace(version))
        {
            return false;
        }

        return _packagesByName.TryGetValue(packageName, out var rule)
               && rule.TryGetReplacementVersion(version, out replacementVersion);
    }

    public bool TryRewritePackageSpec(string packageName, string originalValue, out string rewrittenValue)
    {
        rewrittenValue = originalValue;
        if (!_packagesByName.TryGetValue(packageName, out var rule))
        {
            return false;
        }

        if (!rule.TryGetReplacementVersion(originalValue, out var replacementVersion))
        {
            return false;
        }

        var normalized = NormalizeVersion(originalValue);
        rewrittenValue = originalValue.Replace(normalized, replacementVersion, StringComparison.OrdinalIgnoreCase);
        return !string.Equals(originalValue, rewrittenValue, StringComparison.Ordinal);
    }

    public IEnumerable<string> GetHostArtifactPathsForCurrentOs()
    {
        foreach (var artifact in HostArtifacts)
        {
            if (!artifact.AppliesToCurrentOs())
            {
                continue;
            }

            yield return Environment.ExpandEnvironmentVariables(artifact.Path);
        }
    }

    public bool IsGitIndicatorMatch(string content)
        => GitIndicators.Any(indicator => content.Contains(indicator, StringComparison.OrdinalIgnoreCase));

    public bool IsTextIndicatorMatch(string content)
        => TextIndicators.Any(indicator => content.Contains(indicator, StringComparison.OrdinalIgnoreCase));

    public bool IsShellProfileIndicatorMatch(string content)
        => ShellProfileIndicators.Any(indicator => content.Contains(indicator, StringComparison.OrdinalIgnoreCase));

    public bool IsWithinExposureWindow(DateTimeOffset timestampUtc)
        => ExposureWindows.Any(window => window.Contains(timestampUtc));

    public string GetAffectedItemsSummary()
    {
        if (ReportAffectedItems.Count == 0)
        {
            return "Affected indicators loaded from threat catalog.";
        }

        return $"Affected indicators: {string.Join(", ", ReportAffectedItems)}.";
    }

    public static string NormalizeVersion(string version)
    {
        var trimmed = version.Trim();
        while (trimmed.Length > 0 && !char.IsDigit(trimmed[0]))
        {
            trimmed = trimmed[1..];
        }

        return trimmed;
    }

    private static string[] Distinct(params IEnumerable<string>?[] sets)
    {
        return sets
            .Where(set => set is not null)
            .SelectMany(set => set!)
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private static ThreatCatalogInfo CreateCatalogInfo(ThreatCatalogMetadataDocument? metadata)
    {
        return new ThreatCatalogInfo(
            string.IsNullOrWhiteSpace(metadata?.CatalogId) ? "npmratpoison-catalog" : metadata!.CatalogId.Trim(),
            string.IsNullOrWhiteSpace(metadata?.Version) ? "unspecified" : metadata!.Version.Trim(),
            metadata?.PublishedUtc,
            null,
            string.Empty,
            CatalogIntegrityStatus.NotValidated,
            null);
    }

    private static string ComputeSha256Hex(string content)
    {
        var bytes = Encoding.UTF8.GetBytes(content);
        var hash = SHA256.HashData(bytes);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private static string NormalizeSha256(string value)
    {
        return value
            .Replace("-", string.Empty, StringComparison.Ordinal)
            .Trim()
            .ToLowerInvariant();
    }
}

public sealed class ThreatPackageRule
{
    public string PackageName { get; set; } = string.Empty;

    public bool RemoveWhenPresent { get; set; }

    public Dictionary<string, string> ReplacementVersions { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    public List<string> LockPackagePaths { get; set; } = [];

    public List<string> DirectoryNames { get; set; } = [];

    public List<string> TextIndicators { get; set; } = [];

    public ThreatPackageRule Normalize()
    {
        ReplacementVersions = ReplacementVersions
            .Where(entry => !string.IsNullOrWhiteSpace(entry.Key) && !string.IsNullOrWhiteSpace(entry.Value))
            .ToDictionary(entry => ThreatCatalog.NormalizeVersion(entry.Key), entry => entry.Value, StringComparer.OrdinalIgnoreCase);

        LockPackagePaths = LockPackagePaths.Where(path => !string.IsNullOrWhiteSpace(path)).ToList();
        DirectoryNames = DirectoryNames.Where(path => !string.IsNullOrWhiteSpace(path)).ToList();
        TextIndicators = TextIndicators.Where(indicator => !string.IsNullOrWhiteSpace(indicator)).ToList();
        PackageName = PackageName.Trim();
        return this;
    }

    public bool TryGetReplacementVersion(string version, out string replacementVersion)
        => ReplacementVersions.TryGetValue(ThreatCatalog.NormalizeVersion(version), out replacementVersion!);
}

public sealed class HostArtifactRule
{
    public List<string> OperatingSystems { get; set; } = [];

    public string Path { get; set; } = string.Empty;

    public bool AppliesToCurrentOs()
    {
        if (OperatingSystems.Count == 0)
        {
            return true;
        }

        return OperatingSystems.Any(operatingSystem => operatingSystem.Equals("windows", StringComparison.OrdinalIgnoreCase) && OperatingSystem.IsWindows())
               || OperatingSystems.Any(operatingSystem => operatingSystem.Equals("linux", StringComparison.OrdinalIgnoreCase) && OperatingSystem.IsLinux())
               || OperatingSystems.Any(operatingSystem => operatingSystem.Equals("macos", StringComparison.OrdinalIgnoreCase) && OperatingSystem.IsMacOS());
    }
}

public sealed class ThreatExposureWindow
{
    public DateTimeOffset StartUtc { get; set; }

    public DateTimeOffset EndUtc { get; set; }

    public bool Contains(DateTimeOffset timestampUtc)
        => timestampUtc >= StartUtc && timestampUtc <= EndUtc;

    public bool IsValid()
        => StartUtc != default && EndUtc != default && EndUtc >= StartUtc;
}

internal sealed class ThreatCatalogDocument
{
    public ThreatCatalogMetadataDocument? Metadata { get; set; }

    public List<ThreatPackageRule>? Packages { get; set; }

    public List<string>? CommonIndicators { get; set; }

    public List<string>? ShellProfileIndicators { get; set; }

    public List<string>? WorkspaceArtifactNames { get; set; }

    public List<HostArtifactRule>? HostArtifacts { get; set; }

    public List<string>? GitIndicators { get; set; }

    public List<ThreatExposureWindow>? GitExposureWindows { get; set; }

    public List<string>? ReportAffectedItems { get; set; }
}

internal sealed class ThreatCatalogMetadataDocument
{
    public string? CatalogId { get; set; }

    public string? Version { get; set; }

    public DateTimeOffset? PublishedUtc { get; set; }
}
