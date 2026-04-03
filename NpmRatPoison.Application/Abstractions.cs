using System.Text.Json;

public interface IThreatCatalogProvider
{
    ThreatCatalog Load(string? catalogPath);
}

public interface IThreatCleanupService
{
    Task<CleanupReport> ExecuteAsync(string rootPath, bool dryRun, ThreatCatalog catalog, bool includeHostLevelChecks = true);
}

public interface IAllDriveScanService
{
    Task<AllDriveScanReport> ExecuteAsync(bool dryRun, bool gitHubOnly, ThreatCatalog catalog, CancellationToken cancellationToken = default);
}

public interface IAutoTriageService
{
    Task<AutoTriageReport> ExecuteAsync(string rootPath, bool pathProvided, bool gitHubOnly, ThreatCatalog catalog, CancellationToken cancellationToken = default);
}

public interface IIncidentSimulationService
{
    Task<IncidentSimulationReport> PlantAsync(string rootPath, ThreatCatalog catalog, CancellationToken cancellationToken = default);
}

public interface IRemoteGitHubScanService
{
    Task<RemoteGitHubScanReport> ExecuteAsync(RemoteGitHubScanRequest request, ThreatCatalog catalog, CancellationToken cancellationToken = default);
}

public interface IGitHubRepositoryGateway
{
    Task<IReadOnlyList<string>> ResolveRepositoryNamesAsync(RemoteGitHubScanRequest request, CancellationToken cancellationToken = default);
    Task<GitHubRepositoryDescriptor> GetRepositoryAsync(string repositoryFullName, string? accessToken, CancellationToken cancellationToken = default);
    Task<GitHubRepositoryTree> GetRepositoryTreeAsync(string repositoryFullName, string gitReference, string? accessToken, CancellationToken cancellationToken = default);
    Task<GitHubContentFile?> GetContentFileAsync(string repositoryFullName, string path, string gitReference, string? accessToken, CancellationToken cancellationToken = default);
    Task<IReadOnlyList<GitHubCommitSummary>> GetRecentDependencyCommitsAsync(string repositoryFullName, string? accessToken, CancellationToken cancellationToken = default);
    Task<IReadOnlyList<string>> GetCommitDiffLinesAsync(string repositoryFullName, string commitSha, string? accessToken, CancellationToken cancellationToken = default);
}

public interface IGitHubCredentialPrompt
{
    string? PromptForAccessToken();
}

public interface IGitHubAccessTokenResolver
{
    string? ResolveAccessToken(string? configuredAccessToken);
}

public interface IProviderIngressService
{
    Task<ProviderIngressResult> AcceptAsync(ProviderIngressSubmission submission, CancellationToken cancellationToken = default);
}

public interface IProviderApiKeyService
{
    Task<ProviderApiKeyGenerationResult> GenerateAsync(ProviderApiKeyGenerationRequest request, CancellationToken cancellationToken = default);
    Task<ProviderApiKeyValidationResult> ValidateAsync(string rawApiKey, CancellationToken cancellationToken = default);
    Task<ProviderApiKeyValidationResult> ValidateSignatureAsync(string apiKeyId, string providerId, string timestamp, byte[] bodyUtf8, string signature, CancellationToken cancellationToken = default);
}

public interface IReportWriter
{
    Task WriteAsync<T>(string? reportDirectory, string prefix, T report, CancellationToken cancellationToken = default);
}

public interface IScanProgressPublisher
{
    void Publish(string stage, string? drive, string? path, string message);
}

public sealed record RemoteGitHubScanRequest(
    string? Organization,
    string? User,
    IReadOnlyList<string> RepositoryNames,
    string? AccessToken);

public sealed record GitHubRepositoryDescriptor(
    string FullName,
    string DefaultBranch,
    bool IsPrivate,
    bool IsArchived,
    string HtmlUrl);

public sealed record GitHubRepositoryTree(
    IReadOnlyList<string> FilePaths,
    bool IsTruncated);

public sealed record GitHubContentFile(
    string Path,
    string Content);

public sealed record GitHubCommitSummary(
    string Sha,
    DateTimeOffset TimestampUtc,
    string Message);

public sealed record ProviderIngressSubmission(
    string ProviderId,
    string ApiKeyId,
    string Timestamp,
    string Signature,
    byte[] BodyUtf8,
    string? ContentType,
    string? RemoteIp,
    string? UserAgent);

public sealed record ProviderIngressResult(
    bool Accepted,
    int StatusCode,
    string Message,
    string? SubmissionId,
    string? StoredPath,
    bool IsDuplicate = false,
    string? ProviderDocumentId = null,
    string? DocumentType = null,
    string? PayloadSha256 = null);

public sealed record ProviderApiKeyGenerationRequest(
    string ProviderId,
    string? Name,
    DateTimeOffset? ExpiresUtc);

public sealed record ProviderApiKeyGenerationResult(
    string ProviderId,
    string KeyId,
    string Name,
    string PublicKeyPem,
    string PrivateKeyPem,
    DateTimeOffset CreatedUtc,
    DateTimeOffset? ExpiresUtc);

public sealed record ProviderApiKeyValidationResult(
    bool IsValid,
    string Message,
    string? ProviderId = null,
    string? KeyId = null,
    string? Name = null,
    DateTimeOffset? ExpiresUtc = null);

public sealed record ProviderIngressDocument(
    string SchemaVersion,
    string DocumentType,
    string ProviderDocumentId,
    DateTimeOffset PublishedUtc,
    string? Title,
    string? Summary,
    string? Severity,
    IReadOnlyList<string> Tags,
    JsonElement Payload);

public sealed class ProviderIngressOptions
{
    public bool Enabled { get; set; }

    public string? StorageRoot { get; set; }

    public string DatabaseProvider { get; set; } = "postgres";

    public bool AutoInitializeDatabase { get; set; } = true;

    public int MaxPayloadBytes { get; set; } = 256 * 1024;

    public int AllowedClockSkewMinutes { get; set; } = 10;

    public int RequestsPerMinute { get; set; } = 30;

    public int ReplayCacheMinutes { get; set; } = 30;

    public Dictionary<string, ProviderIngressProviderOptions> Providers { get; set; } = new(StringComparer.OrdinalIgnoreCase);
}

public sealed class ProviderIngressProviderOptions
{
    public bool Enabled { get; set; } = true;

    public string? DisplayName { get; set; }

    public string? Contact { get; set; }

    public List<string> AllowedDocumentTypes { get; set; } = [];
}
