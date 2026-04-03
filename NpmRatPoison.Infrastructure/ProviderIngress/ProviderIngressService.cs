using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using VapeCache.Abstractions.Caching;

public sealed class ProviderIngressService : IProviderIngressService
{
    private readonly ProviderIngressOptions _options;
    private readonly IDbContextFactory<ProviderIngressDbContext> _dbContextFactory;
    private readonly IVapeCache _cache;
    private readonly ILogger<ProviderIngressService> _logger;

    public ProviderIngressService(
        IOptions<ProviderIngressOptions> options,
        IDbContextFactory<ProviderIngressDbContext> dbContextFactory,
        IVapeCache cache,
        ILogger<ProviderIngressService> logger)
    {
        _options = options.Value;
        _dbContextFactory = dbContextFactory;
        _cache = cache;
        _logger = logger;
    }

    public async Task<ProviderIngressResult> AcceptAsync(ProviderIngressSubmission submission, CancellationToken cancellationToken = default)
    {
        var body = submission.BodyUtf8 ?? [];

        if (!_options.Enabled)
        {
            return Reject(503, "Provider ingress is disabled.");
        }

        if (string.IsNullOrWhiteSpace(submission.ProviderId))
        {
            return Reject(400, "Missing provider identifier.");
        }

        if (string.IsNullOrWhiteSpace(submission.ApiKeyId))
        {
            return Reject(401, "Missing API key identifier.");
        }

        if (!_options.Providers.TryGetValue(submission.ProviderId, out var providerOptions)
            || providerOptions is null
            || !providerOptions.Enabled)
        {
            _logger.LogWarning("Rejected provider ingress submission for unknown provider {ProviderId}.", submission.ProviderId);
            return Reject(401, "Unknown provider.");
        }

        if (string.IsNullOrWhiteSpace(submission.Timestamp)
            || !DateTimeOffset.TryParse(
                submission.Timestamp,
                CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                out var requestTimestamp))
        {
            return Reject(400, "Missing or invalid timestamp.");
        }

        var allowedSkew = TimeSpan.FromMinutes(Math.Max(1, _options.AllowedClockSkewMinutes));
        var nowUtc = DateTimeOffset.UtcNow;
        if (nowUtc - requestTimestamp > allowedSkew
            || requestTimestamp - nowUtc > allowedSkew)
        {
            _logger.LogWarning(
                "Rejected provider ingress submission for provider {ProviderId} due to timestamp skew. Timestamp: {TimestampUtc:o}",
                submission.ProviderId,
                requestTimestamp);
            return Reject(401, "Submission timestamp is outside the allowed clock skew.");
        }

        if (string.IsNullOrWhiteSpace(submission.Signature))
        {
            return Reject(401, "Missing signature.");
        }

        if (submission.ContentType is not null
            && !submission.ContentType.Contains("application/json", StringComparison.OrdinalIgnoreCase)
            && !submission.ContentType.Contains("+json", StringComparison.OrdinalIgnoreCase))
        {
            return Reject(415, "Only JSON payloads are supported.");
        }

        if (body.Length == 0)
        {
            return Reject(400, "Payload body is required.");
        }

        if (body.Length > Math.Max(1024, _options.MaxPayloadBytes))
        {
            return Reject(413, "Payload exceeds the configured size limit.");
        }

        try
        {
            using var parsedBody = JsonDocument.Parse(body);
            if (!TryParseDocument(parsedBody.RootElement, out var document, out var validationMessage))
            {
                return Reject(400, validationMessage ?? "Payload body is missing required metadata.");
            }

            if (providerOptions.AllowedDocumentTypes.Count > 0
                && !providerOptions.AllowedDocumentTypes.Contains(document.DocumentType, StringComparer.OrdinalIgnoreCase))
            {
                return Reject(403, $"Document type '{document.DocumentType}' is not allowed for provider '{submission.ProviderId}'.");
            }

            var payloadSha256 = Convert.ToHexString(SHA256.HashData(body)).ToLowerInvariant();
            var duplicateKey = CacheKey<string>.From(
                $"provider-ingress:replay:{submission.ProviderId.ToLowerInvariant()}:{document.DocumentType.ToLowerInvariant()}:{document.ProviderDocumentId.ToLowerInvariant()}:{payloadSha256}");
            var replayMarker = Guid.NewGuid().ToString("N");
            var replayCacheMinutes = Math.Max(1, _options.ReplayCacheMinutes);
            var cachedMarker = await _cache.GetOrCreateAsync(
                duplicateKey,
                _ => new ValueTask<string>(replayMarker),
                new CacheEntryOptions(TimeSpan.FromMinutes(replayCacheMinutes)));

            if (!string.Equals(cachedMarker, replayMarker, StringComparison.Ordinal))
            {
                _logger.LogInformation(
                    "Acknowledged duplicate provider ingress submission for provider {ProviderId}, api key {ApiKeyId}, document {ProviderDocumentId}, type {DocumentType}.",
                    submission.ProviderId,
                    submission.ApiKeyId,
                    document.ProviderDocumentId,
                    document.DocumentType);

                return new ProviderIngressResult(
                    Accepted: true,
                    StatusCode: 202,
                    Message: $"Duplicate submission acknowledged for API key '{submission.ApiKeyId}'.",
                    SubmissionId: null,
                    StoredPath: null,
                    IsDuplicate: true,
                    ProviderDocumentId: document.ProviderDocumentId,
                    DocumentType: document.DocumentType,
                    PayloadSha256: payloadSha256);
            }

            var submissionId = Guid.NewGuid().ToString("N");
            var receivedUtc = DateTimeOffset.UtcNow;
            var envelope = new ProviderIngressEnvelope(
                EnvelopeVersion: "provider-ingress-envelope/v2",
                SubmissionId: submissionId,
                ProviderId: submission.ProviderId,
                ReceivedUtc: receivedUtc,
                TimestampUtc: requestTimestamp,
                ContentType: submission.ContentType ?? "application/json",
                RemoteIp: submission.RemoteIp,
                UserAgent: submission.UserAgent,
                SignatureAlgorithm: "RSA-PSS-SHA256",
                ApiKeyId: submission.ApiKeyId,
                PayloadSha256: payloadSha256,
                Document: document);

            var envelopeJson = JsonSerializer.Serialize(envelope, ProviderIngressJsonContext.Default.ProviderIngressEnvelope);
            var tagsJson = JsonSerializer.Serialize(document.Tags, ProviderIngressJsonContext.Default.StringArray);
            var payloadJson = document.Payload.GetRawText();

            await using var dbContext = await _dbContextFactory.CreateDbContextAsync(cancellationToken);
            dbContext.ProviderIngressDocuments.Add(new ProviderIngressDocumentEntity
            {
                Id = Guid.NewGuid(),
                SubmissionId = submissionId,
                ProviderId = submission.ProviderId,
                SignatureAlgorithm = envelope.SignatureAlgorithm,
                ApiKeyId = submission.ApiKeyId,
                DocumentType = document.DocumentType,
                ProviderDocumentId = document.ProviderDocumentId,
                EnvelopeVersion = envelope.EnvelopeVersion,
                ContentType = envelope.ContentType,
                PayloadSha256 = payloadSha256,
                TagsJson = tagsJson,
                PayloadJson = payloadJson,
                EnvelopeJson = envelopeJson,
                Title = document.Title,
                Summary = document.Summary,
                Severity = document.Severity,
                RemoteIp = submission.RemoteIp,
                UserAgent = submission.UserAgent,
                ReceivedUtc = receivedUtc,
                TimestampUtc = requestTimestamp,
                PublishedUtc = document.PublishedUtc
            });

            try
            {
                await dbContext.SaveChangesAsync(cancellationToken);
            }
            catch (DbUpdateException)
            {
                var duplicateExists = await dbContext.ProviderIngressDocuments
                    .AsNoTracking()
                    .AnyAsync(
                        item => item.ProviderId == submission.ProviderId
                                && item.DocumentType == document.DocumentType
                                && item.ProviderDocumentId == document.ProviderDocumentId
                                && item.PayloadSha256 == payloadSha256,
                        cancellationToken);

                if (duplicateExists)
                {
                    return new ProviderIngressResult(
                        Accepted: true,
                        StatusCode: 202,
                        Message: $"Duplicate submission acknowledged for API key '{submission.ApiKeyId}'.",
                        SubmissionId: null,
                        StoredPath: null,
                        IsDuplicate: true,
                        ProviderDocumentId: document.ProviderDocumentId,
                        DocumentType: document.DocumentType,
                        PayloadSha256: payloadSha256);
                }

                throw;
            }

            _logger.LogInformation(
                "Accepted provider ingress submission {SubmissionId} from provider {ProviderId}, api key {ApiKeyId}, document {ProviderDocumentId}, type {DocumentType}, stored in database.",
                submissionId,
                submission.ProviderId,
                submission.ApiKeyId,
                document.ProviderDocumentId,
                document.DocumentType);

            return new ProviderIngressResult(
                Accepted: true,
                StatusCode: 202,
                Message: $"Submission accepted for API key '{submission.ApiKeyId}'.",
                SubmissionId: submissionId,
                StoredPath: $"db://provider_ingress_documents/{submissionId}",
                IsDuplicate: false,
                ProviderDocumentId: document.ProviderDocumentId,
                DocumentType: document.DocumentType,
                PayloadSha256: payloadSha256);
        }
        catch (JsonException)
        {
            return Reject(400, "Payload body must be valid JSON.");
        }
    }

    private static bool TryParseDocument(JsonElement root, out ProviderIngressDocument document, out string? validationMessage)
    {
        document = default!;
        validationMessage = null;

        if (root.ValueKind != JsonValueKind.Object)
        {
            validationMessage = "Payload body must be a JSON object.";
            return false;
        }

        if (!TryGetRequiredString(root, "schemaVersion", out var schemaVersion))
        {
            validationMessage = "Payload body must include schemaVersion.";
            return false;
        }

        if (!string.Equals(schemaVersion, "1.0", StringComparison.Ordinal))
        {
            validationMessage = "Unsupported schemaVersion. Expected 1.0.";
            return false;
        }

        if (!TryGetRequiredString(root, "documentType", out var documentType))
        {
            validationMessage = "Payload body must include documentType.";
            return false;
        }

        if (!TryGetRequiredString(root, "providerDocumentId", out var providerDocumentId))
        {
            validationMessage = "Payload body must include providerDocumentId.";
            return false;
        }

        if (!root.TryGetProperty("publishedUtc", out var publishedUtcElement)
            || publishedUtcElement.ValueKind != JsonValueKind.String
            || !DateTimeOffset.TryParse(
                publishedUtcElement.GetString(),
                CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                out var publishedUtc))
        {
            validationMessage = "Payload body must include a valid publishedUtc timestamp.";
            return false;
        }

        if (!root.TryGetProperty("payload", out var payload))
        {
            validationMessage = "Payload body must include payload.";
            return false;
        }

        var tags = Array.Empty<string>();
        if (root.TryGetProperty("tags", out var tagsElement))
        {
            if (tagsElement.ValueKind != JsonValueKind.Array)
            {
                validationMessage = "tags must be an array of strings when provided.";
                return false;
            }

            var materializedTags = new List<string>();
            foreach (var tag in tagsElement.EnumerateArray())
            {
                if (tag.ValueKind != JsonValueKind.String || string.IsNullOrWhiteSpace(tag.GetString()))
                {
                    validationMessage = "tags must contain only non-empty strings.";
                    return false;
                }

                materializedTags.Add(tag.GetString()!);
            }

            tags = [.. materializedTags];
        }

        document = new ProviderIngressDocument(
            SchemaVersion: schemaVersion,
            DocumentType: documentType,
            ProviderDocumentId: providerDocumentId,
            PublishedUtc: publishedUtc,
            Title: TryGetOptionalString(root, "title"),
            Summary: TryGetOptionalString(root, "summary"),
            Severity: TryGetOptionalString(root, "severity"),
            Tags: tags,
            Payload: payload.Clone());
        return true;
    }

    private static bool TryGetRequiredString(JsonElement root, string propertyName, out string value)
    {
        value = string.Empty;
        if (!root.TryGetProperty(propertyName, out var element)
            || element.ValueKind != JsonValueKind.String
            || string.IsNullOrWhiteSpace(element.GetString()))
        {
            return false;
        }

        value = element.GetString()!;
        return true;
    }

    private static string? TryGetOptionalString(JsonElement root, string propertyName)
    {
        if (!root.TryGetProperty(propertyName, out var element))
        {
            return null;
        }

        return element.ValueKind == JsonValueKind.String ? element.GetString() : null;
    }

    private ProviderIngressResult Reject(int statusCode, string message)
    {
        return new ProviderIngressResult(
            Accepted: false,
            StatusCode: statusCode,
            Message: message,
            SubmissionId: null,
            StoredPath: null);
    }
}

public sealed record ProviderIngressEnvelope(
    string EnvelopeVersion,
    string SubmissionId,
    string ProviderId,
    DateTimeOffset ReceivedUtc,
    DateTimeOffset TimestampUtc,
    string ContentType,
    string? RemoteIp,
    string? UserAgent,
    string SignatureAlgorithm,
    string ApiKeyId,
    string PayloadSha256,
    ProviderIngressDocument Document);

[JsonSerializable(typeof(ProviderIngressEnvelope))]
[JsonSerializable(typeof(ProviderIngressDocument))]
[JsonSerializable(typeof(string[]))]
internal partial class ProviderIngressJsonContext : JsonSerializerContext
{
}
