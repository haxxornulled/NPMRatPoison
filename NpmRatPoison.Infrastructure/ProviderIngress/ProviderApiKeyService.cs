using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using VapeCache.Abstractions.Caching;

public sealed class ProviderApiKeyService : IProviderApiKeyService
{
    private static readonly byte[] CanonicalSeparator = [10];
    private static readonly TimeSpan ApiKeyCacheTtl = TimeSpan.FromMinutes(5);
    private readonly IDbContextFactory<ProviderIngressDbContext> _dbContextFactory;
    private readonly IVapeCache _cache;
    private readonly ILogger<ProviderApiKeyService> _logger;

    public ProviderApiKeyService(
        IDbContextFactory<ProviderIngressDbContext> dbContextFactory,
        IVapeCache cache,
        ILogger<ProviderApiKeyService> logger)
    {
        _dbContextFactory = dbContextFactory;
        _cache = cache;
        _logger = logger;
    }

    public async Task<ProviderApiKeyGenerationResult> GenerateAsync(ProviderApiKeyGenerationRequest request, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(request.ProviderId))
        {
            throw new InvalidOperationException("ProviderId is required.");
        }

        var createdUtc = DateTimeOffset.UtcNow;
        var keyId = BuildPublicKeyId(createdUtc);
        var name = string.IsNullOrWhiteSpace(request.Name) ? $"Provider credential {createdUtc:yyyy-MM-dd HH:mm:ss}Z" : request.Name.Trim();

        using var rsa = RSA.Create(3072);
        var publicKeyPem = rsa.ExportRSAPublicKeyPem();
        var privateKeyPem = rsa.ExportPkcs8PrivateKeyPem();

        await using var dbContext = await _dbContextFactory.CreateDbContextAsync(cancellationToken);
        dbContext.ProviderApiKeys.Add(new ProviderApiKeyEntity
        {
            Id = Guid.NewGuid(),
            ProviderId = request.ProviderId,
            KeyId = keyId,
            Name = name,
            Algorithm = "RSA-PSS-SHA256",
            PublicKeyPem = publicKeyPem,
            CreatedUtc = createdUtc,
            ExpiresUtc = request.ExpiresUtc
        });

        await dbContext.SaveChangesAsync(cancellationToken);

        _logger.LogInformation("Created RSA provider credential {KeyId} for provider {ProviderId}.", keyId, request.ProviderId);

        return new ProviderApiKeyGenerationResult(
            ProviderId: request.ProviderId,
            KeyId: keyId,
            Name: name,
            PublicKeyPem: publicKeyPem,
            PrivateKeyPem: privateKeyPem,
            CreatedUtc: createdUtc,
            ExpiresUtc: request.ExpiresUtc);
    }

    public async Task<ProviderApiKeyValidationResult> ValidateAsync(string rawApiKey, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(rawApiKey))
        {
            return new ProviderApiKeyValidationResult(false, "Missing API key.");
        }

        var cacheKey = CacheKey<ProviderApiKeyValidationCacheEntry>.From($"provider-ingress:rsa-key:{rawApiKey.Trim()}");
        var cached = await _cache.GetOrCreateAsync(
            cacheKey,
            async _ => await LoadValidationEntryAsync(rawApiKey.Trim(), cancellationToken),
            new CacheEntryOptions(ApiKeyCacheTtl),
            cancellationToken);

        if (!cached.IsValid)
        {
            return new ProviderApiKeyValidationResult(false, cached.Message);
        }

        return new ProviderApiKeyValidationResult(
            true,
            "API key validated.",
            cached.ProviderId,
            cached.KeyId,
            cached.Name,
            cached.ExpiresUtc);
    }

    public async Task<ProviderApiKeyValidationResult> ValidateSignatureAsync(
        string apiKeyId,
        string providerId,
        string timestamp,
        byte[] bodyUtf8,
        string signature,
        CancellationToken cancellationToken = default)
    {
        var validation = await ValidateAsync(apiKeyId, cancellationToken);
        if (!validation.IsValid)
        {
            return validation;
        }

        if (!string.Equals(validation.ProviderId, providerId, StringComparison.OrdinalIgnoreCase))
        {
            return new ProviderApiKeyValidationResult(false, "API key provider does not match X-NpmRatPoison-Provider.");
        }

        if (!TryNormalizeSignature(signature, out var signatureBytes))
        {
            return new ProviderApiKeyValidationResult(false, "Invalid RSA signature format.");
        }

        var cacheKey = CacheKey<ProviderApiKeyValidationCacheEntry>.From($"provider-ingress:rsa-key:{apiKeyId.Trim()}");
        var cached = await _cache.GetOrCreateAsync(
            cacheKey,
            async _ => await LoadValidationEntryAsync(apiKeyId.Trim(), cancellationToken),
            new CacheEntryOptions(ApiKeyCacheTtl),
            cancellationToken);

        if (string.IsNullOrWhiteSpace(cached.PublicKeyPem))
        {
            return new ProviderApiKeyValidationResult(false, "Public key is not available for the API key.");
        }

        using var rsa = RSA.Create();
        rsa.ImportFromPem(cached.PublicKeyPem);
        var canonical = BuildCanonicalBytes(providerId, timestamp, bodyUtf8);
        var signatureValid = rsa.VerifyData(canonical, signatureBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        if (!signatureValid)
        {
            return new ProviderApiKeyValidationResult(false, "RSA signature validation failed.");
        }

        return validation;
    }

    private async ValueTask<ProviderApiKeyValidationCacheEntry> LoadValidationEntryAsync(string apiKeyId, CancellationToken cancellationToken)
    {
        await using var dbContext = await _dbContextFactory.CreateDbContextAsync(cancellationToken);
        var nowUtc = DateTimeOffset.UtcNow;
        var entity = await dbContext.ProviderApiKeys
            .AsNoTracking()
            .Where(item => item.KeyId == apiKeyId)
            .SingleOrDefaultAsync(cancellationToken);

        if (entity is null)
        {
            return ProviderApiKeyValidationCacheEntry.Invalid("API key is invalid.");
        }

        if (entity.RevokedUtc.HasValue)
        {
            return ProviderApiKeyValidationCacheEntry.Invalid("API key has been revoked.");
        }

        if (entity.ExpiresUtc.HasValue && entity.ExpiresUtc.Value <= nowUtc)
        {
            return ProviderApiKeyValidationCacheEntry.Invalid("API key has expired.");
        }

        return ProviderApiKeyValidationCacheEntry.Valid(entity.ProviderId, entity.KeyId, entity.Name, entity.PublicKeyPem, entity.ExpiresUtc);
    }

    private static string BuildPublicKeyId(DateTimeOffset createdUtc)
    {
        Span<byte> suffixBytes = stackalloc byte[4];
        RandomNumberGenerator.Fill(suffixBytes);
        return $"pak_{createdUtc:yyyyMMddHHmmss}_{Convert.ToHexString(suffixBytes).ToLowerInvariant()}";
    }

    private static bool TryNormalizeSignature(string signature, out byte[] signatureBytes)
    {
        var trimmed = signature.Trim();
        if (trimmed.StartsWith("rsa-pss-sha256=", StringComparison.OrdinalIgnoreCase))
        {
            trimmed = trimmed["rsa-pss-sha256=".Length..].Trim();
        }

        try
        {
            signatureBytes = Convert.FromBase64String(trimmed);
            return signatureBytes.Length > 0;
        }
        catch (FormatException)
        {
            signatureBytes = [];
            return false;
        }
    }

    private static byte[] BuildCanonicalBytes(string providerId, string timestamp, byte[] bodyUtf8)
    {
        var providerBytes = Encoding.UTF8.GetBytes(providerId);
        var timestampBytes = Encoding.UTF8.GetBytes(timestamp);
        var buffer = new byte[providerBytes.Length + timestampBytes.Length + bodyUtf8.Length + 2];
        var offset = 0;
        providerBytes.CopyTo(buffer, offset);
        offset += providerBytes.Length;
        buffer[offset++] = CanonicalSeparator[0];
        timestampBytes.CopyTo(buffer, offset);
        offset += timestampBytes.Length;
        buffer[offset++] = CanonicalSeparator[0];
        bodyUtf8.CopyTo(buffer, offset);
        return buffer;
    }

    private sealed record ProviderApiKeyValidationCacheEntry(
        bool IsValid,
        string Message,
        string? ProviderId,
        string? KeyId,
        string? Name,
        string? PublicKeyPem,
        DateTimeOffset? ExpiresUtc)
    {
        public static ProviderApiKeyValidationCacheEntry Invalid(string message)
        {
            return new ProviderApiKeyValidationCacheEntry(false, message, null, null, null, null, null);
        }

        public static ProviderApiKeyValidationCacheEntry Valid(string providerId, string keyId, string name, string publicKeyPem, DateTimeOffset? expiresUtc)
        {
            return new ProviderApiKeyValidationCacheEntry(true, "API key validated.", providerId, keyId, name, publicKeyPem, expiresUtc);
        }
    }
}
