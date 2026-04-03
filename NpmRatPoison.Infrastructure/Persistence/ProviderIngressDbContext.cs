using Microsoft.EntityFrameworkCore;

public sealed class ProviderIngressDbContext : DbContext
{
    public ProviderIngressDbContext(DbContextOptions<ProviderIngressDbContext> options)
        : base(options)
    {
    }

    public DbSet<ProviderApiKeyEntity> ProviderApiKeys => Set<ProviderApiKeyEntity>();

    public DbSet<ProviderIngressDocumentEntity> ProviderIngressDocuments => Set<ProviderIngressDocumentEntity>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<ProviderApiKeyEntity>(entity =>
        {
            entity.ToTable("provider_api_keys");
            entity.HasKey(item => item.Id);
            entity.Property(item => item.Id).ValueGeneratedNever();
            entity.Property(item => item.ProviderId).HasMaxLength(200).IsRequired();
            entity.Property(item => item.KeyId).HasMaxLength(200).IsRequired();
            entity.Property(item => item.Name).HasMaxLength(200).IsRequired();
            entity.Property(item => item.Algorithm).HasMaxLength(50).IsRequired();
            entity.Property(item => item.PublicKeyPem).HasColumnType("text").IsRequired();
            entity.Property(item => item.CreatedUtc).IsRequired();
            entity.Property(item => item.ExpiresUtc);
            entity.Property(item => item.RevokedUtc);
            entity.HasIndex(item => new { item.ProviderId, item.KeyId }).IsUnique();
            entity.HasIndex(item => item.KeyId).IsUnique();
        });

        modelBuilder.Entity<ProviderIngressDocumentEntity>(entity =>
        {
            entity.ToTable("provider_ingress_documents");
            entity.HasKey(item => item.Id);
            entity.Property(item => item.Id).ValueGeneratedNever();
            entity.Property(item => item.SubmissionId).HasMaxLength(64).IsRequired();
            entity.Property(item => item.ProviderId).HasMaxLength(200).IsRequired();
            entity.Property(item => item.SignatureAlgorithm).HasMaxLength(50).IsRequired();
            entity.Property(item => item.ApiKeyId).HasMaxLength(200).IsRequired();
            entity.Property(item => item.DocumentType).HasMaxLength(200).IsRequired();
            entity.Property(item => item.ProviderDocumentId).HasMaxLength(200).IsRequired();
            entity.Property(item => item.EnvelopeVersion).HasMaxLength(64).IsRequired();
            entity.Property(item => item.ContentType).HasMaxLength(200).IsRequired();
            entity.Property(item => item.Title).HasMaxLength(300);
            entity.Property(item => item.Summary).HasMaxLength(4000);
            entity.Property(item => item.Severity).HasMaxLength(50);
            entity.Property(item => item.RemoteIp).HasMaxLength(128);
            entity.Property(item => item.UserAgent).HasMaxLength(1024);
            entity.Property(item => item.PayloadSha256).HasMaxLength(128).IsRequired();
            entity.Property(item => item.TagsJson).HasColumnType("text").IsRequired();
            entity.Property(item => item.PayloadJson).HasColumnType("text").IsRequired();
            entity.Property(item => item.EnvelopeJson).HasColumnType("text").IsRequired();
            entity.Property(item => item.ReceivedUtc).IsRequired();
            entity.Property(item => item.TimestampUtc).IsRequired();
            entity.Property(item => item.PublishedUtc).IsRequired();
            entity.HasIndex(item => item.SubmissionId).IsUnique();
            entity.HasIndex(item => new { item.ProviderId, item.DocumentType, item.ProviderDocumentId, item.PayloadSha256 }).IsUnique();
            entity.HasIndex(item => new { item.ProviderId, item.DocumentType, item.PublishedUtc });
            entity.HasIndex(item => item.PayloadSha256);
        });
    }
}

public sealed class ProviderApiKeyEntity
{
    public Guid Id { get; set; }

    public string ProviderId { get; set; } = string.Empty;

    public string KeyId { get; set; } = string.Empty;

    public string Name { get; set; } = string.Empty;

    public string Algorithm { get; set; } = "RSA-PSS-SHA256";

    public string PublicKeyPem { get; set; } = string.Empty;

    public DateTimeOffset CreatedUtc { get; set; }

    public DateTimeOffset? ExpiresUtc { get; set; }

    public DateTimeOffset? RevokedUtc { get; set; }
}

public sealed class ProviderIngressDocumentEntity
{
    public Guid Id { get; set; }

    public string SubmissionId { get; set; } = string.Empty;

    public string ProviderId { get; set; } = string.Empty;

    public string SignatureAlgorithm { get; set; } = string.Empty;

    public string ApiKeyId { get; set; } = string.Empty;

    public string DocumentType { get; set; } = string.Empty;

    public string ProviderDocumentId { get; set; } = string.Empty;

    public string EnvelopeVersion { get; set; } = string.Empty;

    public string ContentType { get; set; } = string.Empty;

    public string PayloadSha256 { get; set; } = string.Empty;

    public string TagsJson { get; set; } = "[]";

    public string PayloadJson { get; set; } = "{}";

    public string EnvelopeJson { get; set; } = "{}";

    public string? Title { get; set; }

    public string? Summary { get; set; }

    public string? Severity { get; set; }

    public string? RemoteIp { get; set; }

    public string? UserAgent { get; set; }

    public DateTimeOffset ReceivedUtc { get; set; }

    public DateTimeOffset TimestampUtc { get; set; }

    public DateTimeOffset PublishedUtc { get; set; }
}
