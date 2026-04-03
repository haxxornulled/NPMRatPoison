using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace NpmRatPoison.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class InitialProviderIngressSchema : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "provider_api_keys",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    ProviderId = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    KeyId = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    Name = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    Algorithm = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                    PublicKeyPem = table.Column<string>(type: "text", nullable: false),
                    CreatedUtc = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    ExpiresUtc = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    RevokedUtc = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_provider_api_keys", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "provider_ingress_documents",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    SubmissionId = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    ProviderId = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    SignatureAlgorithm = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: false),
                    ApiKeyId = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    DocumentType = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    ProviderDocumentId = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    EnvelopeVersion = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    ContentType = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    PayloadSha256 = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    TagsJson = table.Column<string>(type: "text", nullable: false),
                    PayloadJson = table.Column<string>(type: "text", nullable: false),
                    EnvelopeJson = table.Column<string>(type: "text", nullable: false),
                    Title = table.Column<string>(type: "character varying(300)", maxLength: 300, nullable: true),
                    Summary = table.Column<string>(type: "character varying(4000)", maxLength: 4000, nullable: true),
                    Severity = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: true),
                    RemoteIp = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: true),
                    UserAgent = table.Column<string>(type: "character varying(1024)", maxLength: 1024, nullable: true),
                    ReceivedUtc = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    TimestampUtc = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    PublishedUtc = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_provider_ingress_documents", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_provider_api_keys_KeyId",
                table: "provider_api_keys",
                column: "KeyId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_provider_api_keys_ProviderId_KeyId",
                table: "provider_api_keys",
                columns: new[] { "ProviderId", "KeyId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_provider_ingress_documents_PayloadSha256",
                table: "provider_ingress_documents",
                column: "PayloadSha256");

            migrationBuilder.CreateIndex(
                name: "IX_provider_ingress_documents_ProviderId_DocumentType_Provider~",
                table: "provider_ingress_documents",
                columns: new[] { "ProviderId", "DocumentType", "ProviderDocumentId", "PayloadSha256" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_provider_ingress_documents_ProviderId_DocumentType_Publishe~",
                table: "provider_ingress_documents",
                columns: new[] { "ProviderId", "DocumentType", "PublishedUtc" });

            migrationBuilder.CreateIndex(
                name: "IX_provider_ingress_documents_SubmissionId",
                table: "provider_ingress_documents",
                column: "SubmissionId",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "provider_api_keys");

            migrationBuilder.DropTable(
                name: "provider_ingress_documents");
        }
    }
}
