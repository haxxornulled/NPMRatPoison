# Catalog Governance

Threat catalogs support metadata and digest validation.

## Metadata

Catalogs can include:

```json
{
  "metadata": {
    "catalogId": "npmratpoison-default",
    "version": "2026.04.02.1",
    "publishedUtc": "2026-04-02T00:00:00Z"
  }
}
```

## Digest Validation

Validate a catalog before running:

```powershell
dotnet run --project .\NpmRatPoison\NpmRatPoison.csproj -- --path . --catalog .\threat-catalog.json --catalog-sha256 <sha256>
```

If the digest does not match, the tool exits with code `2`.

## Operational Guidance

- Version catalogs intentionally.
- Publish digests alongside advisory bundles.
- Prefer distributing catalogs through a trusted internal channel.
- Keep repository cleanup and host cleanup as separate decisions.
