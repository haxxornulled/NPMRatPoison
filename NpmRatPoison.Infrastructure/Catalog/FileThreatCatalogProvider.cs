using VapeCache.Abstractions.Caching;

public sealed class FileThreatCatalogProvider : IThreatCatalogProvider
{
    private static readonly TimeSpan CatalogCacheTtl = TimeSpan.FromMinutes(10);
    private readonly IVapeCache _cache;

    public FileThreatCatalogProvider(IVapeCache cache)
    {
        _cache = cache;
    }

    public ThreatCatalog Load(string? catalogPath)
    {
        var resolvedPath = ResolveCatalogPath(catalogPath);
        var key = CacheKey<ThreatCatalog>.From(BuildCacheKey(resolvedPath));

        return _cache.GetOrCreateAsync(
                key,
                _ => new ValueTask<ThreatCatalog>(LoadCatalog(resolvedPath)),
                new CacheEntryOptions(CatalogCacheTtl))
            .GetAwaiter()
            .GetResult();
    }

    private static ThreatCatalog LoadCatalog(string? resolvedPath)
    {
        if (string.IsNullOrWhiteSpace(resolvedPath))
        {
            return ThreatCatalog.CreateDefault();
        }

        return ThreatCatalog.LoadFromFile(resolvedPath);
    }

    private static string? ResolveCatalogPath(string? catalogPath)
    {
        if (!string.IsNullOrWhiteSpace(catalogPath))
        {
            return Path.GetFullPath(catalogPath);
        }

        var defaultCatalogPath = Path.Combine(AppContext.BaseDirectory, "threat-catalog.json");
        return File.Exists(defaultCatalogPath) ? defaultCatalogPath : null;
    }

    private static string BuildCacheKey(string? resolvedPath)
    {
        if (string.IsNullOrWhiteSpace(resolvedPath))
        {
            return "threat-catalog:default";
        }

        var fileInfo = new FileInfo(resolvedPath);
        var stamp = fileInfo.Exists ? fileInfo.LastWriteTimeUtc.Ticks.ToString() : "missing";
        return $"threat-catalog:{resolvedPath.ToLowerInvariant()}:{stamp}";
    }
}
