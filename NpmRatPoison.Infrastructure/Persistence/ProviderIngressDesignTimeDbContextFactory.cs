using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

public sealed class ProviderIngressDesignTimeDbContextFactory : IDesignTimeDbContextFactory<ProviderIngressDbContext>
{
    public ProviderIngressDbContext CreateDbContext(string[] args)
    {
        var databaseProvider = Environment.GetEnvironmentVariable("ProviderIngress__DatabaseProvider")
                               ?? Environment.GetEnvironmentVariable("NPMRATPOISON_PROVIDERINGRESS_DATABASEPROVIDER")
                               ?? "postgres";
        var connectionString = Environment.GetEnvironmentVariable("ConnectionStrings__ProviderIngress")
                               ?? Environment.GetEnvironmentVariable("ProviderIngress__ConnectionString")
                               ?? Environment.GetEnvironmentVariable("NPMRATPOISON_PROVIDERINGRESS_CONNECTIONSTRING")
                               ?? GetDefaultConnectionString(databaseProvider);

        var optionsBuilder = new DbContextOptionsBuilder<ProviderIngressDbContext>();
        if (string.Equals(databaseProvider, "sqlite", StringComparison.OrdinalIgnoreCase))
        {
            optionsBuilder.UseSqlite(connectionString);
        }
        else
        {
            optionsBuilder.UseNpgsql(connectionString, npgsqlOptions =>
            {
                npgsqlOptions.EnableRetryOnFailure();
            });
        }

        return new ProviderIngressDbContext(optionsBuilder.Options);
    }

    private static string GetDefaultConnectionString(string databaseProvider)
    {
        if (string.Equals(databaseProvider, "sqlite", StringComparison.OrdinalIgnoreCase))
        {
            var root = AppContext.BaseDirectory;
            return $"Data Source={Path.Combine(root, "provider-ingress-design.db")};Pooling=False";
        }

        return "Host=localhost;Port=5432;Database=npmratpoison;Username=npmratpoison;Password=change-me-before-production";
    }
}
