using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

public sealed class ProviderIngressDatabaseInitializerHostedService : IHostedService
{
    private readonly IDbContextFactory<ProviderIngressDbContext> _dbContextFactory;
    private readonly IOptions<ProviderIngressOptions> _options;
    private readonly ILogger<ProviderIngressDatabaseInitializerHostedService> _logger;

    public ProviderIngressDatabaseInitializerHostedService(
        IDbContextFactory<ProviderIngressDbContext> dbContextFactory,
        IOptions<ProviderIngressOptions> options,
        ILogger<ProviderIngressDatabaseInitializerHostedService> logger)
    {
        _dbContextFactory = dbContextFactory;
        _options = options;
        _logger = logger;
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        if (!_options.Value.Enabled || !_options.Value.AutoInitializeDatabase)
        {
            return;
        }

        try
        {
            await using var dbContext = await _dbContextFactory.CreateDbContextAsync(cancellationToken);
            if (string.Equals(_options.Value.DatabaseProvider, "sqlite", StringComparison.OrdinalIgnoreCase))
            {
                await dbContext.Database.EnsureCreatedAsync(cancellationToken);
                _logger.LogInformation("Provider ingress SQLite database ensured for local/dev usage.");
                return;
            }

            await dbContext.Database.MigrateAsync(cancellationToken);
            _logger.LogInformation("Provider ingress database migrations applied for provider '{DatabaseProvider}'.", _options.Value.DatabaseProvider);
        }
        catch (Exception ex)
        {
            _logger.LogError(
                ex,
                "Provider ingress database initialization failed. The host will continue running, but provider-ingress persistence is unavailable until the database is reachable.");
        }
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        return Task.CompletedTask;
    }
}
