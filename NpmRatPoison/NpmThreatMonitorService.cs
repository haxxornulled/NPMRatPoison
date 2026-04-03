using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

internal sealed class NpmThreatMonitorService : BackgroundService
{
    private readonly ServiceScanOptions _options;
    private readonly IScanProgressPublisher _progressPublisher;
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly ILogger<NpmThreatMonitorService> _logger;

    public NpmThreatMonitorService(
        ServiceScanOptions options,
        IScanProgressPublisher progressPublisher,
        IServiceScopeFactory scopeFactory,
        ILogger<NpmThreatMonitorService> logger)
    {
        _options = options;
        _progressPublisher = progressPublisher;
        _scopeFactory = scopeFactory;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("NpmRatPoison service started. Interval={IntervalMinutes}m, Scope={Scope}", _options.IntervalMinutes, _options.GitHubOnly ? "GitHub" : "All git repos");

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                _progressPublisher.Publish("service", null, null, "Service scan cycle started");
                await using var scope = _scopeFactory.CreateAsyncScope();
                var services = scope.ServiceProvider;
                var catalogProvider = services.GetRequiredService<IThreatCatalogProvider>();
                var allDriveScanService = services.GetRequiredService<IAllDriveScanService>();
                var reportWriter = services.GetRequiredService<IReportWriter>();

                var catalog = catalogProvider.Load(_options.CatalogPath);
                var report = await allDriveScanService.ExecuteAsync(dryRun: true, gitHubOnly: _options.GitHubOnly, catalog: catalog, cancellationToken: stoppingToken);

                _logger.LogInformation(
                    "Service scan complete: Drives={Drives}, ReposScanned={ReposScanned}, Findings={Findings}, Errors={Errors}",
                    report.DrivesScanned.Count,
                    report.ReposScanned,
                    report.ReposWithFindings,
                    report.Errors.Count);

                await reportWriter.WriteAsync(_options.ReportDirectory, "service-cycle", report, stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Service scan cycle failed.");
            }

            await Task.Delay(TimeSpan.FromMinutes(_options.IntervalMinutes), stoppingToken);
        }

        _logger.LogInformation("NpmRatPoison service stopping.");
    }
}
