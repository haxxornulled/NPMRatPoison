using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

public sealed class DashboardLifecycleService : IHostedLifecycleService
{
    private readonly ScanDashboardState _dashboardState;
    private readonly IServer _server;
    private readonly DashboardScanCoordinator _dashboardScanCoordinator;
    private readonly ILogger<DashboardLifecycleService> _logger;

    public DashboardLifecycleService(
        ScanDashboardState dashboardState,
        IServer server,
        DashboardScanCoordinator dashboardScanCoordinator,
        ILogger<DashboardLifecycleService> logger)
    {
        _dashboardState = dashboardState;
        _server = server;
        _dashboardScanCoordinator = dashboardScanCoordinator;
        _logger = logger;
    }

    public Task StartingAsync(CancellationToken cancellationToken)
    {
        _dashboardState.SetLifecycle("Starting", "Bootstrapping Blazor dashboard");
        return Task.CompletedTask;
    }

    public async Task StartedAsync(CancellationToken cancellationToken)
    {
        var address = ResolveAddress();
        _dashboardState.SetLifecycle("Running", "Blazor dashboard is ready", address);
        await _dashboardScanCoordinator.RefreshArtifactsAsync(cancellationToken);
        _logger.LogInformation("Dashboard ready at {Address}", address ?? "unknown");
    }

    public Task StoppingAsync(CancellationToken cancellationToken)
    {
        _dashboardState.SetLifecycle("Stopping", "Dashboard shutdown requested");
        return Task.CompletedTask;
    }

    public Task StoppedAsync(CancellationToken cancellationToken)
    {
        _dashboardState.SetLifecycle("Stopped", "Dashboard stopped");
        return Task.CompletedTask;
    }

    public Task StartAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    private string? ResolveAddress()
    {
        var feature = _server.Features.Get<IServerAddressesFeature>();
        return feature?.Addresses.FirstOrDefault();
    }
}
