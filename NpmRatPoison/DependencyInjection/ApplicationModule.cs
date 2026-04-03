using Autofac;

internal sealed class ApplicationModule : Module
{
    protected override void Load(ContainerBuilder builder)
    {
        builder.RegisterType<ThreatCleanupService>()
            .As<IThreatCleanupService>()
            .InstancePerLifetimeScope();

        builder.RegisterType<AllDriveScanService>()
            .As<IAllDriveScanService>()
            .InstancePerLifetimeScope();

        builder.RegisterType<AutoTriageService>()
            .As<IAutoTriageService>()
            .InstancePerLifetimeScope();

        builder.RegisterType<IncidentSimulationService>()
            .As<IIncidentSimulationService>()
            .InstancePerLifetimeScope();

        builder.RegisterType<RemoteGitHubScanService>()
            .As<IRemoteGitHubScanService>()
            .InstancePerLifetimeScope();
    }
}
