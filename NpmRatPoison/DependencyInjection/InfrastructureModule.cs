using Autofac;
using System.Net.Http.Headers;

internal sealed class InfrastructureModule : Module
{
    protected override void Load(ContainerBuilder builder)
    {
        builder.RegisterType<FileThreatCatalogProvider>()
            .As<IThreatCatalogProvider>()
            .SingleInstance();

        builder.RegisterType<ConsoleScanProgressPublisher>()
            .As<IScanProgressPublisher>()
            .SingleInstance();

        builder.RegisterType<JsonReportWriter>()
            .As<IReportWriter>()
            .SingleInstance();

        builder.RegisterType<SystemConsoleRuntime>()
            .As<IConsoleRuntime>()
            .SingleInstance();

        builder.RegisterType<ConsoleGitHubCredentialPrompt>()
            .As<IGitHubCredentialPrompt>()
            .SingleInstance();

        builder.RegisterType<GitHubAccessTokenResolver>()
            .As<IGitHubAccessTokenResolver>()
            .SingleInstance();

        builder.Register(_ =>
            {
                var client = new HttpClient
                {
                    BaseAddress = new Uri("https://api.github.com")
                };
                client.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("NpmRatPoison", "1.0"));
                client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.github+json"));
                return client;
            })
            .SingleInstance();

        builder.RegisterType<GitHubRepositoryGateway>()
            .As<IGitHubRepositoryGateway>()
            .SingleInstance();

        builder.RegisterType<ProviderIngressService>()
            .As<IProviderIngressService>()
            .SingleInstance();

        builder.RegisterType<ProviderApiKeyService>()
            .As<IProviderApiKeyService>()
            .SingleInstance();
    }
}
