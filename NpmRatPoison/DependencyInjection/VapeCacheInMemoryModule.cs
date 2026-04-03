using Autofac;
using VapeCache.Abstractions.Caching;
using VapeCache.Infrastructure.Caching;
using VapeCache.Infrastructure.DependencyInjection;

internal sealed class VapeCacheInMemoryModule : Module
{
    protected override void Load(ContainerBuilder builder)
    {
        builder.RegisterModule<VapeCacheCachingModule>();

        builder.Register(context => (ICacheService)context.Resolve<ICacheFallbackService>())
            .As<ICacheService>()
            .SingleInstance();

        builder.Register(context => new VapeCacheClient(
                context.Resolve<ICacheService>(),
                context.Resolve<ICacheCodecProvider>()))
            .As<IVapeCache>()
            .SingleInstance();
    }
}
