using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using OpenTelemetry.Exporter;
using OpenTelemetry.Metrics;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;
using VapeCache.Extensions.EntityFrameworkCore;
using VapeCache.Extensions.EntityFrameworkCore.OpenTelemetry;

internal static class OpenTelemetryRegistrationExtensions
{
    private const string ServiceName = "NpmRatPoison";
    private const string ActivitySourceName = "NpmRatPoison";
    private const string MeterName = "NpmRatPoison";
    private const string VapeCacheEfCoreActivitySource = "VapeCache.EFCore.Cache";
    private const string VapeCacheEfCoreMeter = "VapeCache.EFCore.Cache";

    public static IServiceCollection AddNpmRatPoisonObservability(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddVapeCacheEntityFrameworkCore(options =>
        {
            options.Enabled = true;
            options.EnableCommandKeyDiagnostics = true;
            options.EnableObserverCallbacks = true;
            options.EnableSaveChangesInvalidation = true;
            options.ZonePrefix = "ef";
        });

        services.AddVapeCacheEfCoreOpenTelemetry(options =>
        {
            options.Enabled = true;
            options.EmitActivities = true;
        });

        var otlpEndpoint = ResolveOtlpEndpoint(configuration);
        var useConsoleExporter = configuration.GetValue("OpenTelemetry:Console:Enabled", true);

        services.AddOpenTelemetry()
            .ConfigureResource(resource => resource
                .AddService(ServiceName, serviceVersion: typeof(Program).Assembly.GetName().Version?.ToString() ?? "1.0.0"))
            .WithMetrics(metrics =>
            {
                metrics
                    .AddMeter(MeterName)
                    .AddMeter(VapeCacheEfCoreMeter)
                    .AddRuntimeInstrumentation()
                    .AddProcessInstrumentation();

                if (useConsoleExporter)
                {
                    metrics.AddConsoleExporter();
                }

                if (otlpEndpoint is not null)
                {
                    metrics.AddOtlpExporter(options =>
                    {
                        options.Endpoint = otlpEndpoint;
                        options.Protocol = OtlpExportProtocol.HttpProtobuf;
                    });
                }
            })
            .WithTracing(tracing =>
            {
                tracing
                    .AddSource(ActivitySourceName)
                    .AddSource(VapeCacheEfCoreActivitySource);

                if (useConsoleExporter)
                {
                    tracing.AddConsoleExporter();
                }

                if (otlpEndpoint is not null)
                {
                    tracing.AddOtlpExporter(options =>
                    {
                        options.Endpoint = otlpEndpoint;
                        options.Protocol = OtlpExportProtocol.HttpProtobuf;
                    });
                }
            });

        return services;
    }

    private static Uri? ResolveOtlpEndpoint(IConfiguration configuration)
    {
        var raw = configuration["OpenTelemetry:Otlp:Endpoint"]
                  ?? Environment.GetEnvironmentVariable("OTEL_EXPORTER_OTLP_ENDPOINT");

        return Uri.TryCreate(raw, UriKind.Absolute, out var endpoint) ? endpoint : null;
    }
}
