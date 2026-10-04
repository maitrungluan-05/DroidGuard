using DLD.DroidGuard.Adb;
using DLD.DroidGuard.Core.Abstractions;
using DLD.DroidGuard.Core.Risk;
using Microsoft.Extensions.DependencyInjection;

namespace DLD.DroidGuard.Infrastructure;

/// <summary>
/// Extension methods to register all DLD DroidGuard services with the DI container.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers ADB & Security Analysis services: IAdbLocator, IAdbClient, IDeviceInfoService, IPackageScanner, IRiskEngine, IAppForensicsAnalyzer, IRuntimeAppAnalyzer, IBehaviorAnalyzer, IAppRemediationService, IScanReportExporter.
    /// </summary>
    public static IServiceCollection AddDroidGuardAdb(
        this IServiceCollection services,
        string? configuredAdbPath = null)
    {
        services.AddSingleton<IAdbLocator>(sp =>
        {
            var logger = sp.GetRequiredService<Microsoft.Extensions.Logging.ILogger<AdbLocator>>();
            return new AdbLocator(logger, configuredAdbPath);
        });

        services.AddSingleton<IAdbClient, AdbClient>();
        services.AddSingleton<IDeviceInfoService, DeviceInfoService>();
        services.AddSingleton<IPackageScanner, PackageScanner>();
        services.AddSingleton<IRiskEngine, RiskEngine>();

        // Milestone 04 & 05 Forensic, Behavioral & Remediation Services
        services.AddSingleton<IAppForensicsAnalyzer, AppForensicsAnalyzer>();
        services.AddSingleton<IRuntimeAppAnalyzer, RuntimeAppAnalyzer>();
        services.AddSingleton<IBehaviorAnalyzer, BehaviorAnalyzer>();
        services.AddSingleton<IAppRemediationService, AppRemediationService>();
        services.AddSingleton<IScanReportExporter, JsonReportExporter>();

        return services;
    }
}
