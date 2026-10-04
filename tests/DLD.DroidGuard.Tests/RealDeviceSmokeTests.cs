using DLD.DroidGuard.Adb;
using DLD.DroidGuard.Core.Models;
using DLD.DroidGuard.Core.Risk;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;
using Xunit.Abstractions;

namespace DLD.DroidGuard.Tests;

public class RealDeviceSmokeTests
{
    private readonly ITestOutputHelper _output;

    public RealDeviceSmokeTests(ITestOutputHelper output)
    {
        _output = output;
    }

    [Fact]
    public async Task SmokeTest_RealAndroidDevice_IfConnected()
    {
        var locator = new AdbLocator(NullLogger<AdbLocator>.Instance);
        var adbPath = locator.TryLocate();

        if (adbPath is null)
        {
            _output.WriteLine("ADB executable not found. Skipping live test.");
            return;
        }

        var adbClient = new AdbClient(locator, NullLogger<AdbClient>.Instance);
        var devices = await adbClient.GetDevicesAsync(CancellationToken.None);

        var onlineDevice = devices.FirstOrDefault(d => d.State == AdbDeviceState.Device);
        if (onlineDevice is null)
        {
            _output.WriteLine("No online Android device connected. Skipping live test.");
            return;
        }

        _output.WriteLine($"Testing on online device: Serial={onlineDevice.Serial}, Model={onlineDevice.Model}");

        var scanner = new PackageScanner(adbClient, NullLogger<PackageScanner>.Instance);
        var scanResult = await scanner.ScanAsync(onlineDevice.Serial, CancellationToken.None);

        _output.WriteLine($"Scan completed in {scanResult.Duration.TotalMilliseconds}ms with Status={scanResult.Status}");
        _output.WriteLine($"Apps count: {scanResult.Apps.Count}");

        Assert.True(scanResult.Apps.Count > 0, "Package count should be > 0 on a real device.");
        Assert.Contains(scanResult.Status, new[] { ScanStatus.Success, ScanStatus.Partial });

        // Run Risk Engine
        var riskEngine = new RiskEngine(NullLogger<RiskEngine>.Instance);
        var analyzedApps = riskEngine.AnalyzeAll(scanResult.Apps);

        int safeCount = analyzedApps.Count(a => a.RiskAnalysis?.RiskLevel == RiskLevel.Safe);
        int lowCount = analyzedApps.Count(a => a.RiskAnalysis?.RiskLevel == RiskLevel.Low);
        int medCount = analyzedApps.Count(a => a.RiskAnalysis?.RiskLevel == RiskLevel.Medium);
        int highCount = analyzedApps.Count(a => a.RiskAnalysis?.RiskLevel == RiskLevel.High);
        int critCount = analyzedApps.Count(a => a.RiskAnalysis?.RiskLevel == RiskLevel.Critical);

        _output.WriteLine($"Risk Analysis Summary:");
        _output.WriteLine($"  SAFE: {safeCount}, LOW: {lowCount}, MEDIUM: {medCount}, HIGH: {highCount}, CRITICAL: {critCount}");

        var detections = analyzedApps.SelectMany(a => a.RiskAnalysis?.Detections ?? Array.Empty<DetectionResult>()).ToList();
        _output.WriteLine($"Total Threat Detections: {detections.Count}");

        var top20 = analyzedApps.OrderByDescending(a => a.RiskAnalysis?.RiskScore ?? 0).Take(20).ToList();
        _output.WriteLine("TOP 20 Highest Scoring Packages:");
        int rank = 1;
        foreach (var app in top20)
        {
            var ra = app.RiskAnalysis!;
            _output.WriteLine($"Rank {rank++}: [{app.Origin}] {app.PackageName} (Score: {ra.RiskScore}, Level: {ra.RiskLevel}, Installer: {app.InstallerPackage ?? "null"}, Launcher: {app.HasLauncherActivity})");
            foreach (var ev in ra.Evidences)
            {
                _output.WriteLine($"   + {ev.Points} pts: {ev.Title} ({ev.Description})");
            }
        }

        Assert.All(analyzedApps, app =>
        {
            Assert.NotNull(app.RiskAnalysis);
            Assert.InRange(app.RiskAnalysis!.RiskScore, 0, 100);
        });
    }
}
