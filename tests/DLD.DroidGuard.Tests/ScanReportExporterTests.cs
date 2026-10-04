using DLD.DroidGuard.Core.Models;
using DLD.DroidGuard.Infrastructure;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace DLD.DroidGuard.Tests;

public class ScanReportExporterTests
{
    [Fact]
    public async Task ExportJsonAsync_CreatesValidJsonFile()
    {
        var exporter = new JsonReportExporter(NullLogger<JsonReportExporter>.Instance);
        var tempFile = Path.Combine(Path.GetTempPath(), $"droidguard_test_report_{Guid.NewGuid()}.json");

        try
        {
            var app = new AndroidApp
            {
                PackageName = "com.example.testpkg",
                Origin = AppOrigin.User,
                RiskAnalysis = new AppRiskAnalysis(
                    RiskScore: 15,
                    RiskLevel: RiskLevel.Safe,
                    Evidences: new[]
                    {
                        new RiskEvidence("SIDELOAD_UNKNOWN_INSTALLER", "Unknown Installer", "Installed manually via APK", 15, RiskImpactSeverity.Medium)
                    },
                    Detections: Array.Empty<DetectionResult>(),
                    RecommendedAction: RecommendedAction.None
                )
            };

            var session = new ScanSession(
                SessionId: Guid.NewGuid(),
                DeviceSerial: "emulator-5554",
                DeviceModel: "Pixel 9 Pro XL",
                AndroidVersion: "16",
                ScanStartedAt: DateTimeOffset.UtcNow.AddSeconds(-5),
                ScanCompletedAt: DateTimeOffset.UtcNow,
                PackageCount: 1,
                RiskDistribution: new Dictionary<RiskLevel, int> { [RiskLevel.Safe] = 1 },
                DetectionCount: 0,
                Apps: new[] { app }
            );

            await exporter.ExportJsonAsync(session, tempFile);

            Assert.True(File.Exists(tempFile));
            var jsonText = await File.ReadAllTextAsync(tempFile);

            Assert.Contains("emulator-5554", jsonText);
            Assert.Contains("com.example.testpkg", jsonText);
            Assert.Contains("SIDELOAD_UNKNOWN_INSTALLER", jsonText);
        }
        finally
        {
            if (File.Exists(tempFile))
            {
                File.Delete(tempFile);
            }
        }
    }
}
