using DLD.DroidGuard.Adb;
using DLD.DroidGuard.Core.Models;
using DLD.DroidGuard.Core.Risk;
using DLD.DroidGuard.Core.Risk.Detectors;
using DLD.DroidGuard.Infrastructure;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Xunit;

namespace DLD.DroidGuard.Tests;

public class ReleaseHardeningTests
{
    private readonly RiskEngine _riskEngine;

    public ReleaseHardeningTests()
    {
        _riskEngine = new RiskEngine(NullLogger<RiskEngine>.Instance);
    }

    [Theory]
    [InlineData("valid_serial_123", true)]
    [InlineData("emulator-5554", true)]
    [InlineData("192.168.1.100:5555", true)]
    [InlineData("invalid; serial", false)]
    [InlineData("serial|rm -rf /", false)]
    [InlineData("serial&echo hi", false)]
    public void SafeAdbCommandBuilder_ValidatesSerialsCorrectly(string serial, bool expectedResult)
    {
        bool isSafe = SafeAdbCommandBuilder.IsSafeIdentifier(serial);
        Assert.Equal(expectedResult, isSafe);
    }

    [Fact]
    public async Task AdbClient_RejectsUnsafeSerialInput()
    {
        var locatorMock = new Mock<DLD.DroidGuard.Core.Abstractions.IAdbLocator>();
        locatorMock.Setup(l => l.Locate()).Returns("adb.exe");

        var client = new AdbClient(locatorMock.Object, NullLogger<AdbClient>.Instance);

        await Assert.ThrowsAsync<ArgumentException>(() =>
            client.ExecuteAsync("serial; rm -rf /", "version", TimeSpan.FromSeconds(5), CancellationToken.None));
    }

    [Fact]
    public void MalformedDumpsysOutput_DoesNotCrashParser()
    {
        var parser = new DumpsysPackageParser();
        var malformedOutput = @"Package [com.example.broken]
  versionCode=INVALID_CODE
  pkgFlags=[ SYSTEM UNKNOWN_FLAG ]
  requested permissions:
    android.permission.READ_SMS: granted=true
  random garbage text line...
";

        var dict = parser.Parse(malformedOutput);

        Assert.NotEmpty(dict);
        Assert.True(dict.ContainsKey("com.example.broken"));
        Assert.Equal("com.example.broken", dict["com.example.broken"].PackageName);
    }

    [Fact]
    public void SideloadPlusPostNotifications_DoesNotTriggerAdwareSuspicion()
    {
        var normalNotificationApp = new AndroidApp
        {
            PackageName = "com.normal.notificationapp",
            Origin = AppOrigin.User,
            HasLauncherActivity = true,
            InstallerPackage = null, // Sideloaded (+15)
            RequestedPermissions = new[] { "android.permission.POST_NOTIFICATIONS", "android.permission.INTERNET" }
        };

        var analysis = _riskEngine.Analyze(normalNotificationApp);

        // MUST NOT trigger Adware Suspicion because SYSTEM_ALERT_WINDOW (Overlay) is missing
        Assert.DoesNotContain(analysis.Detections, d => d.Type == DetectionType.AdwareSuspicion);
        Assert.Equal(17, analysis.RiskScore); // Sideload (15) + Sensitive Perm POST_NOTIFICATIONS (2) = 17
        Assert.Equal(RiskLevel.Safe, analysis.RiskLevel);
    }

    [Fact]
    public void SideloadPlusOverlayPlusBoot_TriggersAdwareSuspicion()
    {
        var adwareApp = new AndroidApp
        {
            PackageName = "com.suspicious.adware",
            Origin = AppOrigin.User,
            HasLauncherActivity = true,
            InstallerPackage = null, // Sideloaded (+15)
            RequestedPermissions = new[]
            {
                "android.permission.SYSTEM_ALERT_WINDOW",  // Overlay (+10)
                "android.permission.RECEIVE_BOOT_COMPLETED" // Boot (+12 background execution)
            }
        };

        var analysis = _riskEngine.Analyze(adwareApp);

        Assert.Contains(analysis.Detections, d => d.Type == DetectionType.AdwareSuspicion);
        Assert.True(analysis.RiskScore >= 30);
    }

    [Fact]
    public void BehaviorScore_IsStrictlyCappedAt15()
    {
        var app = new AndroidApp
        {
            PackageName = "com.behavior.test",
            Origin = AppOrigin.User,
            HasLauncherActivity = false,
            InstallerPackage = null,
            RequestedPermissions = new[] { "android.permission.SYSTEM_ALERT_WINDOW" }
        };

        var staticAnalysis = new AppRiskAnalysis(
            RiskScore: 40,
            RiskLevel: RiskLevel.Low,
            Evidences: Array.Empty<RiskEvidence>(),
            Detections: Array.Empty<DetectionResult>(),
            RecommendedAction: RecommendedAction.None
        );

        var heavyBehaviorReport = new BehaviorAnalysisReport(
            PackageName: app.PackageName,
            StartedAt: DateTimeOffset.UtcNow,
            CompletedAt: DateTimeOffset.UtcNow,
            IsComplete: true,
            Processes: new[] { "PID 1", "PID 2", "PID 3" },
            Services: new[] { "Svc1", "Svc2", "Svc3" },
            Activities: Array.Empty<string>(),
            Receivers: Array.Empty<string>(),
            NetworkIndicators: new[]
            {
                new NetworkIndicator(1001, "1.2.3.4", 443, "ESTABLISHED", NetworkActivityClassification.UnknownBackgroundNetworkActivity, "Desc")
            },
            FileIndicators: Array.Empty<string>(),
            Evidence: new[] { "Ev1", "Ev2", "Ev3" },
            Errors: Array.Empty<string>(),
            Confidence: 0.90
        );

        var correlated = BehaviorCorrelationEngine.Assess(app, staticAnalysis, heavyBehaviorReport);

        Assert.True(correlated.BehaviorScore <= 15, $"Behavior score should be capped at 15, got {correlated.BehaviorScore}");
        Assert.Equal(40 + correlated.BehaviorScore, correlated.FinalRiskScore);
    }
}
