using DLD.DroidGuard.Core.Models;
using DLD.DroidGuard.Core.Risk;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace DLD.DroidGuard.Tests;

public class RiskEngineTests
{
    private readonly RiskEngine _riskEngine;

    public RiskEngineTests()
    {
        _riskEngine = new RiskEngine(NullLogger<RiskEngine>.Instance);
    }

    [Fact]
    public void Analyze_SafeApp_ReturnsSafeOrLowRiskLevel()
    {
        var safeApp = new AndroidApp
        {
            PackageName = "com.example.safeapp",
            Origin = AppOrigin.User,
            HasLauncherActivity = true,
            InstallerPackage = "com.android.vending", // Google Play
            RequestedPermissions = new[] { "android.permission.INTERNET", "android.permission.VIBRATE" }
        };

        var analysis = _riskEngine.Analyze(safeApp);

        Assert.Equal(RiskLevel.Safe, analysis.RiskLevel);
        Assert.True(analysis.RiskScore < 30);
        Assert.Empty(analysis.Detections);
        Assert.Equal(RecommendedAction.None, analysis.RecommendedAction);
    }

    [Fact]
    public void Analyze_HiddenSuspiciousApp_ReturnsHighRiskAndHiddenAppDetection()
    {
        var suspiciousApp = new AndroidApp
        {
            PackageName = "com.suspicious.stealth",
            Origin = AppOrigin.User,
            HasLauncherActivity = false, // No launcher icon
            InstallerPackage = null,     // Unknown / Sideload
            RequestedPermissions = new[]
            {
                "android.permission.READ_SMS",
                "android.permission.READ_CONTACTS",
                "android.permission.RECEIVE_BOOT_COMPLETED",
                "android.permission.SYSTEM_ALERT_WINDOW"
            }
        };

        var analysis = _riskEngine.Analyze(suspiciousApp);

        Assert.True(analysis.RiskScore >= 70, $"Expected score >= 70, got {analysis.RiskScore}");
        Assert.True(analysis.RiskLevel >= RiskLevel.High);
        Assert.Contains(analysis.Detections, d => d.Type == DetectionType.HiddenApp);
        Assert.Contains(analysis.Evidences, e => e.FactorId == "HIDDEN_LAUNCHER_ACTIVITY");
        Assert.Contains(analysis.Evidences, e => e.FactorId == "SIDELOAD_UNKNOWN_INSTALLER");
    }

    [Fact]
    public void Analyze_LegitimateHiddenService_MitigatesFalsePositive()
    {
        var keyboardApp = new AndroidApp
        {
            PackageName = "com.google.android.inputmethod.latin", // Gboard keyboard
            Origin = AppOrigin.User,
            HasLauncherActivity = false, // Keyboards usually don't have standard launcher
            InstallerPackage = "com.android.vending",
            RequestedPermissions = new[] { "android.permission.VIBRATE", "android.permission.INTERNET" }
        };

        var analysis = _riskEngine.Analyze(keyboardApp);

        // Should NOT trigger HiddenApp detection because it's a known input method
        Assert.DoesNotContain(analysis.Detections, d => d.Type == DetectionType.HiddenApp);
        Assert.Equal(RiskLevel.Safe, analysis.RiskLevel);
    }

    [Fact]
    public void Analyze_SideloadAppOnly_IncreasesRiskScoreWithoutJumpingToCritical()
    {
        var sideloadedNormalApp = new AndroidApp
        {
            PackageName = "com.user.sideloadedapp",
            Origin = AppOrigin.User,
            HasLauncherActivity = true,
            InstallerPackage = null, // Sideloaded
            RequestedPermissions = new[] { "android.permission.INTERNET" }
        };

        var analysis = _riskEngine.Analyze(sideloadedNormalApp);

        Assert.Equal(15, analysis.RiskScore);
        Assert.Equal(RiskLevel.Safe, analysis.RiskLevel); // 15 is < 30 (Safe)
        Assert.Contains(analysis.Evidences, e => e.FactorId == "SIDELOAD_UNKNOWN_INSTALLER");
    }

    [Fact]
    public void Analyze_SensitivePermissionsAlone_DoesNotCauseSevereFalsePositive()
    {
        var cameraApp = new AndroidApp
        {
            PackageName = "com.trusted.cameraapp",
            Origin = AppOrigin.User,
            HasLauncherActivity = true,
            InstallerPackage = "com.android.vending",
            RequestedPermissions = new[] { "android.permission.CAMERA", "android.permission.ACCESS_FINE_LOCATION" }
        };

        var analysis = _riskEngine.Analyze(cameraApp);

        Assert.True(analysis.RiskScore < 30);
        Assert.Equal(RiskLevel.Safe, analysis.RiskLevel);
    }

    [Theory]
    [InlineData(0, RiskLevel.Safe)]
    [InlineData(29, RiskLevel.Safe)]
    [InlineData(30, RiskLevel.Low)]
    [InlineData(49, RiskLevel.Low)]
    [InlineData(50, RiskLevel.Medium)]
    [InlineData(69, RiskLevel.Medium)]
    [InlineData(70, RiskLevel.High)]
    [InlineData(84, RiskLevel.High)]
    [InlineData(85, RiskLevel.Critical)]
    [InlineData(100, RiskLevel.Critical)]
    public void ScoreBoundaries_MapToCorrectRiskLevels(int score, RiskLevel expectedLevel)
    {
        var level = RiskLevelExtensions.FromScore(score);
        Assert.Equal(expectedLevel, level);
    }
}
