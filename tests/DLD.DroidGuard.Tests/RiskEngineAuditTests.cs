using DLD.DroidGuard.Core.Models;
using DLD.DroidGuard.Core.Risk;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace DLD.DroidGuard.Tests;

public class RiskEngineAuditTests
{
    private readonly RiskEngine _riskEngine;

    public RiskEngineAuditTests()
    {
        _riskEngine = new RiskEngine(NullLogger<RiskEngine>.Instance);
    }

    [Fact]
    public void DuplicatePermissions_AreNotScoredMultipleTimes()
    {
        var appWithDuplicates = new AndroidApp
        {
            PackageName = "com.example.duplicateperm",
            Origin = AppOrigin.User,
            HasLauncherActivity = true,
            InstallerPackage = "com.android.vending",
            RequestedPermissions = new[]
            {
                "android.permission.READ_SMS",
                "android.permission.READ_SMS",
                "android.permission.READ_SMS",
                "READ_SMS"
            }
        };

        var analysis = _riskEngine.Analyze(appWithDuplicates);

        // READ_SMS is high risk (5 pts). It should only be scored ONCE (5 pts), not 4 times (20 pts).
        var smsEvidences = analysis.Evidences.Where(e => e.FactorId == "SENSITIVE_PERMISSIONS").ToList();
        Assert.Single(smsEvidences);
        Assert.Equal(5, analysis.RiskScore);
    }

    [Fact]
    public void UnknownPermission_DoesNotCrash_AndIsNotAssignedHighRisk()
    {
        var appWithUnknownPerm = new AndroidApp
        {
            PackageName = "com.example.unknownperm",
            Origin = AppOrigin.User,
            HasLauncherActivity = true,
            InstallerPackage = "com.android.vending",
            RequestedPermissions = new[]
            {
                "com.vendor.custom.UNKNOWN_PERMISSION_XYZ",
                "android.permission.SOME_NEW_FUTURE_PERMISSION"
            }
        };

        var analysis = _riskEngine.Analyze(appWithUnknownPerm);

        Assert.Equal(0, analysis.RiskScore);
        Assert.Equal(RiskLevel.Safe, analysis.RiskLevel);
        Assert.Empty(analysis.Evidences);
    }

    [Fact]
    public void EmptyMetadata_DoesNotCrash()
    {
        var emptyApp = new AndroidApp { PackageName = "com.empty.app" };

        var analysis = _riskEngine.Analyze(emptyApp);

        Assert.NotNull(analysis);
        Assert.True(analysis.RiskScore >= 0);
        Assert.NotNull(analysis.Evidences);
        Assert.NotNull(analysis.Detections);
    }

    [Fact]
    public void RiskScore_IsAlwaysSumOfEvidencePoints_Clamped0To100()
    {
        var suspiciousApp = new AndroidApp
        {
            PackageName = "com.suspicious.app",
            Origin = AppOrigin.User,
            HasLauncherActivity = false,
            InstallerPackage = null, // Sideload: +15
            RequestedPermissions = new[]
            {
                "android.permission.READ_SMS",              // +5
                "android.permission.READ_CONTACTS",         // +5
                "android.permission.SYSTEM_ALERT_WINDOW",   // +10
                "android.permission.RECEIVE_BOOT_COMPLETED" // Normal (0 perm pts, but triggers combinations/background execution)
            }
        };

        var analysis = _riskEngine.Analyze(suspiciousApp);

        int evidenceSum = analysis.Evidences.Sum(e => e.Points);
        int expectedClampedScore = Math.Clamp(evidenceSum, 0, 100);

        Assert.Equal(expectedClampedScore, analysis.RiskScore);
    }

    [Fact]
    public void Detector_DoesNotAddExtraPointsToRiskScore()
    {
        var appWithAdwarePattern = new AndroidApp
        {
            PackageName = "com.adware.pattern",
            Origin = AppOrigin.User,
            HasLauncherActivity = true,
            InstallerPackage = null, // Sideload (+15)
            RequestedPermissions = new[]
            {
                "android.permission.SYSTEM_ALERT_WINDOW",  // SpecialAccess (+10)
                "android.permission.POST_NOTIFICATIONS",   // Sensitive (+2)
                "android.permission.RECEIVE_BOOT_COMPLETED" // Boot (+12 background execution capability factor)
            }
        };

        var analysis = _riskEngine.Analyze(appWithAdwarePattern);

        // Check if Adware detector fired
        Assert.Contains(analysis.Detections, d => d.Type == DetectionType.AdwareSuspicion);

        // Sum of evidences: Sideload (15) + Permissions (12) + Background Execution (12) = 39
        int evidenceSum = analysis.Evidences.Sum(e => e.Points);
        Assert.Equal(39, evidenceSum);
        Assert.Equal(39, analysis.RiskScore);
    }

    [Theory]
    [InlineData("com.google.android.inputmethod.latin", true)] // Keyboard
    [InlineData("com.wireguard.android", true)]                 // VPN
    [InlineData("com.android.wallpaper", true)]                // Wallpaper
    [InlineData("com.example.malicious.app", false)]           // Generic suspicious app
    public void HiddenAppDetector_MitigatesLegitimatePackageNames(string packageName, bool shouldBeMitigated)
    {
        var app = new AndroidApp
        {
            PackageName = packageName,
            Origin = AppOrigin.User,
            HasLauncherActivity = false,
            InstallerPackage = "com.android.vending",
            RequestedPermissions = new[] { "android.permission.INTERNET" }
        };

        var analysis = _riskEngine.Analyze(app);

        bool hasHiddenDetection = analysis.Detections.Any(d => d.Type == DetectionType.HiddenApp);

        if (shouldBeMitigated)
        {
            Assert.False(hasHiddenDetection, $"Expected no HiddenApp detection for {packageName}");
        }
        else
        {
            Assert.True(hasHiddenDetection, $"Expected HiddenApp detection for {packageName}");
        }
    }
}
