using DLD.DroidGuard.Core.Models;
using DLD.DroidGuard.Core.Risk;
using Xunit;

namespace DLD.DroidGuard.Tests;

public class CorrelationEngineTests
{
    [Fact]
    public void Assess_CorrelatesStaticAndBehaviorScoresSafely()
    {
        var app = new AndroidApp
        {
            PackageName = "com.suspicious.hidden",
            Origin = AppOrigin.User,
            HasLauncherActivity = false,
            InstallerPackage = null,
            RequestedPermissions = new[] { "android.permission.SYSTEM_ALERT_WINDOW" }
        };

        var staticAnalysis = new AppRiskAnalysis(
            RiskScore: 50,
            RiskLevel: RiskLevel.Medium,
            Evidences: new[]
            {
                new RiskEvidence("SIDELOAD_UNKNOWN_INSTALLER", "Unknown Installer", "Sideloaded", 15, RiskImpactSeverity.Medium),
                new RiskEvidence("HIDDEN_LAUNCHER_ACTIVITY", "No Launcher", "Hidden UI", 20, RiskImpactSeverity.High)
            },
            Detections: Array.Empty<DetectionResult>(),
            RecommendedAction: RecommendedAction.ReviewPermissions
        );

        var behaviorReport = new BehaviorAnalysisReport(
            PackageName: app.PackageName,
            StartedAt: DateTimeOffset.UtcNow.AddSeconds(-2),
            CompletedAt: DateTimeOffset.UtcNow,
            IsComplete: true,
            Processes: new[] { "PID 1234" },
            Services: new[] { "ServiceRecord{com.suspicious.hidden/.BackgroundService}" },
            Activities: Array.Empty<string>(),
            Receivers: Array.Empty<string>(),
            NetworkIndicators: Array.Empty<NetworkIndicator>(),
            FileIndicators: Array.Empty<string>(),
            Evidence: new[] { "Active background service on user package without launcher" },
            Errors: Array.Empty<string>(),
            Confidence: 0.90
        );

        var correlated = BehaviorCorrelationEngine.Assess(app, staticAnalysis, behaviorReport);

        Assert.Equal(50, correlated.StaticScore);
        Assert.Equal(10, correlated.BehaviorScore);
        Assert.Equal(60, correlated.FinalRiskScore); // 50 + 10 = 60
        Assert.Equal(RiskLevel.Medium, correlated.RiskLevel);
        Assert.NotEmpty(correlated.Timeline);
    }
}
