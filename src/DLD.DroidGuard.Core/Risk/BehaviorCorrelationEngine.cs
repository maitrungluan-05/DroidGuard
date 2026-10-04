using DLD.DroidGuard.Core.Models;

namespace DLD.DroidGuard.Core.Risk;

/// <summary>
/// Correlates static risk engine results, forensic data, and dynamic behavioral indicators.
/// Combines scores safely without double-counting or inflating risk for legitimate apps.
/// </summary>
public static class BehaviorCorrelationEngine
{
    public static CorrelatedSecurityAssessment Assess(
        AndroidApp app,
        AppRiskAnalysis? staticAnalysis = null,
        BehaviorAnalysisReport? behaviorReport = null,
        AppForensicReport? forensicReport = null)
    {
        var staticRisk = staticAnalysis ?? app.RiskAnalysis;
        int staticScore = staticRisk?.RiskScore ?? 0;

        int behaviorPoints = 0;
        var timeline = new List<BehaviorTimelineEntry>();
        var additionalEvidences = new List<RiskEvidence>();

        var now = DateTimeOffset.UtcNow;

        if (behaviorReport != null && behaviorReport.IsComplete)
        {
            timeline.Add(new BehaviorTimelineEntry(behaviorReport.StartedAt, "System", $"Behavior analysis initialized for package {app.PackageName}", RiskImpactSeverity.Low));

            // Process correlation
            if (behaviorReport.Processes.Count > 0)
            {
                timeline.Add(new BehaviorTimelineEntry(now, "Process", $"Active runtime process detected: {string.Join(", ", behaviorReport.Processes.Take(2))}", RiskImpactSeverity.Low));
            }

            // Service correlation with hidden launcher / background capability
            if (behaviorReport.Services.Count > 0)
            {
                timeline.Add(new BehaviorTimelineEntry(now, "Service", $"Background service active ({behaviorReport.Services.Count} service(s))", RiskImpactSeverity.Medium));

                if (app.HasLauncherActivity == false && app.Origin == AppOrigin.User)
                {
                    bool isLegitimate = Factors.HiddenLauncherRiskFactor.IsLegitimateBackgroundService(app.PackageName);
                    if (!isLegitimate)
                    {
                        behaviorPoints += 10;
                        additionalEvidences.Add(new RiskEvidence(
                            FactorId: "CORRELATED_HIDDEN_BACKGROUND_SERVICE",
                            Title: "Active Background Service on Hidden User Application",
                            Description: "Application operates persistent active background services without exposing a launcher icon.",
                            Points: 10,
                            Severity: RiskImpactSeverity.High,
                            SourceType: EvidenceSourceType.Runtime,
                            RuleId: "RULE_CORR_01",
                            Confidence: 0.85
                        ));
                    }
                }
            }

            // Network indicator correlation
            if (behaviorReport.NetworkIndicators.Count > 0)
            {
                var unknownNet = behaviorReport.NetworkIndicators
                    .Where(n => n.Classification == NetworkActivityClassification.UnknownBackgroundNetworkActivity ||
                                n.Classification == NetworkActivityClassification.SuspiciousNetworkPattern)
                    .ToList();

                if (unknownNet.Count > 0)
                {
                    timeline.Add(new BehaviorTimelineEntry(now, "Network", $"Non-system background network connection detected to {unknownNet.First().DestinationIp}:{unknownNet.First().DestinationPort}", RiskImpactSeverity.Medium));

                    // Corroborate with sideload / overlay permissions
                    bool isSideloaded = InstallerClassifier.Classify(app.InstallerPackage) == InstallerCategory.UnknownSideload;
                    bool hasOverlay = app.RequestedPermissions.Any(p => PermissionClassifier.NormalizePermission(p) == "android.permission.SYSTEM_ALERT_WINDOW");

                    if (isSideloaded || hasOverlay)
                    {
                        behaviorPoints += 5;
                        additionalEvidences.Add(new RiskEvidence(
                            FactorId: "CORRELATED_UNTRUSTED_NETWORK_ACTIVITY",
                            Title: "Background Network Connection on Sideloaded / Overlay App",
                            Description: $"Active connection established to {unknownNet.First().DestinationIp}:{unknownNet.First().DestinationPort} by untrusted / high-capability package.",
                            Points: 5,
                            Severity: RiskImpactSeverity.Medium,
                            SourceType: EvidenceSourceType.Runtime,
                            RuleId: "RULE_CORR_02",
                            Confidence: 0.75
                        ));
                    }
                }
                else
                {
                    timeline.Add(new BehaviorTimelineEntry(now, "Network", "Normal network activity metadata observed", RiskImpactSeverity.Low));
                }
            }
        }

        // Cap corroborating behavior points to maximum +15 to avoid explosive false positive inflation
        int behaviorScoreClamped = Math.Min(behaviorPoints, 15);

        // Combine static + corroborating behavior score
        int finalScore = Math.Clamp(staticScore + behaviorScoreClamped, 0, 100);
        var finalLevel = RiskLevelExtensions.FromScore(finalScore);

        // Combine evidences
        var combinedEvidences = new List<RiskEvidence>(staticRisk?.Evidences ?? Array.Empty<RiskEvidence>());
        combinedEvidences.AddRange(additionalEvidences);

        double confidence = behaviorReport?.Confidence ?? 0.90;
        string quality = behaviorReport != null
            ? "Correlated Assessment (Static Metadata + Dynamic Behavioral Corroboration)"
            : "Standard Assessment (Static Metadata)";

        return new CorrelatedSecurityAssessment(
            StaticScore: staticScore,
            BehaviorScore: behaviorScoreClamped,
            FinalRiskScore: finalScore,
            RiskLevel: finalLevel,
            Confidence: confidence,
            EvidenceQuality: quality,
            Evidences: combinedEvidences,
            Detections: staticRisk?.Detections ?? Array.Empty<DetectionResult>(),
            Timeline: timeline
        );
    }
}
