namespace DLD.DroidGuard.Core.Models;

/// <summary>
/// Complete security risk analysis result for an Android application.
/// </summary>
public sealed record AppRiskAnalysis(
    int RiskScore,
    RiskLevel RiskLevel,
    IReadOnlyList<RiskEvidence> Evidences,
    IReadOnlyList<DetectionResult> Detections,
    RecommendedAction RecommendedAction,
    double Confidence = 1.0,
    string EvidenceQuality = "Standard (Package Metadata)"
);
