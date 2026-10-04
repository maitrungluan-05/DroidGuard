namespace DLD.DroidGuard.Core.Models;

/// <summary>
/// Combined risk assessment correlating static metadata, forensic data, and runtime behavioral evidence.
/// </summary>
public sealed record CorrelatedSecurityAssessment(
    int StaticScore,
    int BehaviorScore,
    int FinalRiskScore,
    RiskLevel RiskLevel,
    double Confidence,
    string EvidenceQuality,
    IReadOnlyList<RiskEvidence> Evidences,
    IReadOnlyList<DetectionResult> Detections,
    IReadOnlyList<BehaviorTimelineEntry> Timeline
);
