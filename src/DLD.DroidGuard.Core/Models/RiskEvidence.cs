namespace DLD.DroidGuard.Core.Models;

/// <summary>
/// Granular evidence explaining why a risk score was assigned to an application.
/// Provides explainable risk transparency for users.
/// </summary>
public sealed record RiskEvidence(
    string FactorId,
    string Title,
    string Description,
    int Points,
    RiskImpactSeverity Severity,
    EvidenceSourceType SourceType = EvidenceSourceType.PackageMetadata,
    string? InputSummary = null,
    string? RuleId = null,
    double? Confidence = null
);
