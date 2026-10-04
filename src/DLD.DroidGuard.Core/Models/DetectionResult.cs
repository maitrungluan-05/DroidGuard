namespace DLD.DroidGuard.Core.Models;

/// <summary>
/// Specific category of threat detected by heuristic scanners.
/// </summary>
public enum DetectionType
{
    HiddenApp,
    AdwareSuspicion,
    SuspiciousSideload,
    SensitivePermissionCombination,
    ExcessivePermissions
}

/// <summary>
/// Result object representing a detected threat.
/// </summary>
public sealed record DetectionResult(
    DetectionType Type,
    string Name,
    RiskImpactSeverity Severity,
    double Confidence, // Range 0.0 to 1.0
    IReadOnlyList<string> EvidenceSummary,
    string Recommendation
);
