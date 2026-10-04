namespace DLD.DroidGuard.Core.Models;

/// <summary>
/// Point-in-time snapshot of runtime behavioral indicators for temporal analysis.
/// </summary>
public sealed record BehaviorSnapshot(
    DateTimeOffset Timestamp,
    string PackageName,
    IReadOnlyList<string> ActiveProcesses,
    IReadOnlyList<string> ActiveServices,
    IReadOnlyList<NetworkIndicator> NetworkIndicators
);

/// <summary>
/// Traceable event in the application's runtime behavior timeline.
/// </summary>
public sealed record BehaviorTimelineEntry(
    DateTimeOffset Timestamp,
    string Category,
    string Description,
    RiskImpactSeverity Impact
);
