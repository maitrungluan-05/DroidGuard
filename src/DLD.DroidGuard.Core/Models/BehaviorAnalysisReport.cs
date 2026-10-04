namespace DLD.DroidGuard.Core.Models;

/// <summary>
/// Runtime dynamic behavioral analysis report for an Android application.
/// </summary>
public sealed record BehaviorAnalysisReport(
    string PackageName,
    DateTimeOffset StartedAt,
    DateTimeOffset CompletedAt,
    bool IsComplete,
    IReadOnlyList<string> Processes,
    IReadOnlyList<string> Services,
    IReadOnlyList<string> Activities,
    IReadOnlyList<string> Receivers,
    IReadOnlyList<NetworkIndicator> NetworkIndicators,
    IReadOnlyList<string> FileIndicators,
    IReadOnlyList<string> Evidence,
    IReadOnlyList<string> Errors,
    double Confidence
);
