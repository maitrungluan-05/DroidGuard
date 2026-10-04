using DLD.DroidGuard.Core.Models;

namespace DLD.DroidGuard.Core.Abstractions;

/// <summary>
/// Service interface for analyzing dynamic runtime behavior, activities, background services,
/// and non-intrusive network indicators via standard ADB shell queries.
/// </summary>
public interface IBehaviorAnalyzer
{
    Task<BehaviorAnalysisReport> AnalyzeAsync(
        string deviceSerial,
        AndroidApp app,
        CancellationToken cancellationToken = default);
}
