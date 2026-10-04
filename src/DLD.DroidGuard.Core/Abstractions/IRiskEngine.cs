using DLD.DroidGuard.Core.Models;

namespace DLD.DroidGuard.Core.Abstractions;

/// <summary>
/// Evaluates security risk scores and threat detections for Android applications.
/// </summary>
public interface IRiskEngine
{
    /// <summary>
    /// Evaluates a single application and returns its AppRiskAnalysis.
    /// </summary>
    AppRiskAnalysis Analyze(AndroidApp app);

    /// <summary>
    /// Evaluates a collection of applications and returns new AndroidApp records with RiskAnalysis populated.
    /// </summary>
    IReadOnlyList<AndroidApp> AnalyzeAll(IEnumerable<AndroidApp> apps);
}
