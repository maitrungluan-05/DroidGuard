using DLD.DroidGuard.Core.Models;

namespace DLD.DroidGuard.Core.Risk;

/// <summary>
/// Abstraction for a single modular risk evaluation factor.
/// </summary>
public interface IRiskFactor
{
    string Id { get; }
    string Name { get; }
    RiskEvidence? Evaluate(AndroidApp app);
}
