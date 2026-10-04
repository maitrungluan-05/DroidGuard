using DLD.DroidGuard.Core.Models;

namespace DLD.DroidGuard.Core.Risk.Factors;

/// <summary>
/// Evaluates risk associated with dangerous permission combinations.
/// </summary>
public sealed class SuspiciousPermissionCombinationFactor : IRiskFactor
{
    public string Id => "SUSPICIOUS_PERMISSION_COMBINATION";
    public string Name => "Suspicious Permission Combination";

    public RiskEvidence? Evaluate(AndroidApp app)
    {
        if (app.RequestedPermissions == null || app.RequestedPermissions.Count == 0)
            return null;

        int points = PermissionClassifier.EvaluatePermissionCombinationPoints(app.RequestedPermissions, out var matchedCombos);
        if (points <= 0 || matchedCombos.Count == 0)
            return null;

        return new RiskEvidence(
            FactorId: Id,
            Title: "Suspicious Permission Combination Detected",
            Description: $"Detected permission pattern: {string.Join("; ", matchedCombos)}.",
            Points: points,
            Severity: RiskImpactSeverity.High
        );
    }
}
