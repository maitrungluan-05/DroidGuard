using DLD.DroidGuard.Core.Models;

namespace DLD.DroidGuard.Core.Risk.Factors;

/// <summary>
/// Evaluates risk associated with sensitive and high-risk permissions.
/// </summary>
public sealed class SensitivePermissionRiskFactor : IRiskFactor
{
    public string Id => "SENSITIVE_PERMISSIONS";
    public string Name => "Sensitive & High Risk Permissions";

    public RiskEvidence? Evaluate(AndroidApp app)
    {
        if (app.RequestedPermissions == null || app.RequestedPermissions.Count == 0)
            return null;

        int points = PermissionClassifier.EvaluatePermissionPoints(app.RequestedPermissions, out var highRiskList);
        if (points <= 0)
            return null;

        var severity = points switch
        {
            >= 20 => RiskImpactSeverity.High,
            >= 10 => RiskImpactSeverity.Medium,
            _     => RiskImpactSeverity.Low
        };

        var summary = highRiskList.Count > 0
            ? $"Requests {highRiskList.Count} sensitive/high-risk permission(s): {string.Join(", ", highRiskList.Select(TrimPermName))}"
            : $"Requests {app.RequestedPermissions.Count} permission(s).";

        return new RiskEvidence(
            FactorId: Id,
            Title: "Sensitive Permissions Requested",
            Description: summary,
            Points: points,
            Severity: severity
        );
    }

    private static string TrimPermName(string fullPerm)
    {
        return fullPerm.StartsWith("android.permission.")
            ? fullPerm.Replace("android.permission.", "")
            : fullPerm;
    }
}
