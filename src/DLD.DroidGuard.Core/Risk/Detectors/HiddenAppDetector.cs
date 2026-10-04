using DLD.DroidGuard.Core.Models;
using DLD.DroidGuard.Core.Risk.Factors;

namespace DLD.DroidGuard.Core.Risk.Detectors;

/// <summary>
/// Heuristic detector for hidden suspicious applications.
/// Mitigates false positives for legitimate system services, input methods, accessibility, and VPN utilities.
/// </summary>
public sealed class HiddenAppDetector
{
    public DetectionResult? Detect(AndroidApp app, IReadOnlyList<RiskEvidence> evidences)
    {
        // Must be a user-installed app with verified absence of launcher activity
        if (app.Origin != AppOrigin.User || app.HasLauncherActivity != false)
            return null;

        // Mitigate false positive: Check if package belongs to known legitimate service types
        if (HiddenLauncherRiskFactor.IsLegitimateBackgroundService(app.PackageName))
            return null;

        var evidenceList = new List<string>
        {
            "User-installed application",
            "No visible launcher icon or activity in app drawer"
        };

        bool hasSensitivePerms = app.RequestedPermissions.Any(p =>
            PermissionClassifier.GetCategory(p) >= PermissionCategory.Sensitive);

        if (hasSensitivePerms)
            evidenceList.Add("Requests sensitive or high-risk permissions");

        bool isSideloaded = InstallerClassifier.Classify(app.InstallerPackage) == InstallerCategory.UnknownSideload;
        if (isSideloaded)
            evidenceList.Add("Installed from unknown/sideloaded source");

        double confidence = (hasSensitivePerms, isSideloaded) switch
        {
            (true, true)   => 0.90,
            (true, false)  => 0.80,
            (false, true)  => 0.75,
            (false, false) => 0.65
        };

        return new DetectionResult(
            Type: DetectionType.HiddenApp,
            Name: "Suspicious Hidden Application",
            Severity: confidence >= 0.85 ? RiskImpactSeverity.High : RiskImpactSeverity.Medium,
            Confidence: confidence,
            EvidenceSummary: evidenceList,
            Recommendation: "Review application legitimacy. Disable or uninstall if unrecognized by user."
        );
    }
}
