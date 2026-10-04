using DLD.DroidGuard.Core.Models;

namespace DLD.DroidGuard.Core.Risk.Factors;

/// <summary>
/// Evaluates risk associated with sideloaded or unknown installer sources.
/// </summary>
public sealed class SideloadRiskFactor : IRiskFactor
{
    public string Id => "SIDELOAD_UNKNOWN_INSTALLER";
    public string Name => "Sideload / Unknown Installer";

    public RiskEvidence? Evaluate(AndroidApp app)
    {
        // System apps are not penalized for installer source
        if (app.Origin == AppOrigin.System)
            return null;

        var cat = InstallerClassifier.Classify(app.InstallerPackage);
        if (cat == InstallerCategory.UnknownSideload)
        {
            var installerText = string.IsNullOrEmpty(app.InstallerPackage)
                ? "No installer package record (Manual APK Sideload)"
                : $"Unknown installer: {app.InstallerPackage}";

            return new RiskEvidence(
                FactorId: Id,
                Title: "Sideloaded / Unknown Installer Source",
                Description: $"Application was not installed from a recognized trusted store ({installerText}).",
                Points: 15,
                Severity: RiskImpactSeverity.Medium
            );
        }

        return null;
    }
}
