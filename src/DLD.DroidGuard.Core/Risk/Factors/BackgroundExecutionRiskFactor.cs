using DLD.DroidGuard.Core.Models;

namespace DLD.DroidGuard.Core.Risk.Factors;

/// <summary>
/// Evaluates risk when an application possesses background execution capabilities
/// in conjunction with sideloading or missing launcher interface.
/// </summary>
public sealed class BackgroundExecutionRiskFactor : IRiskFactor
{
    public string Id => "BACKGROUND_EXECUTION_CAPABILITY";
    public string Name => "Background Execution Capability";

    public RiskEvidence? Evaluate(AndroidApp app)
    {
        if (app.Origin == AppOrigin.System || app.RequestedPermissions == null)
            return null;

        var perms = new HashSet<string>(app.RequestedPermissions, StringComparer.OrdinalIgnoreCase);

        bool hasBoot = perms.Contains("android.permission.RECEIVE_BOOT_COMPLETED");
        bool hasForeground = perms.Contains("android.permission.FOREGROUND_SERVICE");

        if (!hasBoot && !hasForeground)
            return null;

        bool isSideloaded = InstallerClassifier.Classify(app.InstallerPackage) == InstallerCategory.UnknownSideload;
        bool isHidden = app.HasLauncherActivity == false;

        // Background capability is especially risky if sideloaded or hidden
        if (isSideloaded || isHidden)
        {
            return new RiskEvidence(
                FactorId: Id,
                Title: "Background Execution Capability",
                Description: "Application possesses auto-start or persistent foreground background execution capability without trusted installer or visible launcher UI.",
                Points: 12,
                Severity: RiskImpactSeverity.Medium
            );
        }

        return null;
    }
}
