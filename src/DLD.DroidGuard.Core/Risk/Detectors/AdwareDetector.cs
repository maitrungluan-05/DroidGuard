using DLD.DroidGuard.Core.Models;

namespace DLD.DroidGuard.Core.Risk.Detectors;

/// <summary>
/// Heuristic adware suspicion detector based on static package metadata & permissions.
/// Requires System Overlay (SYSTEM_ALERT_WINDOW) combined with sideloading and boot auto-start/hidden launcher
/// to prevent false positives on standard notification-enabled applications.
/// </summary>
public sealed class AdwareDetector
{
    public DetectionResult? Detect(AndroidApp app, IReadOnlyList<RiskEvidence> evidences)
    {
        if (app.Origin != AppOrigin.User || app.RequestedPermissions == null)
            return null;

        var perms = new HashSet<string>(
            app.RequestedPermissions.Select(PermissionClassifier.NormalizePermission),
            StringComparer.OrdinalIgnoreCase);

        bool isSideloaded = InstallerClassifier.Classify(app.InstallerPackage) == InstallerCategory.UnknownSideload;
        bool hasOverlay = perms.Contains("android.permission.SYSTEM_ALERT_WINDOW");
        bool hasBoot = perms.Contains("android.permission.RECEIVE_BOOT_COMPLETED");
        bool isHidden = app.HasLauncherActivity == false;

        // Adware heuristic pattern: Sideloaded + System Overlay permission + (Boot Auto-start OR Hidden launcher)
        if (isSideloaded && hasOverlay && (hasBoot || isHidden))
        {
            var summary = new List<string>
            {
                "Installed from unknown/sideloaded source",
                "Requests System Overlay permission (SYSTEM_ALERT_WINDOW)",
                hasBoot ? "Auto-starts on system boot" : "Lacks visible launcher activity"
            };

            return new DetectionResult(
                Type: DetectionType.AdwareSuspicion,
                Name: "Adware Behavior Suspicion",
                Severity: RiskImpactSeverity.Medium,
                Confidence: 0.80,
                EvidenceSummary: summary,
                Recommendation: "Monitor for unexpected pop-up ads or full-screen overlays. Uninstall if unwanted."
            );
        }

        return null;
    }
}
