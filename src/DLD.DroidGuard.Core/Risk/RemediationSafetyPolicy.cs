using DLD.DroidGuard.Core.Models;

namespace DLD.DroidGuard.Core.Risk;

/// <summary>
/// Evaluates safety policies prior to executing destructive or state-changing remediation operations.
/// Prevents accidental bricking or disruption of core Android OS components.
/// </summary>
public static class RemediationSafetyPolicy
{
    private static readonly HashSet<string> CriticalSystemPackages = new(StringComparer.OrdinalIgnoreCase)
    {
        "android",
        "com.android.systemui",
        "com.android.settings",
        "com.android.vending",
        "com.google.android.gms",
        "com.google.android.gsf",
        "com.android.phone",
        "com.android.providers.telephony",
        "com.android.providers.media",
        "com.android.providers.contacts",
        "com.android.providers.downloads",
        "com.android.launcher",
        "com.android.launcher3",
        "com.google.android.apps.nexuslauncher",
        "com.sec.android.app.launcher"
    };

    public static (bool IsAllowed, string? Reason, bool IsWarningOnly) Evaluate(AndroidApp app, RemediationAction action)
    {
        if (app == null || string.IsNullOrWhiteSpace(app.PackageName))
            return (false, "Invalid application metadata.", false);

        var pkg = app.PackageName.Trim();

        // 1. Core OS Package Protection
        if (CriticalSystemPackages.Contains(pkg))
        {
            if (action == RemediationAction.Uninstall || action == RemediationAction.Disable || action == RemediationAction.ClearData)
            {
                return (false, $"Safety Violation: '{pkg}' is a critical Android OS core package. Remediation is blocked to prevent system instability or device bricking.", false);
            }
        }

        // 2. System App Policy
        if (app.Origin == AppOrigin.System)
        {
            if (action == RemediationAction.Uninstall)
            {
                return (false, $"Policy Restriction: '{pkg}' is a System package. Standard user uninstallation is restricted by Android OS safety rules.", false);
            }
        }

        // 3. Home / Launcher App Safety Warning
        if (app.HasLauncherActivity == true && action == RemediationAction.Uninstall)
        {
            return (true, $"Warning: '{pkg}' provides a user interface icon. Removing it will remove user launcher access.", true);
        }

        return (true, null, false);
    }
}
