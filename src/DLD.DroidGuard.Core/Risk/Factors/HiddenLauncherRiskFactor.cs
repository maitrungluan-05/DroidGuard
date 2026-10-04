using DLD.DroidGuard.Core.Models;

namespace DLD.DroidGuard.Core.Risk.Factors;

/// <summary>
/// Evaluates risk when a user application has no Launcher Activity.
/// Mitigates false positives for legitimate background components (keyboards, accessibility, VPNs, wallpapers).
/// Does NOT use overly broad generic keywords (like 'service', 'provider', 'plugin') which could bypass detection.
/// </summary>
public sealed class HiddenLauncherRiskFactor : IRiskFactor
{
    public string Id => "HIDDEN_LAUNCHER_ACTIVITY";
    public string Name => "Missing Launcher Activity";

    // Precise legitimate background utility keywords in package name
    private static readonly string[] LegitimateKeywords = new[]
    {
        "inputmethod", "keyboard", "honeyboard", "ime", "latin", "swiftkey", "vietkey", "laban",
        "accessibility", "talkback",
        "vpn", "wireguard", "openvpn", "strongswan",
        "wallpaper",
        "supervision", "devicepolicy", "knox", "mdm",
        "autofill", "printservice", "tile", "overlay"
    };

    public RiskEvidence? Evaluate(AndroidApp app)
    {
        // Only evaluate if HasLauncherActivity is explicitly false (not null, not system)
        if (app.HasLauncherActivity != false || app.Origin == AppOrigin.System)
            return null;

        var pkgNameLower = app.PackageName.ToLowerInvariant();
        bool isLegitimateCategory = LegitimateKeywords.Any(kw => pkgNameLower.Contains(kw));

        if (isLegitimateCategory)
        {
            // Mitigate false positive: legitimate background utility service detected
            return null;
        }

        return new RiskEvidence(
            FactorId: Id,
            Title: "User Application Without Launcher Icon",
            Description: "Application operates without exposing a standard launcher activity or icon in the app drawer.",
            Points: 20,
            Severity: RiskImpactSeverity.High
        );
    }

    public static bool IsLegitimateBackgroundService(string packageName)
    {
        if (string.IsNullOrWhiteSpace(packageName)) return false;
        var pkgNameLower = packageName.ToLowerInvariant();
        return LegitimateKeywords.Any(kw => pkgNameLower.Contains(kw));
    }
}
