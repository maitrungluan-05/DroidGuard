namespace DLD.DroidGuard.Core.Models;

/// <summary>
/// Recommended user action for an application based on security analysis.
/// Remediation remains strictly user-initiated.
/// </summary>
public enum RecommendedAction
{
    None,
    Monitor,
    ReviewPermissions,
    Disable,
    Uninstall
}
