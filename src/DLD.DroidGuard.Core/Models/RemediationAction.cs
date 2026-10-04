namespace DLD.DroidGuard.Core.Models;

/// <summary>
/// Remediation action types available for processing Android applications.
/// </summary>
public enum RemediationAction
{
    Uninstall,
    Disable,
    Enable,
    ClearData,
    ForceStop
}
