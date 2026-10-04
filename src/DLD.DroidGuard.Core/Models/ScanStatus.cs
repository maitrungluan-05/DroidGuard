namespace DLD.DroidGuard.Core.Models;

/// <summary>
/// Status of a package scan operation.
/// </summary>
public enum ScanStatus
{
    Success,
    Partial,
    Unsupported,
    Failed,
    Cancelled
}
