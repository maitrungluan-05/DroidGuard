namespace DLD.DroidGuard.Core.Models;

/// <summary>
/// Result of a package enumeration and metadata scan operation.
/// </summary>
public sealed record PackageScanResult(
    ScanStatus Status,
    IReadOnlyList<AndroidApp> Apps,
    IReadOnlyList<string> Errors,
    IReadOnlyList<string> Warnings,
    TimeSpan Duration,
    ScanCapability? Capability
);
