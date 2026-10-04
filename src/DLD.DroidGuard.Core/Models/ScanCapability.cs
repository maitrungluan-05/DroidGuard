namespace DLD.DroidGuard.Core.Models;

/// <summary>
/// Capability metrics recorded during a package scan.
/// </summary>
public sealed record ScanCapability(
    bool ListPackagesSupported,
    bool DumpsysPackageSupported,
    bool LauncherQuerySupported
);
