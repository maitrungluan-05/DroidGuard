using DLD.DroidGuard.Core.Models;

namespace DLD.DroidGuard.Core.Abstractions;

/// <summary>
/// Scans an Android device via ADB to enumerate packages and extract metadata.
/// </summary>
public interface IPackageScanner
{
    /// <summary>
    /// Scans installed packages on the target device.
    /// </summary>
    /// <param name="serial">Serial number of the target device.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task<PackageScanResult> ScanAsync(string serial, CancellationToken cancellationToken);
}
