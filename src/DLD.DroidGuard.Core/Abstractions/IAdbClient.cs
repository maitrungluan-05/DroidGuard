using DLD.DroidGuard.Core.Models;

namespace DLD.DroidGuard.Core.Abstractions;

/// <summary>
/// Abstraction over the ADB command-line tool.
/// UI and ViewModels must only communicate with ADB through this interface.
/// </summary>
public interface IAdbClient
{
    /// <summary>
    /// Executes an ADB command and returns the full result.
    /// Never throws for non-zero exit codes.
    /// </summary>
    Task<AdbResult> ExecuteAsync(
        string? serial,
        string arguments,
        TimeSpan timeout,
        CancellationToken cancellationToken);

    /// <summary>
    /// Returns the ADB server version string (e.g. "1.0.41").
    /// </summary>
    Task<string> GetVersionAsync(CancellationToken cancellationToken);

    /// <summary>
    /// Returns all devices currently visible to ADB.
    /// Returns an empty list when no devices are connected.
    /// </summary>
    Task<IReadOnlyList<AndroidDevice>> GetDevicesAsync(CancellationToken cancellationToken);
}
