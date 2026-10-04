namespace DLD.DroidGuard.Core.Abstractions;

/// <summary>
/// Locates the ADB executable on the host machine.
/// Supports configured path, bundled executable, and PATH discovery.
/// </summary>
public interface IAdbLocator
{
    /// <summary>
    /// Returns the full path to adb.exe if found, or null.
    /// </summary>
    string? TryLocate();

    /// <summary>
    /// Returns the full path to adb.exe.
    /// Throws <see cref="AdbNotFoundException"/> if ADB cannot be found.
    /// </summary>
    string Locate();
}
