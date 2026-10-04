using DLD.DroidGuard.Core.Models;

namespace DLD.DroidGuard.Core.Abstractions;

/// <summary>
/// Reads Android device properties via ADB shell getprop.
/// </summary>
public interface IDeviceInfoService
{
    /// <summary>
    /// Reads a single getprop value from the specified device.
    /// Returns null if the property does not exist or cannot be read.
    /// </summary>
    Task<string?> GetPropAsync(
        string serial,
        string property,
        CancellationToken cancellationToken);

    /// <summary>
    /// Reads the standard device information properties.
    /// Properties that cannot be read are returned as null.
    /// </summary>
    Task<DeviceInfo> GetDeviceInfoAsync(
        string serial,
        CancellationToken cancellationToken);
}
