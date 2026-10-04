namespace DLD.DroidGuard.Core.Models;

/// <summary>
/// Basic device information retrieved via adb shell getprop.
/// Properties not available on the device are null.
/// </summary>
public sealed record DeviceInfo(
    string Serial,
    string? Manufacturer,
    string? Model,
    string? Device,
    string? AndroidVersion,
    string? SdkVersion,
    string? SecurityPatch
);
