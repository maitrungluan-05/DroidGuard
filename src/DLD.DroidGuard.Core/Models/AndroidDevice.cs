namespace DLD.DroidGuard.Core.Models;

/// <summary>
/// Represents an Android device discovered via ADB.
/// </summary>
public sealed record AndroidDevice(
    string Serial,
    AdbDeviceState State,
    string? Product,
    string? Model,
    string? Device
);
