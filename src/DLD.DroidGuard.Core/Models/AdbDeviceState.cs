namespace DLD.DroidGuard.Core.Models;

/// <summary>
/// Represents the connection state of an Android device as reported by ADB.
/// </summary>
public enum AdbDeviceState
{
    Unknown,
    Offline,
    Unauthorized,
    Bootloader,
    Device,
    NoPermissions,
    Recovery,
    Sideload,
}
