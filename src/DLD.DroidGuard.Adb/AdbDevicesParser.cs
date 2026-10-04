using System.Text.RegularExpressions;
using DLD.DroidGuard.Core.Models;

namespace DLD.DroidGuard.Adb;

/// <summary>
/// Parses the output of "adb devices -l" into a list of AndroidDevice records.
/// Handles: device, offline, unauthorized, no devices, multiple devices, unknown states.
/// </summary>
public sealed class AdbDevicesParser
{
    // Matches: SERIAL<whitespace>STATE [key:value ...]
    // Groups: 1=serial, 2=state, 3=attrs (optional)
    private static readonly Regex DeviceLineRegex = new(
        @"^(\S+)\s+(device|offline|unauthorized|bootloader|no permissions|recovery|sideload|host)(\s+.*)?$",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private static readonly Regex KeyValueRegex = new(
        @"(\w+):(\S+)",
        RegexOptions.Compiled);

    /// <summary>
    /// Parses "adb devices -l" output.
    /// </summary>
    public IReadOnlyList<AndroidDevice> Parse(string output)
    {
        var devices = new List<AndroidDevice>();

        if (string.IsNullOrWhiteSpace(output))
            return devices;

        foreach (var line in output.Split('\n'))
        {
            var trimmed = line.Trim();

            // Skip the header line and empty lines
            if (string.IsNullOrEmpty(trimmed)
                || trimmed.StartsWith("List of devices attached", StringComparison.OrdinalIgnoreCase))
                continue;

            var match = DeviceLineRegex.Match(trimmed);
            if (!match.Success)
                continue;

            var serial = match.Groups[1].Value;
            var stateToken = match.Groups[2].Value;
            var attrsSegment = match.Groups[3].Value;

            var state = ParseState(stateToken);
            var attrs = ParseAttributes(attrsSegment);

            attrs.TryGetValue("product", out var product);
            attrs.TryGetValue("model", out var model);
            attrs.TryGetValue("device", out var device);

            devices.Add(new AndroidDevice(serial, state, product, model, device));
        }

        return devices;
    }

    private static AdbDeviceState ParseState(string token) => token.ToLowerInvariant() switch
    {
        "device"         => AdbDeviceState.Device,
        "offline"        => AdbDeviceState.Offline,
        "unauthorized"   => AdbDeviceState.Unauthorized,
        "bootloader"     => AdbDeviceState.Bootloader,
        "no permissions" => AdbDeviceState.NoPermissions,
        "recovery"       => AdbDeviceState.Recovery,
        "sideload"       => AdbDeviceState.Sideload,
        _                => AdbDeviceState.Unknown,
    };

    private static Dictionary<string, string> ParseAttributes(string segment)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrWhiteSpace(segment))
            return result;

        foreach (Match m in KeyValueRegex.Matches(segment))
        {
            var key   = m.Groups[1].Value;
            var value = m.Groups[2].Value;
            result[key] = value;
        }

        return result;
    }
}
