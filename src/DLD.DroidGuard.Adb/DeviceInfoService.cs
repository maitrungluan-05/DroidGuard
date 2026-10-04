using DLD.DroidGuard.Core.Abstractions;
using DLD.DroidGuard.Core.Models;
using Microsoft.Extensions.Logging;

namespace DLD.DroidGuard.Adb;

/// <summary>
/// Retrieves Android device properties by calling "adb shell getprop".
/// </summary>
public sealed class DeviceInfoService : IDeviceInfoService
{
    private static readonly TimeSpan GetPropTimeout = TimeSpan.FromSeconds(10);

    private readonly IAdbClient _adbClient;
    private readonly ILogger<DeviceInfoService> _logger;

    public DeviceInfoService(IAdbClient adbClient, ILogger<DeviceInfoService> logger)
    {
        _adbClient = adbClient ?? throw new ArgumentNullException(nameof(adbClient));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <inheritdoc />
    public async Task<string?> GetPropAsync(
        string serial,
        string property,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(serial);
        ArgumentException.ThrowIfNullOrWhiteSpace(property);

        _logger.LogDebug("GetProp [{Serial}] {Property}", serial, property);

        AdbResult result;
        try
        {
            result = await _adbClient.ExecuteAsync(
                serial: serial,
                arguments: $"shell getprop {property}",
                timeout: GetPropTimeout,
                cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogWarning(ex, "GetProp: Exception for [{Serial}] {Property}", serial, property);
            return null;
        }

        if (result.TimedOut)
        {
            _logger.LogWarning("GetProp: Timed out for [{Serial}] {Property}", serial, property);
            return null;
        }

        if (result.ExitCode != 0)
        {
            _logger.LogWarning(
                "GetProp: ExitCode={ExitCode} for [{Serial}] {Property}, StdErr={StdErr}",
                result.ExitCode, serial, property, result.StdErr);
            return null;
        }

        if (!string.IsNullOrEmpty(result.StdErr))
        {
            _logger.LogWarning(
                "GetProp: StdErr present for [{Serial}] {Property}: {StdErr}",
                serial, property, result.StdErr);
        }

        return NullIfEmpty(result.StdOut);
    }

    /// <inheritdoc />
    public async Task<DeviceInfo> GetDeviceInfoAsync(
        string serial,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(serial);

        _logger.LogDebug("GetDeviceInfo [{Serial}]", serial);

        // Fetch all required properties concurrently
        var manufacturerTask  = GetPropAsync(serial, "ro.product.manufacturer",     cancellationToken);
        var modelTask         = GetPropAsync(serial, "ro.product.model",             cancellationToken);
        var deviceTask        = GetPropAsync(serial, "ro.product.device",            cancellationToken);
        var androidTask       = GetPropAsync(serial, "ro.build.version.release",     cancellationToken);
        var sdkTask           = GetPropAsync(serial, "ro.build.version.sdk",         cancellationToken);
        var securityPatchTask = GetPropAsync(serial, "ro.build.version.security_patch", cancellationToken);

        await Task.WhenAll(
            manufacturerTask, modelTask, deviceTask,
            androidTask, sdkTask, securityPatchTask).ConfigureAwait(false);

        var info = new DeviceInfo(
            Serial:        serial,
            Manufacturer:  await manufacturerTask,
            Model:         await modelTask,
            Device:        await deviceTask,
            AndroidVersion: await androidTask,
            SdkVersion:    await sdkTask,
            SecurityPatch: await securityPatchTask);

        _logger.LogInformation(
            "GetDeviceInfo [{Serial}]: {Manufacturer} {Model} Android={Android} SDK={SDK}",
            serial, info.Manufacturer, info.Model, info.AndroidVersion, info.SdkVersion);

        return info;
    }

    private static string? NullIfEmpty(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        var trimmed = value.Trim();
        return trimmed.Length == 0 ? null : trimmed;
    }
}
