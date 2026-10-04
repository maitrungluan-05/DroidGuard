using DLD.DroidGuard.Adb;
using DLD.DroidGuard.Core.Abstractions;
using DLD.DroidGuard.Core.Models;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Xunit;

namespace DLD.DroidGuard.Tests;

public class DeviceInfoServiceTests
{
    private readonly Mock<IAdbClient> _adbClientMock = new();
    private readonly DeviceInfoService _service;

    public DeviceInfoServiceTests()
    {
        _service = new DeviceInfoService(_adbClientMock.Object, NullLogger<DeviceInfoService>.Instance);
    }

    [Fact]
    public async Task GetPropAsync_SuccessfulOutput_ReturnsTrimmedValue()
    {
        _adbClientMock
            .Setup(c => c.ExecuteAsync("SERIAL1", "shell getprop ro.product.manufacturer", It.IsAny<TimeSpan>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AdbResult(0, "  Samsung  \n", "", false, TimeSpan.FromMilliseconds(50)));

        var result = await _service.GetPropAsync("SERIAL1", "ro.product.manufacturer", CancellationToken.None);

        Assert.Equal("Samsung", result);
    }

    [Fact]
    public async Task GetPropAsync_EmptyOutput_ReturnsNull()
    {
        _adbClientMock
            .Setup(c => c.ExecuteAsync("SERIAL1", "shell getprop ro.nonexistent", It.IsAny<TimeSpan>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AdbResult(0, "\n", "", false, TimeSpan.FromMilliseconds(50)));

        var result = await _service.GetPropAsync("SERIAL1", "ro.nonexistent", CancellationToken.None);

        Assert.Null(result);
    }

    [Fact]
    public async Task GetPropAsync_NonZeroExitCode_ReturnsNull()
    {
        _adbClientMock
            .Setup(c => c.ExecuteAsync("SERIAL1", "shell getprop error.prop", It.IsAny<TimeSpan>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AdbResult(1, "", "error occurred", false, TimeSpan.FromMilliseconds(50)));

        var result = await _service.GetPropAsync("SERIAL1", "error.prop", CancellationToken.None);

        Assert.Null(result);
    }

    [Fact]
    public async Task GetPropAsync_Timeout_ReturnsNull()
    {
        _adbClientMock
            .Setup(c => c.ExecuteAsync("SERIAL1", "shell getprop timeout.prop", It.IsAny<TimeSpan>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AdbResult(-1, "", "", true, TimeSpan.FromSeconds(10)));

        var result = await _service.GetPropAsync("SERIAL1", "timeout.prop", CancellationToken.None);

        Assert.Null(result);
    }

    [Fact]
    public async Task GetDeviceInfoAsync_ReadsAllPropertiesConcurrently()
    {
        SetupProp("ro.product.manufacturer", "Xiaomi");
        SetupProp("ro.product.model", "2201116SG");
        SetupProp("ro.product.device", "viva");
        SetupProp("ro.build.version.release", "13");
        SetupProp("ro.build.version.sdk", "33");
        SetupProp("ro.build.version.security_patch", "2023-11-01");

        var info = await _service.GetDeviceInfoAsync("SERIAL123", CancellationToken.None);

        Assert.Equal("SERIAL123", info.Serial);
        Assert.Equal("Xiaomi", info.Manufacturer);
        Assert.Equal("2201116SG", info.Model);
        Assert.Equal("viva", info.Device);
        Assert.Equal("13", info.AndroidVersion);
        Assert.Equal("33", info.SdkVersion);
        Assert.Equal("2023-11-01", info.SecurityPatch);
    }

    [Fact]
    public async Task GetDeviceInfoAsync_UnicodeOutput_HandlesCorrectly()
    {
        SetupProp("ro.product.manufacturer", "Công Ty TNHH Việt Nam");
        SetupProp("ro.product.model", "Mẫu Mới 2026");
        SetupProp("ro.product.device", "ThiếtBị");
        SetupProp("ro.build.version.release", "14");
        SetupProp("ro.build.version.sdk", "34");
        SetupProp("ro.build.version.security_patch", "2024-01-01");

        var info = await _service.GetDeviceInfoAsync("VN_SERIAL", CancellationToken.None);

        Assert.Equal("Công Ty TNHH Việt Nam", info.Manufacturer);
        Assert.Equal("Mẫu Mới 2026", info.Model);
    }

    private void SetupProp(string prop, string value)
    {
        _adbClientMock
            .Setup(c => c.ExecuteAsync("SERIAL123", $"shell getprop {prop}", It.IsAny<TimeSpan>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AdbResult(0, value + "\n", "", false, TimeSpan.FromMilliseconds(10)));

        _adbClientMock
            .Setup(c => c.ExecuteAsync("VN_SERIAL", $"shell getprop {prop}", It.IsAny<TimeSpan>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AdbResult(0, value + "\n", "", false, TimeSpan.FromMilliseconds(10)));
    }
}
