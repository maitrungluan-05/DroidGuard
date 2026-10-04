using DLD.DroidGuard.Adb;
using DLD.DroidGuard.Core.Models;
using Xunit;

namespace DLD.DroidGuard.Tests;

public class AdbDevicesParserTests
{
    private readonly AdbDevicesParser _parser = new();

    [Fact]
    public void Parse_EmptyOrNullOutput_ReturnsEmptyList()
    {
        Assert.Empty(_parser.Parse(string.Empty));
        Assert.Empty(_parser.Parse("   \r\n  "));
    }

    [Fact]
    public void Parse_OnlyHeader_ReturnsEmptyList()
    {
        var output = "List of devices attached\n";
        Assert.Empty(_parser.Parse(output));
    }

    [Fact]
    public void Parse_SingleAuthorizedDevice_ParsesCorrectly()
    {
        var output = "List of devices attached\n" +
                     "1234567890ABCDEF    device product:sdk_gphone64_x86_64 model:sdk_gphone64_x86_64 device:emulator64_x86_64 transport_id:1\n";

        var devices = _parser.Parse(output);

        Assert.Single(devices);
        var dev = devices[0];
        Assert.Equal("1234567890ABCDEF", dev.Serial);
        Assert.Equal(AdbDeviceState.Device, dev.State);
        Assert.Equal("sdk_gphone64_x86_64", dev.Product);
        Assert.Equal("sdk_gphone64_x86_64", dev.Model);
        Assert.Equal("emulator64_x86_64", dev.Device);
    }

    [Fact]
    public void Parse_MultipleDevices_ParsesAll()
    {
        var output = "List of devices attached\n" +
                     "SERIAL1    device product:prod1 model:model1 device:dev1\n" +
                     "SERIAL2    offline\n" +
                     "SERIAL3    unauthorized\n";

        var devices = _parser.Parse(output);

        Assert.Equal(3, devices.Count);
        Assert.Equal("SERIAL1", devices[0].Serial);
        Assert.Equal(AdbDeviceState.Device, devices[0].State);
        Assert.Equal("SERIAL2", devices[1].Serial);
        Assert.Equal(AdbDeviceState.Offline, devices[1].State);
        Assert.Equal("SERIAL3", devices[2].Serial);
        Assert.Equal(AdbDeviceState.Unauthorized, devices[2].State);
    }

    [Fact]
    public void Parse_UnauthorizedDevice_ParsesCorrectly()
    {
        var output = "List of devices attached\n" +
                     "R58M123456X    unauthorized usb:1-1 product:star2ltexx model:SM_G965F device:star2lte\n";

        var devices = _parser.Parse(output);

        Assert.Single(devices);
        Assert.Equal("R58M123456X", devices[0].Serial);
        Assert.Equal(AdbDeviceState.Unauthorized, devices[0].State);
        Assert.Equal("star2ltexx", devices[0].Product);
        Assert.Equal("SM_G965F", devices[0].Model);
    }

    [Fact]
    public void Parse_OfflineDevice_ParsesCorrectly()
    {
        var output = "List of devices attached\n" +
                     "emulator-5554    offline\n";

        var devices = _parser.Parse(output);

        Assert.Single(devices);
        Assert.Equal("emulator-5554", devices[0].Serial);
        Assert.Equal(AdbDeviceState.Offline, devices[0].State);
        Assert.Null(devices[0].Product);
        Assert.Null(devices[0].Model);
        Assert.Null(devices[0].Device);
    }

    [Fact]
    public void Parse_UnknownState_ParsesAsUnknownState()
    {
        var output = "List of devices attached\n" +
                     "SOME_SERIAL    host\n";

        var devices = _parser.Parse(output);

        Assert.Single(devices);
        Assert.Equal("SOME_SERIAL", devices[0].Serial);
        Assert.Equal(AdbDeviceState.Unknown, devices[0].State);
    }

    [Fact]
    public void Parse_MalformedLines_IgnoresInvalidLines()
    {
        var output = "List of devices attached\n" +
                     "random text here without device state\n" +
                     "* daemon not running; starting now at tcp:5037\n" +
                     "* daemon started successfully\n" +
                     "VALID_SERIAL    device model:TestModel\n";

        var devices = _parser.Parse(output);

        Assert.Single(devices);
        Assert.Equal("VALID_SERIAL", devices[0].Serial);
        Assert.Equal(AdbDeviceState.Device, devices[0].State);
        Assert.Equal("TestModel", devices[0].Model);
    }

    [Fact]
    public void Parse_UnicodeModelName_ParsesUnicodeText()
    {
        var output = "List of devices attached\n" +
                     "VN123456    device product:Tiếng_Việt model:Điện_Thoại_Chính_Hãng device:TiếngViệt\n";

        var devices = _parser.Parse(output);

        Assert.Single(devices);
        Assert.Equal("VN123456", devices[0].Serial);
        Assert.Equal("Tiếng_Việt", devices[0].Product);
        Assert.Equal("Điện_Thoại_Chính_Hãng", devices[0].Model);
    }
}
