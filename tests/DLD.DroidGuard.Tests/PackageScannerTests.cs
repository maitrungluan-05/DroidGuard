using DLD.DroidGuard.Adb;
using DLD.DroidGuard.Core.Abstractions;
using DLD.DroidGuard.Core.Models;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Xunit;

namespace DLD.DroidGuard.Tests;

public class PackageScannerTests
{
    private readonly Mock<IAdbClient> _adbClientMock = new();
    private readonly PackageScanner _scanner;

    public PackageScannerTests()
    {
        _scanner = new PackageScanner(_adbClientMock.Object, NullLogger<PackageScanner>.Instance);
    }

    [Fact]
    public async Task ScanAsync_EmptySerial_ReturnsFailedResult()
    {
        var result = await _scanner.ScanAsync("", CancellationToken.None);

        Assert.Equal(ScanStatus.Failed, result.Status);
        Assert.Single(result.Errors);
        Assert.Empty(result.Apps);
    }

    [Fact]
    public async Task ScanAsync_SuccessfulScan_CombinesMetadataAndLauncherState()
    {
        var serial = "SERIAL123";

        var listOutput = "package:/data/app/app1.apk=com.user.app\n" +
                         "package:/system/app/sys1.apk=com.system.app\n";

        var dumpsysOutput = @"
  Package [com.user.app] (1):
    versionName=1.0.0
    versionCode=100
    userId=10050
    codePath=/data/app/app1.apk
    pkgFlags=[ HAS_CODE ]
    enabledSetting=ENABLED
    installerPackageName=com.android.vending

  Package [com.system.app] (2):
    versionName=2.0.0
    versionCode=200
    userId=10001
    codePath=/system/app/sys1.apk
    pkgFlags=[ SYSTEM HAS_CODE ]
    enabledSetting=ENABLED
";

        var launcherOutput = @"
Priority: 0
  com.user.app/com.user.app.MainActivity
";

        _adbClientMock
            .Setup(c => c.ExecuteAsync(serial, "shell pm list packages -f", It.IsAny<TimeSpan>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AdbResult(0, listOutput, "", false, TimeSpan.FromMilliseconds(50)));

        _adbClientMock
            .Setup(c => c.ExecuteAsync(serial, "shell dumpsys package", It.IsAny<TimeSpan>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AdbResult(0, dumpsysOutput, "", false, TimeSpan.FromMilliseconds(100)));

        _adbClientMock
            .Setup(c => c.ExecuteAsync(serial, "shell cmd package query-activities --brief -a android.intent.action.MAIN -c android.intent.category.LAUNCHER", It.IsAny<TimeSpan>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AdbResult(0, launcherOutput, "", false, TimeSpan.FromMilliseconds(50)));

        var result = await _scanner.ScanAsync(serial, CancellationToken.None);

        Assert.Equal(ScanStatus.Success, result.Status);
        Assert.Equal(2, result.Apps.Count);

        var userApp = result.Apps.First(a => a.PackageName == "com.user.app");
        Assert.Equal(AppOrigin.User, userApp.Origin);
        Assert.False(userApp.IsSystemApp);
        Assert.Equal("1.0.0", userApp.VersionName);
        Assert.Equal(100L, userApp.VersionCode);
        Assert.Equal(10050, userApp.Uid);
        Assert.True(userApp.IsEnabled);
        Assert.True(userApp.HasLauncherActivity);
        Assert.Equal("com.android.vending", userApp.InstallerPackage);

        var sysApp = result.Apps.First(a => a.PackageName == "com.system.app");
        Assert.Equal(AppOrigin.System, sysApp.Origin);
        Assert.True(sysApp.IsSystemApp);
        Assert.Equal("2.0.0", sysApp.VersionName);
        Assert.False(sysApp.HasLauncherActivity); // Verified to NOT be in launcher list

        Assert.NotNull(result.Capability);
        Assert.True(result.Capability.ListPackagesSupported);
        Assert.True(result.Capability.DumpsysPackageSupported);
        Assert.True(result.Capability.LauncherQuerySupported);
    }

    [Fact]
    public async Task ScanAsync_TargetingDeviceSerial_AppliesSerialToAllAdbCommands()
    {
        var targetSerial = "SPECIFIC_DEVICE_SERIAL";

        _adbClientMock
            .Setup(c => c.ExecuteAsync(targetSerial, "shell pm list packages -f", It.IsAny<TimeSpan>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AdbResult(0, "package:/data/app/test.apk=com.test.pkg\n", "", false, TimeSpan.FromMilliseconds(10)));

        _adbClientMock
            .Setup(c => c.ExecuteAsync(targetSerial, "shell dumpsys package", It.IsAny<TimeSpan>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AdbResult(0, "", "", false, TimeSpan.FromMilliseconds(10)));

        _adbClientMock
            .Setup(c => c.ExecuteAsync(targetSerial, It.Is<string>(s => s.Contains("query-activities")), It.IsAny<TimeSpan>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AdbResult(0, "", "", false, TimeSpan.FromMilliseconds(10)));

        var result = await _scanner.ScanAsync(targetSerial, CancellationToken.None);

        Assert.Single(result.Apps);
        Assert.Equal("com.test.pkg", result.Apps[0].PackageName);

        // Verify serial parameter was passed on all calls
        _adbClientMock.Verify(c => c.ExecuteAsync(targetSerial, It.IsAny<string>(), It.IsAny<TimeSpan>(), It.IsAny<CancellationToken>()), Times.AtLeast(2));
    }

    [Fact]
    public async Task ScanAsync_UnsupportedLauncherQuery_SetsHasLauncherActivityToNull()
    {
        var serial = "SERIAL_OLD_ANDROID";

        _adbClientMock
            .Setup(c => c.ExecuteAsync(serial, "shell pm list packages -f", It.IsAny<TimeSpan>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AdbResult(0, "package:/data/app/app.apk=com.example.app\n", "", false, TimeSpan.FromMilliseconds(10)));

        _adbClientMock
            .Setup(c => c.ExecuteAsync(serial, "shell dumpsys package", It.IsAny<TimeSpan>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AdbResult(0, "", "", false, TimeSpan.FromMilliseconds(10)));

        // Primary launcher query fails/unsupported
        _adbClientMock
            .Setup(c => c.ExecuteAsync(serial, "shell cmd package query-activities --brief -a android.intent.action.MAIN -c android.intent.category.LAUNCHER", It.IsAny<TimeSpan>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AdbResult(1, "", "Unknown command: query-activities", false, TimeSpan.FromMilliseconds(10)));

        // Fallback launcher query also fails
        _adbClientMock
            .Setup(c => c.ExecuteAsync(serial, "shell pm query-intent-activities -a android.intent.action.MAIN -c android.intent.category.LAUNCHER", It.IsAny<TimeSpan>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AdbResult(1, "", "Error", false, TimeSpan.FromMilliseconds(10)));

        var result = await _scanner.ScanAsync(serial, CancellationToken.None);

        Assert.Single(result.Apps);
        Assert.Null(result.Apps[0].HasLauncherActivity); // Must be null, NOT false!
        Assert.NotNull(result.Capability);
        Assert.False(result.Capability.LauncherQuerySupported);
    }

    [Fact]
    public async Task ScanAsync_Cancellation_ReturnsCancelledStatus()
    {
        var serial = "SERIAL_CANCEL";
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        _adbClientMock
            .Setup(c => c.ExecuteAsync(serial, It.IsAny<string>(), It.IsAny<TimeSpan>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new OperationCanceledException());

        var result = await _scanner.ScanAsync(serial, cts.Token);

        Assert.Equal(ScanStatus.Cancelled, result.Status);
    }
}
