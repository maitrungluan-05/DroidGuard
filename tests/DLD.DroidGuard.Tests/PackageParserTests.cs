using DLD.DroidGuard.Adb;
using DLD.DroidGuard.Core.Models;
using Xunit;

namespace DLD.DroidGuard.Tests;

public class PackageParserTests
{
    private readonly PackageListParser _listParser = new();
    private readonly DumpsysPackageParser _dumpsysParser = new();
    private readonly LauncherQueryParser _launcherParser = new();

    #region PackageListParser Tests

    [Fact]
    public void PackageListParser_EmptyOrWhitespace_ReturnsEmptyList()
    {
        Assert.Empty(_listParser.Parse(""));
        Assert.Empty(_listParser.Parse("   \r\n\t "));
    }

    [Fact]
    public void PackageListParser_HeaderOnly_ReturnsEmptyList()
    {
        var output = "package:\n";
        Assert.Empty(_listParser.Parse(output));
    }

    [Fact]
    public void PackageListParser_OnePackage_ParsesPathAndName()
    {
        var output = "package:/data/app/~~abc==/com.example.app-xyz==/base.apk=com.example.app\n";
        var result = _listParser.Parse(output);

        Assert.Single(result);
        Assert.Equal("com.example.app", result[0].PackageName);
        Assert.Equal("/data/app/~~abc==/com.example.app-xyz==/base.apk", result[0].ApkPath);
    }

    [Fact]
    public void PackageListParser_MultiplePackagesAndAppTypes_ParsesAll()
    {
        var output = "package:/system/app/Calendar/Calendar.apk=com.android.calendar\n" +
                     "package:/system/priv-app/Settings/Settings.apk=com.android.settings\n" +
                     "package:/product/app/YouTube/YouTube.apk=com.google.android.youtube\n" +
                     "package:/data/app/viva.apk=com.user.app\n";

        var result = _listParser.Parse(output);

        Assert.Equal(4, result.Count);
        Assert.Equal("com.android.calendar", result[0].PackageName);
        Assert.Equal("/system/app/Calendar/Calendar.apk", result[0].ApkPath);
        Assert.Equal("com.android.settings", result[1].PackageName);
        Assert.Equal("/system/priv-app/Settings/Settings.apk", result[1].ApkPath);
        Assert.Equal("com.google.android.youtube", result[2].PackageName);
        Assert.Equal("/product/app/YouTube/YouTube.apk", result[2].ApkPath);
        Assert.Equal("com.user.app", result[3].PackageName);
    }

    [Fact]
    public void PackageListParser_PackageWithoutPath_ParsesPackageNameOnly()
    {
        var output = "package:com.example.nopath\n";
        var result = _listParser.Parse(output);

        Assert.Single(result);
        Assert.Equal("com.example.nopath", result[0].PackageName);
        Assert.Null(result[0].ApkPath);
    }

    [Fact]
    public void PackageListParser_MalformedLinesAndUnexpectedSpacing_IgnoresInvalidLines()
    {
        var output = "  package:/data/app/test.apk=com.valid.app  \r\n" +
                     "random error text from adb\r\n" +
                     "package:\r\n" +
                     "package:=invalidformat\r\n" +
                     "package:com.another.valid\r\n";

        var result = _listParser.Parse(output);

        Assert.Equal(2, result.Count);
        Assert.Equal("com.valid.app", result[0].PackageName);
        Assert.Equal("com.another.valid", result[1].PackageName);
    }

    [Fact]
    public void PackageListParser_UnicodeTextInPath_ParsesSuccessfully()
    {
        var output = "package:/data/app/ỨngDụngViệt.apk=com.vietnam.app\n";
        var result = _listParser.Parse(output);

        Assert.Single(result);
        Assert.Equal("com.vietnam.app", result[0].PackageName);
        Assert.Equal("/data/app/ỨngDụngViệt.apk", result[0].ApkPath);
    }

    #endregion

    #region DumpsysPackageParser Tests

    [Fact]
    public void DumpsysPackageParser_EmptyOutput_ReturnsEmptyDictionary()
    {
        var result = _dumpsysParser.Parse("");
        Assert.Empty(result);
    }

    [Fact]
    public void DumpsysPackageParser_NormalUserPackage_ExtractsAllFields()
    {
        var sample = @"
Packages:
  Package [com.example.userapp] (a1b2c3d):
    userId=10188
    pkg=Package{112233 com.example.userapp}
    codePath=/data/app/com.example.userapp-1/base.apk
    resourcePath=/data/app/com.example.userapp-1/base.apk
    versionCode=102030 minSdk=26 targetSdk=33
    versionName=2.1.0
    pkgFlags=[ HAS_CODE ALLOW_CLEAR_USER_DATA ]
    firstInstallTime=2023-01-15 12:00:00
    lastUpdateTime=2023-06-20 15:30:00
    installerPackageName=com.android.vending
    enabledSetting=ENABLED
";

        var dict = _dumpsysParser.Parse(sample);
        Assert.Single(dict);
        Assert.True(dict.ContainsKey("com.example.userapp"));

        var meta = dict["com.example.userapp"];
        Assert.Equal("com.example.userapp", meta.PackageName);
        Assert.Equal("2.1.0", meta.VersionName);
        Assert.Equal(102030L, meta.VersionCode);
        Assert.Equal(10188, meta.Uid);
        Assert.Equal("/data/app/com.example.userapp-1/base.apk", meta.ApkPath);
        Assert.Equal(AppOrigin.User, meta.Origin);
        Assert.True(meta.IsEnabled);
        Assert.Equal("com.android.vending", meta.InstallerPackage);
        Assert.NotNull(meta.FirstInstallTime);
        Assert.NotNull(meta.LastUpdateTime);
    }

    [Fact]
    public void DumpsysPackageParser_SystemAppWithDisabledState_ParsesSystemOriginAndDisabled()
    {
        var sample = @"
  Package [com.android.bloatware] (778899):
    appId=10012
    codePath=/system/app/Bloatware/Bloatware.apk
    versionCode=1
    versionName=1.0
    pkgFlags=[ SYSTEM HAS_CODE ]
    enabledSetting=DISABLED_USER
    installerPackageName=null
";

        var dict = _dumpsysParser.Parse(sample);
        var meta = dict["com.android.bloatware"];

        Assert.Equal(AppOrigin.System, meta.Origin);
        Assert.False(meta.IsEnabled);
        Assert.Null(meta.InstallerPackage);
    }

    [Fact]
    public void DumpsysPackageParser_MissingFields_ReturnsNullForMissingFields()
    {
        var sample = @"
  Package [com.minimal.app] (12345):
    codePath=/data/app/minimal.apk
";

        var dict = _dumpsysParser.Parse(sample);
        var meta = dict["com.minimal.app"];

        Assert.Equal("com.minimal.app", meta.PackageName);
        Assert.Null(meta.VersionName);
        Assert.Null(meta.VersionCode);
        Assert.Null(meta.Uid);
        Assert.Equal(AppOrigin.Unknown, meta.Origin);
        Assert.Null(meta.IsEnabled);
        Assert.Null(meta.InstallerPackage);
        Assert.Null(meta.FirstInstallTime);
        Assert.Null(meta.LastUpdateTime);
    }

    [Fact]
    public void DumpsysPackageParser_UnicodeVersionName_ParsesCorrectly()
    {
        var sample = @"
  Package [com.vn.app] (abc):
    versionName=2.0 (Phiên Bản Việt)
    versionCode=200
    pkgFlags=[ HAS_CODE ]
";

        var dict = _dumpsysParser.Parse(sample);
        Assert.Equal("2.0 (Phiên Bản Việt)", dict["com.vn.app"].VersionName);
    }

    #endregion

    #region LauncherQueryParser Tests

    [Fact]
    public void LauncherQueryParser_CmdPackageOutput_ParsesLauncherSet()
    {
        var output = @"
Priority: 0
  com.example.app/com.example.app.MainActivity
  com.android.settings/.Settings
";

        var set = _launcherParser.Parse(output);
        Assert.NotNull(set);
        Assert.Equal(2, set.Count);
        Assert.Contains("com.example.app", set);
        Assert.Contains("com.android.settings", set);
    }

    [Fact]
    public void LauncherQueryParser_NoLauncherResults_ReturnsEmptySet()
    {
        var output = "Priority: 0\n";
        var set = _launcherParser.Parse(output);

        Assert.NotNull(set);
        Assert.Empty(set);
    }

    [Fact]
    public void LauncherQueryParser_UnsupportedCommand_ReturnsNull()
    {
        Assert.Null(_launcherParser.Parse("Unknown command: query-activities"));
        Assert.Null(_launcherParser.Parse("Error: Could not access package manager"));
    }

    #endregion
}
