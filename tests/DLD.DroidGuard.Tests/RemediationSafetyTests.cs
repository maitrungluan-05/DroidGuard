using DLD.DroidGuard.Core.Models;
using DLD.DroidGuard.Core.Risk;
using DLD.DroidGuard.Infrastructure;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Xunit;

namespace DLD.DroidGuard.Tests;

public class RemediationSafetyTests
{
    [Fact]
    public void SafetyPolicy_BlocksUninstallOfCriticalSystemPackages()
    {
        var systemUi = new AndroidApp
        {
            PackageName = "com.android.systemui",
            Origin = AppOrigin.System
        };

        var (isAllowed, reason, _) = RemediationSafetyPolicy.Evaluate(systemUi, RemediationAction.Uninstall);

        Assert.False(isAllowed);
        Assert.NotNull(reason);
        Assert.Contains("critical Android OS core package", reason);
    }

    [Fact]
    public void SafetyPolicy_BlocksUninstallOfSystemApps()
    {
        var systemApp = new AndroidApp
        {
            PackageName = "com.google.android.youtube",
            Origin = AppOrigin.System
        };

        var (isAllowed, reason, _) = RemediationSafetyPolicy.Evaluate(systemApp, RemediationAction.Uninstall);

        Assert.False(isAllowed);
        Assert.NotNull(reason);
        Assert.Contains("System package", reason);
    }

    [Fact]
    public void SafetyPolicy_WarnsOnLauncherAppUninstall()
    {
        var launcherUserApp = new AndroidApp
        {
            PackageName = "com.example.customlauncher",
            Origin = AppOrigin.User,
            HasLauncherActivity = true
        };

        var (isAllowed, reason, isWarningOnly) = RemediationSafetyPolicy.Evaluate(launcherUserApp, RemediationAction.Uninstall);

        Assert.True(isAllowed);
        Assert.True(isWarningOnly);
        Assert.NotNull(reason);
        Assert.Contains("Warning", reason);
    }

    [Fact]
    public void SafetyPolicy_AllowsUninstallOfUserApp()
    {
        var userApp = new AndroidApp
        {
            PackageName = "com.user.sampleapp",
            Origin = AppOrigin.User,
            HasLauncherActivity = true
        };

        var (isAllowed, _, isWarningOnly) = RemediationSafetyPolicy.Evaluate(userApp, RemediationAction.Uninstall);

        Assert.True(isAllowed);
    }

    [Fact]
    public async Task RemediationService_DryRun_GeneratesCommandWithoutExecution()
    {
        var mockAdb = new Moq.Mock<DLD.DroidGuard.Core.Abstractions.IAdbClient>();
        var service = new AppRemediationService(mockAdb.Object, NullLogger<AppRemediationService>.Instance);

        var userApp = new AndroidApp
        {
            PackageName = "com.user.sampleapp",
            Origin = AppOrigin.User
        };

        var result = await service.ExecuteActionAsync("device-123", userApp, RemediationAction.Uninstall, dryRun: true);

        Assert.True(result.Success);
        Assert.True(result.IsDryRun);
        Assert.False(result.IsBlockedBySafety);
        Assert.Equal("adb -s device-123 shell pm uninstall --user 0 com.user.sampleapp", result.Command);

        // ADB client should NEVER be called during DRY RUN
        mockAdb.Verify(a => a.ExecuteAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<TimeSpan>(), It.IsAny<CancellationToken>()), Times.Never);
    }
}
