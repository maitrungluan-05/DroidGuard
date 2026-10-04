using DLD.DroidGuard.Core.Models;
using DLD.DroidGuard.Infrastructure;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Xunit;

namespace DLD.DroidGuard.Tests;

public class CommandSafetyTests
{
    [Fact]
    public async Task ExecuteActionAsync_RejectsMaliciousPackageNameInjection()
    {
        var mockAdb = new Mock<DLD.DroidGuard.Core.Abstractions.IAdbClient>();
        var remediationService = new AppRemediationService(mockAdb.Object, NullLogger<AppRemediationService>.Instance);

        var maliciousApp = new AndroidApp
        {
            PackageName = "com.normal.app; pm uninstall --user 0 android"
        };

        var result = await remediationService.ExecuteActionAsync("device-123", maliciousApp, RemediationAction.Uninstall, dryRun: false);

        Assert.False(result.Success);
        Assert.True(result.IsBlockedBySafety);
        Assert.Contains("Command safety check failed", result.Error);

        // ADB Client should NEVER be invoked on unsafe string injection attempt
        mockAdb.Verify(a => a.ExecuteAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<TimeSpan>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task PreflightCheck_AbortsIfPackageMissingOnDevice()
    {
        var mockAdb = new Mock<DLD.DroidGuard.Core.Abstractions.IAdbClient>();
        // Mock preflight command "shell pm path com.user.app" returning failure / package not found
        mockAdb.Setup(a => a.ExecuteAsync(It.IsAny<string>(), It.Is<string>(s => s.Contains("pm path")), It.IsAny<TimeSpan>(), It.IsAny<CancellationToken>()))
               .ReturnsAsync(new AdbResult(1, string.Empty, "Error: package not found", false, TimeSpan.FromMilliseconds(50)));

        var remediationService = new AppRemediationService(mockAdb.Object, NullLogger<AppRemediationService>.Instance);

        var userApp = new AndroidApp
        {
            PackageName = "com.user.app",
            Origin = AppOrigin.User
        };

        var result = await remediationService.ExecuteActionAsync("device-123", userApp, RemediationAction.Uninstall, dryRun: false);

        Assert.False(result.Success);
        Assert.True(result.IsBlockedBySafety);
        Assert.Contains("Preflight verification failed", result.Error);
    }
}
