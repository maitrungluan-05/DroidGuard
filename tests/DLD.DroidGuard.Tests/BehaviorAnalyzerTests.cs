using DLD.DroidGuard.Core.Models;
using DLD.DroidGuard.Infrastructure;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Xunit;

namespace DLD.DroidGuard.Tests;

public class BehaviorAnalyzerTests
{
    [Fact]
    public async Task AnalyzeAsync_RejectsUnsafePackageNameString()
    {
        var mockAdb = new Mock<DLD.DroidGuard.Core.Abstractions.IAdbClient>();
        var analyzer = new BehaviorAnalyzer(mockAdb.Object, NullLogger<BehaviorAnalyzer>.Instance);

        var unsafeApp = new AndroidApp
        {
            PackageName = "com.example.app; rm -rf /"
        };

        var report = await analyzer.AnalyzeAsync("serial-123", unsafeApp);

        Assert.False(report.IsComplete);
        Assert.Contains(report.Errors, e => e.Contains("Command safety validation failed"));
    }

    [Fact]
    public async Task AnalyzeAsync_ExecutesNonIntrusiveQueriesSafely()
    {
        var mockAdb = new Mock<DLD.DroidGuard.Core.Abstractions.IAdbClient>();
        mockAdb.Setup(a => a.ExecuteAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<TimeSpan>(), It.IsAny<CancellationToken>()))
               .ReturnsAsync(new AdbResult(0, string.Empty, string.Empty, false, TimeSpan.FromMilliseconds(50)));

        mockAdb.Setup(a => a.ExecuteAsync(It.IsAny<string>(), It.Is<string>(s => s.Contains("pidof")), It.IsAny<TimeSpan>(), It.IsAny<CancellationToken>()))
               .ReturnsAsync(new AdbResult(0, "1234 5678", string.Empty, false, TimeSpan.FromMilliseconds(50)));

        mockAdb.Setup(a => a.ExecuteAsync(It.IsAny<string>(), It.Is<string>(s => s.Contains("netstat")), It.IsAny<TimeSpan>(), It.IsAny<CancellationToken>()))
               .ReturnsAsync(new AdbResult(0, "tcp 0 0 192.168.1.50:45678 93.184.216.34:443 ESTABLISHED", string.Empty, false, TimeSpan.FromMilliseconds(50)));

        var analyzer = new BehaviorAnalyzer(mockAdb.Object, NullLogger<BehaviorAnalyzer>.Instance);

        var app = new AndroidApp
        {
            PackageName = "com.example.safeapp",
            Uid = 10123
        };

        var report = await analyzer.AnalyzeAsync("serial-123", app);

        Assert.True(report.IsComplete);
        Assert.NotEmpty(report.Processes);
        Assert.NotEmpty(report.NetworkIndicators);
        Assert.Equal("93.184.216.34", report.NetworkIndicators.First().DestinationIp);
    }
}
