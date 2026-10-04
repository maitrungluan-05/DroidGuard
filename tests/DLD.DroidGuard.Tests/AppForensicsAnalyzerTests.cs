using DLD.DroidGuard.Core.Models;
using DLD.DroidGuard.Infrastructure;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Xunit;

namespace DLD.DroidGuard.Tests;

public class AppForensicsAnalyzerTests
{
    [Fact]
    public async Task AnalyzeAsync_ExtractsDebuggableAndSdkFlags()
    {
        var mockAdb = new Mock<DLD.DroidGuard.Core.Abstractions.IAdbClient>();
        var analyzer = new AppForensicsAnalyzer(mockAdb.Object, NullLogger<AppForensicsAnalyzer>.Instance);

        var app = new AndroidApp
        {
            PackageName = "com.example.forensicapp",
            IsDebuggable = true,
            AllowBackup = true,
            TargetSdk = 34,
            MinSdk = 26,
            Signatures = new[] { "A1B2C3D4E5F6" }
        };

        var report = await analyzer.AnalyzeAsync("serial-123", app);

        Assert.NotNull(report);
        Assert.True(report.IsDebuggable);
        Assert.True(report.AllowBackup);
        Assert.Equal(34, report.TargetSdk);
        Assert.Equal(26, report.MinSdk);
        Assert.Contains(report.Evidence, e => e.Contains("DEBUGGABLE"));
        Assert.Contains(report.Evidence, e => e.Contains("ALLOW_BACKUP"));
        Assert.Contains(report.Evidence, e => e.Contains("A1B2C3D4E5F6"));
    }
}
