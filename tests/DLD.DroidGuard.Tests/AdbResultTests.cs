using DLD.DroidGuard.Core.Models;
using Xunit;

namespace DLD.DroidGuard.Tests;

public class AdbResultTests
{
    [Fact]
    public void IsSuccess_ZeroExitCodeAndNotTimedOut_ReturnsTrue()
    {
        var result = new AdbResult(0, "stdout", "", false, TimeSpan.FromMilliseconds(100));
        Assert.True(result.IsSuccess);
    }

    [Fact]
    public void IsSuccess_NonZeroExitCode_ReturnsFalse()
    {
        var result = new AdbResult(1, "", "error", false, TimeSpan.FromMilliseconds(100));
        Assert.False(result.IsSuccess);
    }

    [Fact]
    public void IsSuccess_TimedOut_ReturnsFalse()
    {
        var result = new AdbResult(0, "", "", true, TimeSpan.FromSeconds(5));
        Assert.False(result.IsSuccess);
    }
}
