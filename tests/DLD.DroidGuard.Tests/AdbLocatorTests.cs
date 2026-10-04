using DLD.DroidGuard.Adb;
using DLD.DroidGuard.Core.Exceptions;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace DLD.DroidGuard.Tests;

public class AdbLocatorTests
{
    [Fact]
    public void TryLocate_NonExistentConfiguredPath_ReturnsNullOrFallback()
    {
        var locator = new AdbLocator(NullLogger<AdbLocator>.Instance, @"C:\NonExistentPath\adb.exe");
        // Unless adb is on PATH or bundled, this will return null or PATH result.
        var path = locator.TryLocate();
        if (path is not null)
        {
            Assert.True(File.Exists(path));
        }
    }

    [Fact]
    public void Locate_WhenNotFound_ThrowsAdbNotFoundException()
    {
        // Give a bogus PATH and non-existent configured path
        var originalPath = Environment.GetEnvironmentVariable("PATH");
        try
        {
            Environment.SetEnvironmentVariable("PATH", @"C:\EmptyDirectoryForTesting12345");
            var locator = new AdbLocator(NullLogger<AdbLocator>.Instance, @"C:\NonExistentPath\adb.exe");

            // Check if bundled adb.exe happens to exist in AppContext.BaseDirectory
            var appDir = AppContext.BaseDirectory;
            var bundled = Path.Combine(appDir, "adb.exe");
            var platformTools = Path.Combine(appDir, "platform-tools", "adb.exe");

            if (!File.Exists(bundled) && !File.Exists(platformTools))
            {
                Assert.Throws<AdbNotFoundException>(() => locator.Locate());
            }
        }
        finally
        {
            Environment.SetEnvironmentVariable("PATH", originalPath);
        }
    }
}
