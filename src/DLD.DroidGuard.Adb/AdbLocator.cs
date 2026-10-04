using DLD.DroidGuard.Core.Abstractions;
using DLD.DroidGuard.Core.Exceptions;
using Microsoft.Extensions.Logging;

namespace DLD.DroidGuard.Adb;

/// <summary>
/// Locates the ADB executable using three strategies in priority order:
/// 1. Configured path
/// 2. Bundled adb.exe (beside the application executable)
/// 3. PATH environment variable
/// </summary>
public sealed class AdbLocator : IAdbLocator
{
    private const string AdbExecutableName = "adb.exe";

    private readonly string? _configuredPath;
    private readonly ILogger<AdbLocator> _logger;

    public AdbLocator(ILogger<AdbLocator> logger, string? configuredPath = null)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _configuredPath = configuredPath;
    }

    /// <inheritdoc />
    public string? TryLocate()
    {
        // Strategy 1: Configured path
        if (!string.IsNullOrWhiteSpace(_configuredPath))
        {
            _logger.LogDebug("ADB: Checking configured path: {Path}", _configuredPath);
            if (File.Exists(_configuredPath))
            {
                _logger.LogInformation("ADB: Found at configured path: {Path}", _configuredPath);
                return _configuredPath;
            }
            _logger.LogWarning("ADB: Configured path does not exist: {Path}", _configuredPath);
        }

        // Strategy 2: Bundled beside the application executable
        var appDir = AppContext.BaseDirectory;
        var bundledPath = Path.Combine(appDir, AdbExecutableName);
        _logger.LogDebug("ADB: Checking bundled path: {Path}", bundledPath);
        if (File.Exists(bundledPath))
        {
            _logger.LogInformation("ADB: Found bundled at: {Path}", bundledPath);
            return bundledPath;
        }

        // Also check platform-tools sub-directory
        var platformToolsPath = Path.Combine(appDir, "platform-tools", AdbExecutableName);
        _logger.LogDebug("ADB: Checking platform-tools path: {Path}", platformToolsPath);
        if (File.Exists(platformToolsPath))
        {
            _logger.LogInformation("ADB: Found in platform-tools: {Path}", platformToolsPath);
            return platformToolsPath;
        }

        // Strategy 3: PATH environment variable
        _logger.LogDebug("ADB: Searching PATH environment variable");
        var pathVariable = Environment.GetEnvironmentVariable("PATH") ?? string.Empty;
        foreach (var dir in pathVariable.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
        {
            var candidate = Path.Combine(dir.Trim(), AdbExecutableName);
            if (File.Exists(candidate))
            {
                _logger.LogInformation("ADB: Found on PATH at: {Path}", candidate);
                return candidate;
            }
        }

        _logger.LogWarning("ADB: adb.exe not found via configured path, bundled location, or PATH.");
        return null;
    }

    /// <inheritdoc />
    public string Locate()
    {
        var path = TryLocate();
        if (path is null)
            throw new AdbNotFoundException();
        return path;
    }
}
