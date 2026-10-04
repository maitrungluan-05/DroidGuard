using System.Diagnostics;
using DLD.DroidGuard.Core.Abstractions;
using DLD.DroidGuard.Core.Models;
using Microsoft.Extensions.Logging;

namespace DLD.DroidGuard.Adb;

/// <summary>
/// Scans Android devices for installed package enumeration and metadata via ADB.
/// Version-tolerant for Android 8 through 15.
/// </summary>
public sealed class PackageScanner : IPackageScanner
{
    private static readonly TimeSpan ListPackagesTimeout = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan DumpsysTimeout = TimeSpan.FromSeconds(45);
    private static readonly TimeSpan LauncherQueryTimeout = TimeSpan.FromSeconds(20);

    private readonly IAdbClient _adbClient;
    private readonly ILogger<PackageScanner> _logger;

    private readonly PackageListParser _listParser = new();
    private readonly DumpsysPackageParser _dumpsysParser = new();
    private readonly LauncherQueryParser _launcherParser = new();

    public PackageScanner(IAdbClient adbClient, ILogger<PackageScanner> logger)
    {
        _adbClient = adbClient ?? throw new ArgumentNullException(nameof(adbClient));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <inheritdoc />
    public async Task<PackageScanResult> ScanAsync(string serial, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(serial))
        {
            return new PackageScanResult(
                Status: ScanStatus.Failed,
                Apps: Array.Empty<AndroidApp>(),
                Errors: new[] { "No target device serial provided." },
                Warnings: Array.Empty<string>(),
                Duration: TimeSpan.Zero,
                Capability: null);
        }

        _logger.LogInformation("PackageScanner: Starting scan for device [{Serial}]", serial);
        var sw = Stopwatch.StartNew();

        var errors = new List<string>();
        var warnings = new List<string>();

        bool listSupported = false;
        bool dumpsysSupported = false;
        bool launcherSupported = false;

        try
        {
            // --- Step 1: Package Enumeration ---
            cancellationToken.ThrowIfCancellationRequested();
            var (rawPackages, listSuccess) = await EnumeratedPackagesAsync(serial, warnings, cancellationToken).ConfigureAwait(false);
            listSupported = listSuccess;

            if (!listSuccess || rawPackages.Count == 0)
            {
                sw.Stop();
                errors.Add("Failed to enumerate packages from device.");
                _logger.LogWarning("PackageScanner [{Serial}]: Enumeration failed or returned 0 packages.", serial);

                return new PackageScanResult(
                    Status: ScanStatus.Failed,
                    Apps: Array.Empty<AndroidApp>(),
                    Errors: errors,
                    Warnings: warnings,
                    Duration: sw.Elapsed,
                    Capability: new ScanCapability(listSupported, dumpsysSupported, launcherSupported));
            }

            _logger.LogInformation("PackageScanner [{Serial}]: Enumerated {Count} packages", serial, rawPackages.Count);

            // --- Step 2: Dumpsys Package Metadata ---
            cancellationToken.ThrowIfCancellationRequested();
            IReadOnlyDictionary<string, ParsedPackageMeta> dumpsysMap = new Dictionary<string, ParsedPackageMeta>();
            try
            {
                var dumpsysResult = await _adbClient.ExecuteAsync(
                    serial: serial,
                    arguments: "shell dumpsys package",
                    timeout: DumpsysTimeout,
                    cancellationToken).ConfigureAwait(false);

                if (dumpsysResult.IsSuccess && !string.IsNullOrWhiteSpace(dumpsysResult.StdOut))
                {
                    dumpsysMap = _dumpsysParser.Parse(dumpsysResult.StdOut);
                    dumpsysSupported = dumpsysMap.Count > 0;
                    _logger.LogInformation("PackageScanner [{Serial}]: Dumpsys parsed metadata for {Count} packages", serial, dumpsysMap.Count);
                }
                else
                {
                    warnings.Add("dumpsys package command did not return detailed metadata.");
                    _logger.LogWarning("PackageScanner [{Serial}]: dumpsys package failed or timed out. ExitCode={Code}, TimedOut={TimedOut}",
                        serial, dumpsysResult.ExitCode, dumpsysResult.TimedOut);
                }
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex)
            {
                warnings.Add($"Error fetching dumpsys metadata: {ex.Message}");
                _logger.LogWarning(ex, "PackageScanner [{Serial}]: Exception during dumpsys package execution", serial);
            }

            // --- Step 3: Launcher Activity Query ---
            cancellationToken.ThrowIfCancellationRequested();
            HashSet<string>? launcherPackages = null;
            try
            {
                // Primary launcher query command
                var launcherResult = await _adbClient.ExecuteAsync(
                    serial: serial,
                    arguments: "shell cmd package query-activities --brief -a android.intent.action.MAIN -c android.intent.category.LAUNCHER",
                    timeout: LauncherQueryTimeout,
                    cancellationToken).ConfigureAwait(false);

                if (launcherResult.IsSuccess && !string.IsNullOrWhiteSpace(launcherResult.StdOut))
                {
                    launcherPackages = _launcherParser.Parse(launcherResult.StdOut);
                }

                // Fallback command if primary failed or was unsupported
                if (launcherPackages is null)
                {
                    var fallbackResult = await _adbClient.ExecuteAsync(
                        serial: serial,
                        arguments: "shell pm query-intent-activities -a android.intent.action.MAIN -c android.intent.category.LAUNCHER",
                        timeout: LauncherQueryTimeout,
                        cancellationToken).ConfigureAwait(false);

                    if (fallbackResult.IsSuccess && !string.IsNullOrWhiteSpace(fallbackResult.StdOut))
                    {
                        launcherPackages = _launcherParser.Parse(fallbackResult.StdOut);
                    }
                }

                launcherSupported = launcherPackages is not null;
                if (launcherSupported)
                {
                    _logger.LogInformation("PackageScanner [{Serial}]: Found {Count} launcher packages", serial, launcherPackages!.Count);
                }
                else
                {
                    warnings.Add("Launcher query is not supported on this device. HasLauncherActivity will be set to null.");
                    _logger.LogWarning("PackageScanner [{Serial}]: Launcher activity query unsupported", serial);
                }
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex)
            {
                warnings.Add($"Error querying launcher activities: {ex.Message}");
                _logger.LogWarning(ex, "PackageScanner [{Serial}]: Exception during launcher activity query", serial);
            }

            // --- Step 4: Assemble AndroidApp Models ---
            var apps = new List<AndroidApp>(rawPackages.Count);

            foreach (var raw in rawPackages)
            {
                dumpsysMap.TryGetValue(raw.PackageName, out var meta);

                // Determine ApkPath
                var apkPath = meta?.ApkPath ?? raw.ApkPath;

                // Determine AppOrigin
                var origin = meta?.Origin ?? AppOrigin.Unknown;
                if (origin == AppOrigin.Unknown && !string.IsNullOrEmpty(apkPath))
                {
                    origin = InferOriginFromPath(apkPath);
                }

                // Determine HasLauncherActivity
                bool? hasLauncher = null;
                if (launcherSupported && launcherPackages is not null)
                {
                    hasLauncher = launcherPackages.Contains(raw.PackageName);
                }

                var app = new AndroidApp
                {
                    PackageName = raw.PackageName,
                    Label = null, // Label extraction deferred to deep inspection if needed
                    VersionName = meta?.VersionName,
                    VersionCode = meta?.VersionCode,
                    Uid = meta?.Uid,
                    ApkPath = apkPath,
                    Origin = origin,
                    IsEnabled = meta?.IsEnabled,
                    HasLauncherActivity = hasLauncher,
                    InstallerPackage = meta?.InstallerPackage,
                    FirstInstallTime = meta?.FirstInstallTime,
                    LastUpdateTime = meta?.LastUpdateTime,
                    RequestedPermissions = meta?.RequestedPermissions ?? Array.Empty<string>(),
                    SharedUserId = meta?.SharedUserId,
                    TargetSdk = meta?.TargetSdk,
                    MinSdk = meta?.MinSdk,
                    IsDebuggable = meta?.IsDebuggable,
                    AllowBackup = meta?.AllowBackup,
                    Signatures = meta?.Signatures
                };

                apps.Add(app);
            }

            sw.Stop();
            var status = warnings.Count > 0 ? ScanStatus.Partial : ScanStatus.Success;
            var capability = new ScanCapability(listSupported, dumpsysSupported, launcherSupported);

            _logger.LogInformation("PackageScanner [{Serial}]: Completed scan in {Duration}ms with Status={Status}",
                serial, (int)sw.ElapsedMilliseconds, status);

            return new PackageScanResult(
                Status: status,
                Apps: apps,
                Errors: errors,
                Warnings: warnings,
                Duration: sw.Elapsed,
                Capability: capability);
        }
        catch (OperationCanceledException)
        {
            sw.Stop();
            _logger.LogInformation("PackageScanner [{Serial}]: Scan cancelled by user.", serial);
            return new PackageScanResult(
                Status: ScanStatus.Cancelled,
                Apps: Array.Empty<AndroidApp>(),
                Errors: new[] { "Package scan was cancelled." },
                Warnings: warnings,
                Duration: sw.Elapsed,
                Capability: new ScanCapability(listSupported, dumpsysSupported, launcherSupported));
        }
        catch (Exception ex)
        {
            sw.Stop();
            _logger.LogError(ex, "PackageScanner [{Serial}]: Scan failed due to exception", serial);
            errors.Add($"Scan failed: {ex.Message}");
            return new PackageScanResult(
                Status: ScanStatus.Failed,
                Apps: Array.Empty<AndroidApp>(),
                Errors: errors,
                Warnings: warnings,
                Duration: sw.Elapsed,
                Capability: new ScanCapability(listSupported, dumpsysSupported, launcherSupported));
        }
    }

    private async Task<(IReadOnlyList<RawPackageEntry> Packages, bool Success)> EnumeratedPackagesAsync(
        string serial,
        List<string> warnings,
        CancellationToken cancellationToken)
    {
        // Try "pm list packages -f"
        var result = await _adbClient.ExecuteAsync(
            serial: serial,
            arguments: "shell pm list packages -f",
            timeout: ListPackagesTimeout,
            cancellationToken).ConfigureAwait(false);

        if (result.IsSuccess && !string.IsNullOrWhiteSpace(result.StdOut))
        {
            var parsed = _listParser.Parse(result.StdOut);
            if (parsed.Count > 0)
                return (parsed, true);
        }

        // Fallback: "pm list packages"
        warnings.Add("pm list packages -f failed or returned empty; falling back to simple package list.");
        var fallbackResult = await _adbClient.ExecuteAsync(
            serial: serial,
            arguments: "shell pm list packages",
            timeout: ListPackagesTimeout,
            cancellationToken).ConfigureAwait(false);

        if (fallbackResult.IsSuccess && !string.IsNullOrWhiteSpace(fallbackResult.StdOut))
        {
            var parsedFallback = _listParser.Parse(fallbackResult.StdOut);
            if (parsedFallback.Count > 0)
                return (parsedFallback, true);
        }

        return (Array.Empty<RawPackageEntry>(), false);
    }

    private static AppOrigin InferOriginFromPath(string path)
    {
        if (path.StartsWith("/system/", StringComparison.OrdinalIgnoreCase) ||
            path.StartsWith("/product/", StringComparison.OrdinalIgnoreCase) ||
            path.StartsWith("/vendor/", StringComparison.OrdinalIgnoreCase) ||
            path.StartsWith("/system_ext/", StringComparison.OrdinalIgnoreCase) ||
            path.StartsWith("/apex/", StringComparison.OrdinalIgnoreCase) ||
            path.StartsWith("/oem/", StringComparison.OrdinalIgnoreCase))
        {
            return AppOrigin.System;
        }

        if (path.StartsWith("/data/app/", StringComparison.OrdinalIgnoreCase))
        {
            return AppOrigin.User;
        }

        return AppOrigin.Unknown;
    }
}
