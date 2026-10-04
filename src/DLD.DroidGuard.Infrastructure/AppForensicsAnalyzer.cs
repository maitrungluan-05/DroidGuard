using System.Text.RegularExpressions;
using DLD.DroidGuard.Core.Abstractions;
using DLD.DroidGuard.Core.Models;
using Microsoft.Extensions.Logging;

namespace DLD.DroidGuard.Infrastructure;

public sealed class AppForensicsAnalyzer : IAppForensicsAnalyzer
{
    private static readonly TimeSpan CommandTimeout = TimeSpan.FromSeconds(15);
    private readonly IAdbClient _adbClient;
    private readonly ILogger<AppForensicsAnalyzer> _logger;

    public AppForensicsAnalyzer(IAdbClient adbClient, ILogger<AppForensicsAnalyzer> logger)
    {
        _adbClient = adbClient ?? throw new ArgumentNullException(nameof(adbClient));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public async Task<AppForensicReport> AnalyzeAsync(
        string deviceSerial,
        AndroidApp app,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(deviceSerial) || app == null || string.IsNullOrWhiteSpace(app.PackageName))
        {
            return new AppForensicReport(
                ApkHashSha256: null,
                ApkSizeBytes: null,
                SigningCertificates: Array.Empty<string>(),
                IsDebuggable: null,
                AllowBackup: null,
                TargetSdk: null,
                MinSdk: null,
                Evidence: new[] { "Invalid package or device input." },
                Errors: new[] { "Missing device serial or package name." },
                IsComplete: false
            );
        }

        _logger.LogInformation("AppForensicsAnalyzer: Deep forensic analysis for [{PackageName}] on [{Serial}]", app.PackageName, deviceSerial);

        var evidence = new List<string>();
        var errors = new List<string>();
        long? apkSize = app.ApkSizeBytes;
        string? sha256 = null;

        // 1. Query APK file size if path is known and size not yet populated
        if (apkSize == null && !string.IsNullOrWhiteSpace(app.ApkPath))
        {
            try
            {
                var statResult = await _adbClient.ExecuteAsync(
                    deviceSerial,
                    $"shell ls -l {app.ApkPath}",
                    CommandTimeout,
                    cancellationToken).ConfigureAwait(false);

                if (statResult.IsSuccess && !string.IsNullOrWhiteSpace(statResult.StdOut))
                {
                    // Parse ls -l output (e.g., "-rw-r--r-- 1 root root 1234567 2023-01-01 ...")
                    var parts = statResult.StdOut.Trim().Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                    foreach (var part in parts)
                    {
                        if (long.TryParse(part, out var bytes) && bytes > 100)
                        {
                            apkSize = bytes;
                            evidence.Add($"Verified APK file size: {apkSize:N0} bytes.");
                            break;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                errors.Add($"Failed to query APK file size: {ex.Message}");
            }
        }

        // 2. Evaluate Debuggable & Backup flags
        if (app.IsDebuggable == true)
        {
            evidence.Add("APK Flag: DEBUGGABLE enabled (Allows process attachment & memory inspection).");
        }
        if (app.AllowBackup == true)
        {
            evidence.Add("APK Flag: ALLOW_BACKUP enabled (Allows data extraction via adb backup).");
        }

        // 3. Evaluate SDK Targets
        if (app.TargetSdk != null)
        {
            evidence.Add($"Target SDK Version: API Level {app.TargetSdk}");
        }
        if (app.MinSdk != null)
        {
            evidence.Add($"Minimum SDK Support: API Level {app.MinSdk}");
        }

        // 4. Signing certificate summary
        var sigs = app.Signatures ?? Array.Empty<string>();
        if (sigs.Count > 0)
        {
            evidence.Add($"Package Signing Certificate Digest: {string.Join(", ", sigs)}");
        }
        else
        {
            evidence.Add("No signature digest extracted from basic package metadata.");
        }

        bool isComplete = errors.Count == 0;

        return new AppForensicReport(
            ApkHashSha256: sha256,
            ApkSizeBytes: apkSize,
            SigningCertificates: sigs,
            IsDebuggable: app.IsDebuggable,
            AllowBackup: app.AllowBackup,
            TargetSdk: app.TargetSdk,
            MinSdk: app.MinSdk,
            Evidence: evidence,
            Errors: errors,
            IsComplete: isComplete
        );
    }
}
