using System.Text.RegularExpressions;
using DLD.DroidGuard.Core.Abstractions;
using DLD.DroidGuard.Core.Models;
using Microsoft.Extensions.Logging;

namespace DLD.DroidGuard.Infrastructure;

public sealed class RuntimeAppAnalyzer : IRuntimeAppAnalyzer
{
    private static readonly TimeSpan CommandTimeout = TimeSpan.FromSeconds(10);
    private readonly IAdbClient _adbClient;
    private readonly ILogger<RuntimeAppAnalyzer> _logger;

    public RuntimeAppAnalyzer(IAdbClient adbClient, ILogger<RuntimeAppAnalyzer> logger)
    {
        _adbClient = adbClient ?? throw new ArgumentNullException(nameof(adbClient));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public async Task<RuntimeAppReport> AnalyzeRuntimeAsync(
        string deviceSerial,
        AndroidApp app,
        CancellationToken cancellationToken = default)
    {
        var timestamp = DateTimeOffset.UtcNow;
        if (string.IsNullOrWhiteSpace(deviceSerial) || app == null || string.IsNullOrWhiteSpace(app.PackageName))
        {
            return new RuntimeAppReport(
                IsRunning: false,
                IsForeground: false,
                RunningProcesses: Array.Empty<string>(),
                ActiveServices: Array.Empty<string>(),
                ActiveActivities: Array.Empty<string>(),
                RecentTaskPresence: false,
                CollectionTimestamp: timestamp
            );
        }

        var pkg = app.PackageName;
        _logger.LogInformation("RuntimeAppAnalyzer: Inspecting runtime state for [{PackageName}] on [{Serial}]", pkg, deviceSerial);

        bool isRunning = false;
        bool isForeground = false;
        var processes = new List<string>();
        var services = new List<string>();
        var activities = new List<string>();
        bool recentTask = false;

        try
        {
            // 1. Check if process is running via "pidof <pkg>"
            var pidResult = await _adbClient.ExecuteAsync(
                deviceSerial,
                $"shell pidof {pkg}",
                CommandTimeout,
                cancellationToken).ConfigureAwait(false);

            if (pidResult.IsSuccess && !string.IsNullOrWhiteSpace(pidResult.StdOut))
            {
                var pids = pidResult.StdOut.Trim().Split(new[] { ' ', '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                if (pids.Length > 0)
                {
                    isRunning = true;
                    processes.Add($"Process PID(s): {string.Join(", ", pids)}");
                }
            }

            // Fallback process check: "ps -A | grep <pkg>"
            if (!isRunning)
            {
                var psResult = await _adbClient.ExecuteAsync(
                    deviceSerial,
                    $"shell ps -A",
                    CommandTimeout,
                    cancellationToken).ConfigureAwait(false);

                if (psResult.IsSuccess && !string.IsNullOrWhiteSpace(psResult.StdOut))
                {
                    var matchingLines = psResult.StdOut
                        .Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
                        .Where(l => l.Contains(pkg, StringComparison.OrdinalIgnoreCase))
                        .ToList();

                    if (matchingLines.Count > 0)
                    {
                        isRunning = true;
                        foreach (var line in matchingLines.Take(5))
                        {
                            processes.Add(line.Trim());
                        }
                    }
                }
            }

            // 2. Query active background services for package
            var svcResult = await _adbClient.ExecuteAsync(
                deviceSerial,
                $"shell dumpsys activity services {pkg}",
                CommandTimeout,
                cancellationToken).ConfigureAwait(false);

            if (svcResult.IsSuccess && !string.IsNullOrWhiteSpace(svcResult.StdOut))
            {
                var svcLines = svcResult.StdOut
                    .Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
                    .Where(l => l.Contains("ServiceRecord{", StringComparison.OrdinalIgnoreCase))
                    .Select(l => l.Trim())
                    .Distinct()
                    .ToList();

                services.AddRange(svcLines.Take(10));
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "RuntimeAppAnalyzer: Error inspecting runtime state for [{PackageName}]", pkg);
        }

        return new RuntimeAppReport(
            IsRunning: isRunning,
            IsForeground: isForeground,
            RunningProcesses: processes,
            ActiveServices: services,
            ActiveActivities: activities,
            RecentTaskPresence: recentTask,
            CollectionTimestamp: timestamp
        );
    }
}
