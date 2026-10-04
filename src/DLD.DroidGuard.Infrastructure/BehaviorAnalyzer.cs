using System.Text.RegularExpressions;
using DLD.DroidGuard.Core.Abstractions;
using DLD.DroidGuard.Core.Models;
using Microsoft.Extensions.Logging;

namespace DLD.DroidGuard.Infrastructure;

public sealed class BehaviorAnalyzer : IBehaviorAnalyzer
{
    private static readonly TimeSpan CommandTimeout = TimeSpan.FromSeconds(12);
    private static readonly Regex SafePackageRegex = new(@"^[a-zA-Z0-9_.]+$", RegexOptions.Compiled);
    private static readonly Regex IpPortRegex = new(@"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)", RegexOptions.Compiled);

    private readonly IAdbClient _adbClient;
    private readonly ILogger<BehaviorAnalyzer> _logger;

    public BehaviorAnalyzer(IAdbClient adbClient, ILogger<BehaviorAnalyzer> logger)
    {
        _adbClient = adbClient ?? throw new ArgumentNullException(nameof(adbClient));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public async Task<BehaviorAnalysisReport> AnalyzeAsync(
        string deviceSerial,
        AndroidApp app,
        CancellationToken cancellationToken = default)
    {
        var startedAt = DateTimeOffset.UtcNow;

        if (app == null || string.IsNullOrWhiteSpace(app.PackageName) || !SafePackageRegex.IsMatch(app.PackageName))
        {
            return new BehaviorAnalysisReport(
                PackageName: app?.PackageName ?? "unknown",
                StartedAt: startedAt,
                CompletedAt: DateTimeOffset.UtcNow,
                IsComplete: false,
                Processes: Array.Empty<string>(),
                Services: Array.Empty<string>(),
                Activities: Array.Empty<string>(),
                Receivers: Array.Empty<string>(),
                NetworkIndicators: Array.Empty<NetworkIndicator>(),
                FileIndicators: Array.Empty<string>(),
                Evidence: new[] { "Invalid or unsafe package name string." },
                Errors: new[] { "Command safety validation failed for package name." },
                Confidence: 0.0
            );
        }

        var pkg = app.PackageName;
        _logger.LogInformation("BehaviorAnalyzer: Analyzing dynamic behavior for [{PackageName}] on [{Serial}]", pkg, deviceSerial);

        var processes = new List<string>();
        var services = new List<string>();
        var activities = new List<string>();
        var receivers = new List<string>();
        var netIndicators = new List<NetworkIndicator>();
        var evidence = new List<string>();
        var errors = new List<string>();

        try
        {
            // 1. Process & PID inspection
            cancellationToken.ThrowIfCancellationRequested();
            var pidResult = await _adbClient.ExecuteAsync(
                deviceSerial,
                $"shell pidof {pkg}",
                CommandTimeout,
                cancellationToken).ConfigureAwait(false);

            if (pidResult != null && pidResult.IsSuccess && !string.IsNullOrWhiteSpace(pidResult.StdOut))
            {
                var pids = pidResult.StdOut.Trim().Split(new[] { ' ', '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                foreach (var pid in pids)
                {
                    processes.Add($"Process PID {pid}");
                }
                evidence.Add($"Active running process(es): PID {string.Join(", ", pids)}.");
            }

            // 2. Active background services inspection
            cancellationToken.ThrowIfCancellationRequested();
            var svcResult = await _adbClient.ExecuteAsync(
                deviceSerial,
                $"shell dumpsys activity services {pkg}",
                CommandTimeout,
                cancellationToken).ConfigureAwait(false);

            if (svcResult != null && svcResult.IsSuccess && !string.IsNullOrWhiteSpace(svcResult.StdOut))
            {
                var svcLines = svcResult.StdOut
                    .Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
                    .Where(l => l.Contains("ServiceRecord{", StringComparison.OrdinalIgnoreCase))
                    .Select(l => l.Trim())
                    .Distinct()
                    .ToList();

                foreach (var s in svcLines.Take(10))
                {
                    services.Add(s);
                }
                if (services.Count > 0)
                {
                    evidence.Add($"Active background service(s): {services.Count} service record(s) active.");
                }
            }

            // 3. Non-intrusive Network Indicator Metadata inspection (netstat / dumpsys netstats)
            cancellationToken.ThrowIfCancellationRequested();
            var netResult = await _adbClient.ExecuteAsync(
                deviceSerial,
                "shell netstat -n",
                CommandTimeout,
                cancellationToken).ConfigureAwait(false);

            if (netResult != null && netResult.IsSuccess && !string.IsNullOrWhiteSpace(netResult.StdOut))
            {
                var netLines = netResult.StdOut
                    .Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
                    .Where(l => l.Contains("ESTABLISHED", StringComparison.OrdinalIgnoreCase) || l.Contains("SYN_SENT", StringComparison.OrdinalIgnoreCase))
                    .Take(5)
                    .ToList();

                foreach (var line in netLines)
                {
                    var matches = IpPortRegex.Matches(line);
                    if (matches.Count >= 2)
                    {
                        var destMatch = matches[1];
                        var ip = destMatch.Groups[1].Value;
                        if (int.TryParse(destMatch.Groups[2].Value, out var port))
                        {
                            var classification = (ip.StartsWith("127.") || ip.StartsWith("10.") || ip.StartsWith("192.168."))
                                ? NetworkActivityClassification.KnownSystemService
                                : NetworkActivityClassification.UnknownBackgroundNetworkActivity;

                            netIndicators.Add(new NetworkIndicator(
                                Uid: app.Uid ?? 0,
                                DestinationIp: ip,
                                DestinationPort: port,
                                ConnectionState: "ESTABLISHED",
                                Classification: classification,
                                Description: $"Active socket connection metadata: {ip}:{port}"
                            ));
                        }
                    }
                }
            }
        }
        catch (OperationCanceledException)
        {
            errors.Add("Behavioral analysis cancelled by user.");
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "BehaviorAnalyzer: Exception during analysis of [{PackageName}]", pkg);
            errors.Add($"Analysis exception: {ex.Message}");
        }

        bool isComplete = errors.Count == 0;
        double confidence = isComplete ? 0.90 : 0.60;

        return new BehaviorAnalysisReport(
            PackageName: pkg,
            StartedAt: startedAt,
            CompletedAt: DateTimeOffset.UtcNow,
            IsComplete: isComplete,
            Processes: processes,
            Services: services,
            Activities: activities,
            Receivers: receivers,
            NetworkIndicators: netIndicators,
            FileIndicators: Array.Empty<string>(),
            Evidence: evidence,
            Errors: errors,
            Confidence: confidence
        );
    }
}
