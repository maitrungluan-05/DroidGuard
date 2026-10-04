using System.Text.RegularExpressions;
using DLD.DroidGuard.Core.Abstractions;
using DLD.DroidGuard.Core.Models;
using DLD.DroidGuard.Core.Risk;
using Microsoft.Extensions.Logging;

namespace DLD.DroidGuard.Infrastructure;

public sealed class AppRemediationService : IAppRemediationService
{
    private static readonly TimeSpan CommandTimeout = TimeSpan.FromSeconds(20);
    private static readonly Regex SafePackageRegex = new(@"^[a-zA-Z0-9_.]+$", RegexOptions.Compiled);

    private readonly IAdbClient _adbClient;
    private readonly ILogger<AppRemediationService> _logger;

    public AppRemediationService(IAdbClient adbClient, ILogger<AppRemediationService> logger)
    {
        _adbClient = adbClient ?? throw new ArgumentNullException(nameof(adbClient));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public async Task<RemediationResult> ExecuteActionAsync(
        string deviceSerial,
        AndroidApp app,
        RemediationAction action,
        bool dryRun = false,
        CancellationToken cancellationToken = default)
    {
        if (app == null || string.IsNullOrWhiteSpace(app.PackageName))
        {
            return new RemediationResult(
                Success: false,
                PackageName: app?.PackageName ?? "unknown",
                Action: action,
                Command: string.Empty,
                Output: string.Empty,
                Error: "Invalid package metadata.",
                ExitCode: -1,
                IsDryRun: dryRun,
                IsBlockedBySafety: true,
                BlockReason: "Package metadata is missing or null."
            );
        }

        var pkg = app.PackageName.Trim();

        // 1. Command Safety Validation (Prevent Shell Injection)
        if (!SafePackageRegex.IsMatch(pkg))
        {
            _logger.LogWarning("AppRemediationService: Command Safety Violation! Unsafe package string detected: '{PackageName}'", pkg);
            return new RemediationResult(
                Success: false,
                PackageName: pkg,
                Action: action,
                Command: string.Empty,
                Output: string.Empty,
                Error: "Command safety check failed. Invalid character in package name.",
                ExitCode: -1,
                IsDryRun: dryRun,
                IsBlockedBySafety: true,
                BlockReason: "Command safety violation (Shell Injection Prevention)."
            );
        }

        // 2. Safety Policy Check
        var (isAllowed, reason, _) = RemediationSafetyPolicy.Evaluate(app, action);
        if (!isAllowed)
        {
            _logger.LogWarning("AppRemediationService: Action [{Action}] for package [{PackageName}] BLOCKED by safety policy: {Reason}",
                action, pkg, reason);

            return new RemediationResult(
                Success: false,
                PackageName: pkg,
                Action: action,
                Command: BuildAdbCommand(pkg, action),
                Output: string.Empty,
                Error: reason ?? "Blocked by security policy.",
                ExitCode: -1,
                IsDryRun: dryRun,
                IsBlockedBySafety: true,
                BlockReason: reason
            );
        }

        var command = BuildAdbCommand(pkg, action);

        // 3. DRY RUN Preview
        if (dryRun)
        {
            _logger.LogInformation("AppRemediationService: Generated DRY RUN preview for [{Action}] on [{PackageName}]: adb {Command}",
                action, pkg, command);

            return new RemediationResult(
                Success: true,
                PackageName: pkg,
                Action: action,
                Command: $"adb -s {deviceSerial} {command}",
                Output: $"DRY RUN PREVIEW: The command 'adb -s {deviceSerial} {command}' will be executed upon confirmation.",
                Error: string.Empty,
                ExitCode: 0,
                IsDryRun: true,
                IsBlockedBySafety: false,
                BlockReason: null
            );
        }

        // 4. Preflight Validation before actual execution
        if (string.IsNullOrWhiteSpace(deviceSerial))
        {
            return new RemediationResult(
                Success: false,
                PackageName: pkg,
                Action: action,
                Command: command,
                Output: string.Empty,
                Error: "Device serial is required for actual remediation execution.",
                ExitCode: -1,
                IsDryRun: false,
                IsBlockedBySafety: false,
                BlockReason: null
            );
        }

        _logger.LogInformation("AppRemediationService: Performing Preflight package verification for [{PackageName}]...", pkg);
        var preflightResult = await _adbClient.ExecuteAsync(
            deviceSerial,
            $"shell pm path {pkg}",
            TimeSpan.FromSeconds(5),
            cancellationToken).ConfigureAwait(false);

        if (!preflightResult.IsSuccess || string.IsNullOrWhiteSpace(preflightResult.StdOut) || !preflightResult.StdOut.Contains("package:", StringComparison.OrdinalIgnoreCase))
        {
            _logger.LogWarning("AppRemediationService: Preflight check FAILED! Package '{PackageName}' no longer exists or state changed.", pkg);
            return new RemediationResult(
                Success: false,
                PackageName: pkg,
                Action: action,
                Command: command,
                Output: string.Empty,
                Error: "Preflight verification failed. Package state changed or package is no longer installed on target device.",
                ExitCode: -1,
                IsDryRun: false,
                IsBlockedBySafety: true,
                BlockReason: "Preflight state verification failure."
            );
        }

        // 5. Execution (Requires explicit user confirmation at caller level)
        _logger.LogWarning("AppRemediationService: EXECUTING remediation [{Action}] on [{PackageName}] via ADB...", action, pkg);

        try
        {
            var result = await _adbClient.ExecuteAsync(
                deviceSerial,
                command,
                CommandTimeout,
                cancellationToken).ConfigureAwait(false);

            bool isSuccess = result.IsSuccess &&
                (string.IsNullOrWhiteSpace(result.StdErr) || result.StdErr.Contains("Success", StringComparison.OrdinalIgnoreCase) || result.StdOut.Contains("Success", StringComparison.OrdinalIgnoreCase));

            return new RemediationResult(
                Success: isSuccess,
                PackageName: pkg,
                Action: action,
                Command: $"adb -s {deviceSerial} {command}",
                Output: result.StdOut,
                Error: result.StdErr,
                ExitCode: result.ExitCode,
                IsDryRun: false,
                IsBlockedBySafety: false,
                BlockReason: null
            );
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "AppRemediationService: Exception executing [{Action}] on [{PackageName}]", action, pkg);
            return new RemediationResult(
                Success: false,
                PackageName: pkg,
                Action: action,
                Command: $"adb -s {deviceSerial} {command}",
                Output: string.Empty,
                Error: ex.Message,
                ExitCode: -1,
                IsDryRun: false,
                IsBlockedBySafety: false,
                BlockReason: null
            );
        }
    }

    private static string BuildAdbCommand(string packageName, RemediationAction action)
    {
        return action switch
        {
            RemediationAction.Uninstall => $"shell pm uninstall --user 0 {packageName}",
            RemediationAction.Disable   => $"shell pm disable-user --user 0 {packageName}",
            RemediationAction.Enable    => $"shell pm enable {packageName}",
            RemediationAction.ClearData => $"shell pm clear {packageName}",
            RemediationAction.ForceStop => $"shell am force-stop {packageName}",
            _ => throw new ArgumentOutOfRangeException(nameof(action))
        };
    }
}
