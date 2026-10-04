using System.Diagnostics;
using System.Text;
using DLD.DroidGuard.Core.Abstractions;
using DLD.DroidGuard.Core.Exceptions;
using DLD.DroidGuard.Core.Models;
using Microsoft.Extensions.Logging;

namespace DLD.DroidGuard.Adb;

/// <summary>
/// Executes ADB commands by spawning adb.exe as a child process.
/// Handles stdout/stderr redirection, UTF-8 encoding, timeouts, and cancellation.
/// </summary>
public sealed class AdbClient : IAdbClient
{
    private readonly IAdbLocator _locator;
    private readonly ILogger<AdbClient> _logger;
    private readonly AdbDevicesParser _devicesParser;

    private static readonly TimeSpan DefaultVersionTimeout = TimeSpan.FromSeconds(10);

    public AdbClient(IAdbLocator locator, ILogger<AdbClient> logger)
    {
        _locator = locator ?? throw new ArgumentNullException(nameof(locator));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _devicesParser = new AdbDevicesParser();
    }

    /// <inheritdoc />
    public async Task<AdbResult> ExecuteAsync(
        string? serial,
        string arguments,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        var adbPath = _locator.Locate(); // throws AdbNotFoundException if not found

        if (!string.IsNullOrWhiteSpace(serial))
        {
            SafeAdbCommandBuilder.ValidateIdentifier(serial, nameof(serial));
        }

        // Build argument string: optionally prefix with -s <serial>
        var fullArguments = serial is null
            ? arguments
            : $"-s {serial} {arguments}";

        _logger.LogDebug("ADB: Executing [{AdbPath}] {Arguments}", adbPath, fullArguments);

        var startInfo = new ProcessStartInfo
        {
            FileName = adbPath,
            Arguments = fullArguments,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
        };

        var sw = Stopwatch.StartNew();
        using var process = new Process { StartInfo = startInfo };

        var stdOutBuilder = new StringBuilder();
        var stdErrBuilder = new StringBuilder();

        // Buffer output asynchronously to avoid deadlocks
        var stdOutTask = Task.CompletedTask;
        var stdErrTask = Task.CompletedTask;

        try
        {
            process.Start();

            // Read stdout and stderr concurrently to avoid blocking
            stdOutTask = ReadStreamAsync(process.StandardOutput, stdOutBuilder, cancellationToken);
            stdErrTask = ReadStreamAsync(process.StandardError, stdErrBuilder, cancellationToken);

            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutCts.CancelAfter(timeout);

            bool exited;
            try
            {
                await process.WaitForExitAsync(timeoutCts.Token).ConfigureAwait(false);
                exited = true;
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                // Timeout (not user cancellation)
                exited = false;
            }

            if (!exited)
            {
                _logger.LogWarning(
                    "ADB: Command timed out after {Timeout}: [{AdbPath}] {Arguments}",
                    timeout, adbPath, fullArguments);

                TryKillProcess(process);
                await WaitForReadersAsync(stdOutTask, stdErrTask).ConfigureAwait(false);
                sw.Stop();

                return new AdbResult(
                    ExitCode: -1,
                    StdOut: stdOutBuilder.ToString(),
                    StdErr: stdErrBuilder.ToString(),
                    TimedOut: true,
                    Duration: sw.Elapsed);
            }

            // Wait for output readers to complete after process exits
            await WaitForReadersAsync(stdOutTask, stdErrTask).ConfigureAwait(false);
            sw.Stop();

            _logger.LogDebug(
                "ADB: ExitCode={ExitCode} Duration={Duration}ms: {Arguments}",
                process.ExitCode, (int)sw.ElapsedMilliseconds, fullArguments);

            return new AdbResult(
                ExitCode: process.ExitCode,
                StdOut: stdOutBuilder.ToString(),
                StdErr: stdErrBuilder.ToString(),
                TimedOut: false,
                Duration: sw.Elapsed);
        }
        catch (OperationCanceledException)
        {
            _logger.LogInformation("ADB: Command cancelled: {Arguments}", fullArguments);
            TryKillProcess(process);
            await WaitForReadersAsync(stdOutTask, stdErrTask).ConfigureAwait(false);
            throw;
        }
        catch (Exception ex) when (ex is not AdbNotFoundException)
        {
            _logger.LogError(ex, "ADB: Process execution failed for arguments: {Arguments}", fullArguments);
            TryKillProcess(process);
            throw;
        }
    }

    /// <inheritdoc />
    public async Task<string> GetVersionAsync(CancellationToken cancellationToken)
    {
        _logger.LogDebug("ADB: Querying version");
        var result = await ExecuteAsync(
            serial: null,
            arguments: "version",
            timeout: DefaultVersionTimeout,
            cancellationToken).ConfigureAwait(false);

        if (result.TimedOut)
        {
            _logger.LogWarning("ADB: version command timed out");
            return "unknown (timeout)";
        }

        if (result.ExitCode != 0)
        {
            _logger.LogWarning("ADB: version command exited with {ExitCode}", result.ExitCode);
            return "unknown (error)";
        }

        // Extract version from "Android Debug Bridge version X.Y.Z"
        var line = result.StdOut
            .Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .FirstOrDefault(l => l.StartsWith("Android Debug Bridge version", StringComparison.OrdinalIgnoreCase));

        if (line is null)
        {
            _logger.LogWarning("ADB: Could not parse version from output: {Output}", result.StdOut);
            return "unknown (parse error)";
        }

        var version = line.Replace("Android Debug Bridge version", string.Empty).Trim();
        _logger.LogInformation("ADB: Version = {Version}", version);
        return version;
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<AndroidDevice>> GetDevicesAsync(CancellationToken cancellationToken)
    {
        _logger.LogDebug("ADB: Listing devices");
        var result = await ExecuteAsync(
            serial: null,
            arguments: "devices -l",
            timeout: TimeSpan.FromSeconds(15),
            cancellationToken).ConfigureAwait(false);

        if (result.TimedOut)
        {
            _logger.LogWarning("ADB: devices command timed out");
            return Array.Empty<AndroidDevice>();
        }

        if (result.ExitCode != 0)
        {
            _logger.LogWarning(
                "ADB: devices command failed with ExitCode={ExitCode}, StdErr={StdErr}",
                result.ExitCode, result.StdErr);
            return Array.Empty<AndroidDevice>();
        }

        var devices = _devicesParser.Parse(result.StdOut);
        _logger.LogInformation("ADB: Found {Count} device(s)", devices.Count);
        return devices;
    }

    // --- helpers ---

    private static async Task ReadStreamAsync(
        System.IO.TextReader reader,
        StringBuilder builder,
        CancellationToken cancellationToken)
    {
        try
        {
            var buffer = new char[4096];
            int read;
            while ((read = await reader.ReadAsync(buffer, 0, buffer.Length).ConfigureAwait(false)) > 0)
            {
                cancellationToken.ThrowIfCancellationRequested();
                builder.Append(buffer, 0, read);
            }
        }
        catch (OperationCanceledException)
        {
            // Stream reading stopped due to cancellation — acceptable
        }
        catch (ObjectDisposedException)
        {
            // Process was killed; stream is gone
        }
    }

    private static async Task WaitForReadersAsync(Task stdOutTask, Task stdErrTask)
    {
        try { await Task.WhenAll(stdOutTask, stdErrTask).ConfigureAwait(false); }
        catch { /* Readers may already be faulted/cancelled; output already captured */ }
    }

    private void TryKillProcess(Process process)
    {
        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
                _logger.LogDebug("ADB: Process killed");
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "ADB: Failed to kill process");
        }
    }
}
