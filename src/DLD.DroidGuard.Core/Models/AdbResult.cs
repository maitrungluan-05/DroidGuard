namespace DLD.DroidGuard.Core.Models;

/// <summary>
/// Represents the result of executing an ADB command.
/// Exit codes and stderr are not treated as exceptions —
/// callers decide whether a non-zero exit code is an error.
/// </summary>
public sealed record AdbResult(
    int ExitCode,
    string StdOut,
    string StdErr,
    bool TimedOut,
    TimeSpan Duration
)
{
    /// <summary>Returns true when the command completed without timeout and exit code is 0.</summary>
    public bool IsSuccess => !TimedOut && ExitCode == 0;
}
