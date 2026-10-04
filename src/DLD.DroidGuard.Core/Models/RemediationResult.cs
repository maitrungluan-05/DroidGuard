namespace DLD.DroidGuard.Core.Models;

/// <summary>
/// Result of executing or evaluating a remediation action.
/// </summary>
public sealed record RemediationResult(
    bool Success,
    string PackageName,
    RemediationAction Action,
    string Command,
    string Output,
    string Error,
    int ExitCode,
    bool IsDryRun,
    bool IsBlockedBySafety,
    string? BlockReason
);
