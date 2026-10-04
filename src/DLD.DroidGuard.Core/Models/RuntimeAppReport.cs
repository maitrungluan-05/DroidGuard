namespace DLD.DroidGuard.Core.Models;

/// <summary>
/// Runtime and process state visibility report for an Android application.
/// </summary>
public sealed record RuntimeAppReport(
    bool IsRunning,
    bool IsForeground,
    IReadOnlyList<string> RunningProcesses,
    IReadOnlyList<string> ActiveServices,
    IReadOnlyList<string> ActiveActivities,
    bool RecentTaskPresence,
    DateTimeOffset CollectionTimestamp
);
