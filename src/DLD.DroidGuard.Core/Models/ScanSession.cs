namespace DLD.DroidGuard.Core.Models;

/// <summary>
/// Session metadata and package security results for a complete scan session.
/// </summary>
public sealed record ScanSession(
    Guid SessionId,
    string DeviceSerial,
    string DeviceModel,
    string AndroidVersion,
    DateTimeOffset ScanStartedAt,
    DateTimeOffset ScanCompletedAt,
    int PackageCount,
    IReadOnlyDictionary<RiskLevel, int> RiskDistribution,
    int DetectionCount,
    IReadOnlyList<AndroidApp> Apps
);
