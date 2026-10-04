namespace DLD.DroidGuard.Core.Models;

/// <summary>
/// Detailed APK and signature forensic analysis report for an Android application.
/// </summary>
public sealed record AppForensicReport(
    string? ApkHashSha256,
    long? ApkSizeBytes,
    IReadOnlyList<string> SigningCertificates,
    bool? IsDebuggable,
    bool? AllowBackup,
    int? TargetSdk,
    int? MinSdk,
    IReadOnlyList<string> Evidence,
    IReadOnlyList<string> Errors,
    bool IsComplete
);
