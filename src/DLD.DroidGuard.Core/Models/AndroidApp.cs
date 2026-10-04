namespace DLD.DroidGuard.Core.Models;

/// <summary>
/// Represents an installed Android application package and its metadata.
/// Unknown / uncollected fields remain null — false is never assumed for missing info.
/// </summary>
public sealed record AndroidApp
{
    public required string PackageName { get; init; }

    public string? Label { get; init; }
    public string? VersionName { get; init; }
    public long? VersionCode { get; init; }
    public int? Uid { get; init; }

    public string? ApkPath { get; init; }

    public AppOrigin Origin { get; init; } = AppOrigin.Unknown;

    /// <summary>
    /// Derived system app state: true if System, false if User, null if Unknown.
    /// </summary>
    public bool? IsSystemApp => Origin switch
    {
        AppOrigin.System => true,
        AppOrigin.User => false,
        _ => null
    };

    public bool? IsEnabled { get; init; }

    /// <summary>
    /// Null = scanner could not determine launcher presence.
    /// False = scanner verified package has no launcher activity.
    /// True = scanner verified package has launcher activity.
    /// </summary>
    public bool? HasLauncherActivity { get; init; }

    public string? InstallerPackage { get; init; }

    public DateTimeOffset? FirstInstallTime { get; init; }
    public DateTimeOffset? LastUpdateTime { get; init; }

    /// <summary>
    /// Permissions requested by this application.
    /// </summary>
    public IReadOnlyList<string> RequestedPermissions { get; init; } = Array.Empty<string>();

    /// <summary>
    /// Additional forensic metadata properties.
    /// </summary>
    public string? SharedUserId { get; init; }
    public long? ApkSizeBytes { get; init; }
    public bool? IsDebuggable { get; init; }
    public bool? AllowBackup { get; init; }
    public int? TargetSdk { get; init; }
    public int? MinSdk { get; init; }
    public IReadOnlyList<string>? Signatures { get; init; }

    /// <summary>
    /// Deep forensic analysis report (populated upon demand/deep scan).
    /// </summary>
    public AppForensicReport? ForensicReport { get; init; }

    /// <summary>
    /// Live runtime state analysis report (populated upon demand/deep scan).
    /// </summary>
    public RuntimeAppReport? RuntimeReport { get; init; }

    /// <summary>
    /// Dynamic behavior analysis report (populated upon demand/deep scan).
    /// </summary>
    public BehaviorAnalysisReport? BehaviorReport { get; init; }

    /// <summary>
    /// Correlated security assessment combining static, forensic, and behavioral analysis.
    /// </summary>
    public CorrelatedSecurityAssessment? CorrelatedAssessment { get; init; }

    /// <summary>
    /// Historical behavior snapshots for temporal analysis.
    /// </summary>
    public IReadOnlyList<BehaviorSnapshot>? BehaviorSnapshots { get; init; }

    /// <summary>
    /// Risk analysis populated by the RiskEngine.
    /// </summary>
    public AppRiskAnalysis? RiskAnalysis { get; init; }
}
