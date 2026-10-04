namespace DLD.DroidGuard.Core.Models;

public enum NetworkActivityClassification
{
    KnownSystemService,
    NormalNetworkActivity,
    UnknownBackgroundNetworkActivity,
    SuspiciousNetworkPattern
}

/// <summary>
/// Network connection metadata collected via non-intrusive standard ADB shell statistics.
/// Contains zero user data content, payloads, or HTTPS interception.
/// </summary>
public sealed record NetworkIndicator(
    int Uid,
    string DestinationIp,
    int DestinationPort,
    string ConnectionState,
    NetworkActivityClassification Classification,
    string Description
);
