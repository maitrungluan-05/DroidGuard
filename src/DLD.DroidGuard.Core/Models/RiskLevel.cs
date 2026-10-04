namespace DLD.DroidGuard.Core.Models;

/// <summary>
/// Threat risk levels based on risk score (0-100).
/// </summary>
public enum RiskLevel
{
    Safe,       // 0-29
    Low,        // 30-49
    Medium,     // 50-69
    High,       // 70-84
    Critical    // 85-100
}

public static class RiskLevelExtensions
{
    public static RiskLevel FromScore(int score) => score switch
    {
        >= 85 => RiskLevel.Critical,
        >= 70 => RiskLevel.High,
        >= 50 => RiskLevel.Medium,
        >= 30 => RiskLevel.Low,
        _     => RiskLevel.Safe
    };
}
