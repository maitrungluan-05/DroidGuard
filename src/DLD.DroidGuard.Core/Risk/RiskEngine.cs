using DLD.DroidGuard.Core.Abstractions;
using DLD.DroidGuard.Core.Models;
using DLD.DroidGuard.Core.Risk.Detectors;
using DLD.DroidGuard.Core.Risk.Factors;
using Microsoft.Extensions.Logging;

namespace DLD.DroidGuard.Core.Risk;

/// <summary>
/// Evidence-based risk scoring and threat detection engine.
/// Evaluates applications completely in-memory without making additional ADB calls.
/// </summary>
public sealed class RiskEngine : IRiskEngine
{
    private readonly IReadOnlyList<IRiskFactor> _factors;
    private readonly HiddenAppDetector _hiddenDetector = new();
    private readonly AdwareDetector _adwareDetector = new();
    private readonly ILogger<RiskEngine> _logger;

    public RiskEngine(ILogger<RiskEngine> logger)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));

        _factors = new IRiskFactor[]
        {
            new SideloadRiskFactor(),
            new HiddenLauncherRiskFactor(),
            new SensitivePermissionRiskFactor(),
            new SuspiciousPermissionCombinationFactor(),
            new BackgroundExecutionRiskFactor()
        };
    }

    /// <inheritdoc />
    public AppRiskAnalysis Analyze(AndroidApp app)
    {
        ArgumentNullException.ThrowIfNull(app);
        _logger.LogDebug("[RiskEngine] Analyzing package {PackageName}", app.PackageName);

        var evidences = new List<RiskEvidence>();
        int totalScore = 0;

        foreach (var factor in _factors)
        {
            try
            {
                var evidence = factor.Evaluate(app);
                if (evidence is not null && evidence.Points > 0)
                {
                    evidences.Add(evidence);
                    totalScore += evidence.Points;
                    _logger.LogDebug("[RiskEngine] Factor {FactorId} matched for {PackageName}: +{Points} pts",
                        factor.Id, app.PackageName, evidence.Points);
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "[RiskEngine] Exception evaluating factor {FactorId} on {PackageName}",
                    factor.Id, app.PackageName);
            }
        }

        // Clamp total score to 0 - 100
        int clampedScore = Math.Clamp(totalScore, 0, 100);
        var level = RiskLevelExtensions.FromScore(clampedScore);

        // Run threat detectors
        var detections = new List<DetectionResult>();

        var hiddenDetection = _hiddenDetector.Detect(app, evidences);
        if (hiddenDetection is not null)
        {
            detections.Add(hiddenDetection);
            _logger.LogInformation("[RiskEngine] Threat detected on {PackageName}: {DetectionName}", app.PackageName, hiddenDetection.Name);
        }

        var adwareDetection = _adwareDetector.Detect(app, evidences);
        if (adwareDetection is not null)
        {
            detections.Add(adwareDetection);
            _logger.LogInformation("[RiskEngine] Threat detected on {PackageName}: {DetectionName}", app.PackageName, adwareDetection.Name);
        }

        var recommendedAction = DetermineRecommendedAction(level, app.Origin, detections);

        _logger.LogDebug("[RiskEngine] Package {PackageName} Score={Score}, Level={Level}, Detections={Count}",
            app.PackageName, clampedScore, level, detections.Count);

        return new AppRiskAnalysis(
            RiskScore: clampedScore,
            RiskLevel: level,
            Evidences: evidences,
            Detections: detections,
            RecommendedAction: recommendedAction
        );
    }

    /// <inheritdoc />
    public IReadOnlyList<AndroidApp> AnalyzeAll(IEnumerable<AndroidApp> apps)
    {
        ArgumentNullException.ThrowIfNull(apps);

        var resultList = new List<AndroidApp>();
        foreach (var app in apps)
        {
            var analysis = Analyze(app);
            resultList.Add(app with { RiskAnalysis = analysis });
        }

        return resultList;
    }

    private static RecommendedAction DetermineRecommendedAction(
        RiskLevel level,
        AppOrigin origin,
        IReadOnlyList<DetectionResult> detections)
    {
        if (level == RiskLevel.Safe)
            return RecommendedAction.None;

        if (level == RiskLevel.Low)
            return RecommendedAction.Monitor;

        if (detections.Any(d => d.Type == DetectionType.HiddenApp))
        {
            return origin == AppOrigin.System ? RecommendedAction.Disable : RecommendedAction.Uninstall;
        }

        return level switch
        {
            RiskLevel.Critical => origin == AppOrigin.System ? RecommendedAction.Disable : RecommendedAction.Uninstall,
            RiskLevel.High => RecommendedAction.ReviewPermissions,
            RiskLevel.Medium => RecommendedAction.Monitor,
            _ => RecommendedAction.None
        };
    }
}
