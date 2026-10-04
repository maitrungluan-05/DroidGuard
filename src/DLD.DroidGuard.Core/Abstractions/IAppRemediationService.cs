using DLD.DroidGuard.Core.Models;

namespace DLD.DroidGuard.Core.Abstractions;

/// <summary>
/// Service interface for evaluating and executing application remediation actions over ADB.
/// </summary>
public interface IAppRemediationService
{
    Task<RemediationResult> ExecuteActionAsync(
        string deviceSerial,
        AndroidApp app,
        RemediationAction action,
        bool dryRun = false,
        CancellationToken cancellationToken = default);
}
