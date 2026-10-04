using DLD.DroidGuard.Core.Models;

namespace DLD.DroidGuard.Core.Abstractions;

/// <summary>
/// Service interface for deep forensic analysis of an Android application package.
/// </summary>
public interface IAppForensicsAnalyzer
{
    Task<AppForensicReport> AnalyzeAsync(
        string deviceSerial,
        AndroidApp app,
        CancellationToken cancellationToken = default);
}
