using DLD.DroidGuard.Core.Models;

namespace DLD.DroidGuard.Core.Abstractions;

/// <summary>
/// Service interface for inspecting runtime process and activity states of an application over ADB.
/// </summary>
public interface IRuntimeAppAnalyzer
{
    Task<RuntimeAppReport> AnalyzeRuntimeAsync(
        string deviceSerial,
        AndroidApp app,
        CancellationToken cancellationToken = default);
}
