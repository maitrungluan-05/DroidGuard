using DLD.DroidGuard.Core.Models;

namespace DLD.DroidGuard.Core.Abstractions;

/// <summary>
/// Service interface for exporting scan session reports to files.
/// </summary>
public interface IScanReportExporter
{
    Task ExportJsonAsync(ScanSession session, string destinationFilePath, CancellationToken cancellationToken = default);
}
