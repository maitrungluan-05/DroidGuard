using System.Text.Json;
using System.Text.Json.Serialization;
using DLD.DroidGuard.Core.Abstractions;
using DLD.DroidGuard.Core.Models;
using Microsoft.Extensions.Logging;

namespace DLD.DroidGuard.Infrastructure;

public sealed class JsonReportExporter : IScanReportExporter
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter() }
    };

    private readonly ILogger<JsonReportExporter> _logger;

    public JsonReportExporter(ILogger<JsonReportExporter> logger)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public async Task ExportJsonAsync(ScanSession session, string destinationFilePath, CancellationToken cancellationToken = default)
    {
        if (session == null) throw new ArgumentNullException(nameof(session));
        if (string.IsNullOrWhiteSpace(destinationFilePath)) throw new ArgumentException("Destination file path cannot be null or empty.", nameof(destinationFilePath));

        _logger.LogInformation("JsonReportExporter: Exporting scan session [{SessionId}] report to '{FilePath}'", session.SessionId, destinationFilePath);

        var dir = Path.GetDirectoryName(destinationFilePath);
        if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
        {
            Directory.CreateDirectory(dir);
        }

        using var stream = File.Create(destinationFilePath);
        await JsonSerializer.SerializeAsync(stream, session, JsonOptions, cancellationToken).ConfigureAwait(false);
    }
}
