using System.Text.Json;
using System.Text.Json.Serialization;

namespace Trowser.EndpointProbe;

public static class EndpointProbeStore
{
    public const int FileVersion = 1;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    public static string Export(IEnumerable<EndpointProbeItem> items)
    {
        var payload = new ExportDocument
        {
            Version = FileVersion,
            Endpoints = items.Select(ToDto).ToList()
        };
        return JsonSerializer.Serialize(payload, JsonOptions);
    }

    public static List<EndpointProbeItem> Import(string json)
    {
        var doc = JsonSerializer.Deserialize<ExportDocument>(json, JsonOptions)
            ?? throw new InvalidOperationException("Invalid endpoint probe file (empty document).");

        if (doc.Endpoints == null || doc.Endpoints.Count == 0)
            throw new InvalidOperationException("No endpoints found in file.");

        return doc.Endpoints
            .Where(d => !string.IsNullOrWhiteSpace(d.Url) && !string.IsNullOrWhiteSpace(d.Method))
            .Select(FromDto)
            .ToList();
    }

    private static EndpointDto ToDto(EndpointProbeItem item) => new()
    {
        Method = item.Method,
        Url = item.Url,
        Priority = item.Priority,
        RequestHeaders = item.RequestHeaders.Count > 0 ? item.RequestHeaders : null,
        RequestBody = item.RequestBody,
        StatusCode = item.StatusCode,
        ResourceType = item.ResourceType
    };

    private static EndpointProbeItem FromDto(EndpointDto dto) => new()
    {
        Method = dto.Method!.Trim().ToUpperInvariant(),
        Url = dto.Url!.Trim(),
        Priority = dto.Priority ?? "low",
        RequestHeaders = dto.RequestHeaders != null
            ? new Dictionary<string, string>(dto.RequestHeaders, StringComparer.OrdinalIgnoreCase)
            : new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase),
        RequestBody = dto.RequestBody,
        StatusCode = dto.StatusCode,
        ResourceType = dto.ResourceType,
        IsImported = true
    };

    private sealed class ExportDocument
    {
        public int Version { get; set; } = FileVersion;
        public List<EndpointDto>? Endpoints { get; set; }
    }

    private sealed class EndpointDto
    {
        public string? Method { get; set; }
        public string? Url { get; set; }
        public string? Priority { get; set; }
        public Dictionary<string, string>? RequestHeaders { get; set; }
        public string? RequestBody { get; set; }
        public int? StatusCode { get; set; }
        public string? ResourceType { get; set; }
    }
}
