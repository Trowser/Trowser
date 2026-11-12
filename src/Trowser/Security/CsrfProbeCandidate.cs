namespace Trowser.Security;

/// <summary>State-changing endpoint snapshot for CSRF custom-header probes.</summary>
public sealed class CsrfProbeCandidate
{
    public string Url { get; init; } = "";
    public string Path { get; init; } = "";
    public string Method { get; init; } = "";
    public Dictionary<string, string> RequestHeaders { get; init; } = new();
    public string? RequestBody { get; init; }
    public int OriginalStatus { get; init; }
    public string? OriginalBody { get; init; }
}
