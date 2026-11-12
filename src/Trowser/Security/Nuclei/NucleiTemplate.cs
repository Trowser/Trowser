namespace Trowser.Security.Nuclei;

public sealed class NucleiTemplate
{
    public string Id { get; init; } = "";
    public string Name { get; init; } = "";
    public string Author { get; init; } = "";
    public string Severity { get; init; } = "info";
    public List<string> Tags { get; init; } = [];
    public string Description { get; init; } = "";
    public List<NucleiHttpRequest> HttpRequests { get; init; } = [];

    /// <summary>Origin of the template: "embedded" (built-in subset) or "user" (templatesDir).</summary>
    public string Source { get; set; } = "embedded";
}

public sealed class NucleiHttpRequest
{
    public string Method { get; init; } = "GET";
    public List<string> Paths { get; init; } = [];
    /// <summary>Expanded path segments from <c>payloads.paths</c> (when the template uses <c>{{paths}}</c>).</summary>
    public List<string> PathPayloadValues { get; init; } = [];
    public Dictionary<string, string> Headers { get; init; } = new(StringComparer.OrdinalIgnoreCase);
    public string? Body { get; init; }
    public string MatchersCondition { get; init; } = "and";
    public List<NucleiMatcher> Matchers { get; init; } = [];
    public bool StopAtFirstMatch { get; init; }
}

public sealed class NucleiMatcher
{
    public string Type { get; init; } = "";
    public string Part { get; init; } = "body";
    public List<string> Words { get; init; } = [];
    public List<string> Regex { get; init; } = [];
    public List<int> Status { get; init; } = [];
    public List<string> Headers { get; init; } = [];
    public string Condition { get; init; } = "or";
    public bool Negative { get; init; }
}
