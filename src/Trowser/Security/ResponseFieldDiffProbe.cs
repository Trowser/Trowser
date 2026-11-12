using System.Text.Json;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Detects excessive data exposure by diffing JSON field paths between two identity sessions.
/// </summary>
public static class ResponseFieldDiffProbe
{
    public sealed class DiffOptions
    {
        public required string LowPrivilegeIdentity { get; set; }
        public required string HighPrivilegeIdentity { get; set; }
        public IReadOnlyList<string>? Endpoints { get; set; }
        public IReadOnlyList<AttackSurfaceEndpoint>? AttackSurface { get; set; }
        public int MaxEndpoints { get; set; } = 10;
        public int TimeoutMs { get; set; } = 15000;
        public bool DiscoverFromAttackSurface { get; set; } = true;
    }

    public sealed class DiffRow
    {
        public string Url { get; init; } = "";
        public string Method { get; init; } = "GET";
        public int LowStatus { get; init; }
        public int HighStatus { get; init; }
        public List<string> FieldsOnlyInHigh { get; init; } = [];
        public List<string> SensitiveFieldsOnlyInHigh { get; init; } = [];
        public string Severity { get; init; } = "medium";
    }

    public sealed class DiffResult
    {
        public List<DiffRow> Rows { get; init; } = [];
        public List<DiffRow> Findings { get; init; } = [];
        public List<string> Summary { get; init; } = [];
    }

    private static readonly string[] SensitiveFieldTokens =
    [
        "password", "secret", "token", "ssn", "salary", "balance", "credit",
        "role", "permission", "admin", "internal", "private", "apikey", "api_key"
    ];

    public static async Task<DiffResult> RunAsync(
        AutomationContext ctx,
        IdentityStore identityStore,
        DiffOptions options,
        CancellationToken ct = default)
    {
        if (!IdentityStore.IsValidName(options.LowPrivilegeIdentity)
            || !IdentityStore.IsValidName(options.HighPrivilegeIdentity))
            throw new ArgumentException("lowPrivilegeIdentity and highPrivilegeIdentity must be valid captured identity names.");

        var lowSnap = identityStore.Load(options.LowPrivilegeIdentity)
            ?? throw new InvalidOperationException($"Identity '{options.LowPrivilegeIdentity}' not found.");
        var highSnap = identityStore.Load(options.HighPrivilegeIdentity)
            ?? throw new InvalidOperationException($"Identity '{options.HighPrivilegeIdentity}' not found.");

        var urls = BuildEndpointList(ctx, options);
        var rows = new List<DiffRow>();
        var findings = new List<DiffRow>();

        foreach (var url in urls)
        {
            ct.ThrowIfCancellationRequested();
            var lowJson = await FetchAsIdentityAsync(ctx, identityStore, lowSnap.Name, url, "GET", options.TimeoutMs);
            var highJson = await FetchAsIdentityAsync(ctx, identityStore, highSnap.Name, url, "GET", options.TimeoutMs);
            var (lowStatus, lowBody) = ParseFetch(lowJson);
            var (highStatus, highBody) = ParseFetch(highJson);

            if (lowStatus is < 200 or >= 300 || highStatus is < 200 or >= 300)
                continue;

            var lowFields = CollectJsonPaths(lowBody);
            var highFields = CollectJsonPaths(highBody);
            var onlyHigh = highFields.Except(lowFields, StringComparer.OrdinalIgnoreCase).OrderBy(f => f).ToList();
            if (onlyHigh.Count == 0) continue;

            var sensitive = onlyHigh.Where(IsSensitiveField).ToList();
            var row = new DiffRow
            {
                Url = url,
                LowStatus = lowStatus,
                HighStatus = highStatus,
                FieldsOnlyInHigh = onlyHigh,
                SensitiveFieldsOnlyInHigh = sensitive,
                Severity = sensitive.Count > 0 ? "high" : "medium"
            };
            rows.Add(row);
            if (onlyHigh.Count >= 2 || sensitive.Count > 0)
                findings.Add(row);
        }

        var summary = new List<string>();
        if (findings.Count > 0)
            summary.Add($"{findings.Count} endpoint(s) return extra fields for '{options.HighPrivilegeIdentity}' vs '{options.LowPrivilegeIdentity}'.");
        else
            summary.Add($"Compared {urls.Count} endpoint(s); no excessive field exposure detected between identities.");

        return new DiffResult { Rows = rows, Findings = findings, Summary = summary };
    }

    private static List<string> BuildEndpointList(AutomationContext ctx, DiffOptions options)
    {
        var urls = new List<string>();
        if (options.Endpoints is { Count: > 0 })
            urls.AddRange(options.Endpoints);

        if (options.DiscoverFromAttackSurface && options.AttackSurface != null)
        {
            foreach (var ep in options.AttackSurface)
            {
                if (ep.Methods.Contains("GET", StringComparer.OrdinalIgnoreCase)
                    && ep.Auth.Required
                    && !ep.UrlTemplate.Contains("admin", StringComparison.OrdinalIgnoreCase))
                    urls.Add(ep.Url);
            }
        }

        return urls
            .Where(u => !string.IsNullOrWhiteSpace(u))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(Math.Max(1, options.MaxEndpoints))
            .ToList();
    }

    private static async Task<string> FetchAsIdentityAsync(
        AutomationContext ctx, IdentityStore store, string identityName, string url, string method, int timeoutMs)
    {
        await store.ApplyAsync(ctx, identityName, navigateTo: null, verify: null);
        return await ctx.Fetch(url, method, null, null, timeoutMs);
    }

    private static HashSet<string> CollectJsonPaths(string json)
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            using var doc = JsonDocument.Parse(json);
            Walk(doc.RootElement, "", set);
        }
        catch { /* non-json */ }
        return set;
    }

    private static void Walk(JsonElement el, string prefix, HashSet<string> paths)
    {
        switch (el.ValueKind)
        {
            case JsonValueKind.Object:
                foreach (var p in el.EnumerateObject())
                {
                    var path = string.IsNullOrEmpty(prefix) ? p.Name : $"{prefix}.{p.Name}";
                    paths.Add(path);
                    Walk(p.Value, path, paths);
                }
                break;
            case JsonValueKind.Array:
                var i = 0;
                foreach (var item in el.EnumerateArray())
                {
                    var path = $"{prefix}[{i}]";
                    Walk(item, path, paths);
                    i++;
                    if (i >= 3) break;
                }
                break;
        }
    }

    private static bool IsSensitiveField(string path)
    {
        var lower = path.ToLowerInvariant();
        return SensitiveFieldTokens.Any(t => lower.Contains(t, StringComparison.Ordinal));
    }

    private static (int status, string body) ParseFetch(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            var status = root.GetProperty("status").GetInt32();
            var body = root.TryGetProperty("body", out var b)
                ? b.ValueKind == JsonValueKind.String ? b.GetString() ?? "" : b.GetRawText()
                : "";
            return (status, body);
        }
        catch
        {
            return (0, "");
        }
    }
}
