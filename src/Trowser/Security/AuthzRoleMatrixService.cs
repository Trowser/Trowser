using System.Text.Json;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Automated role×endpoint authorization matrix using captured identities.
/// </summary>
public static class AuthzRoleMatrixService
{
    public sealed class MatrixOptions
    {
        public required IReadOnlyList<string> Identities { get; set; }
        public IReadOnlyList<string>? Endpoints { get; set; }
        public IReadOnlyList<AttackSurfaceEndpoint>? AttackSurface { get; set; }
        public bool IncludeAdminEndpoints { get; set; } = true;
        public int MaxEndpoints { get; set; } = 20;
        public int TimeoutMs { get; set; } = 15000;
    }

    public sealed class MatrixCell
    {
        public string Identity { get; init; } = "";
        public string Url { get; init; } = "";
        public string Method { get; init; } = "GET";
        public int Status { get; init; }
        public string Classification { get; init; } = "";
        public string BodyHash { get; init; } = "";
        public int BodyLength { get; init; }
    }

    public sealed class MatrixFinding
    {
        public string Url { get; init; } = "";
        public string Method { get; init; } = "GET";
        public string Finding { get; init; } = "";
        public string Severity { get; init; } = "medium";
        public string Detail { get; init; } = "";
        public List<MatrixCell> Cells { get; init; } = [];
    }

    public sealed class MatrixResult
    {
        public List<MatrixCell> Cells { get; init; } = [];
        public List<MatrixFinding> Findings { get; init; } = [];
        public List<string> EndpointsTested { get; init; } = [];
        public List<string> Summary { get; init; } = [];
    }

    public static async Task<MatrixResult> RunAsync(
        AutomationContext ctx,
        IdentityStore identityStore,
        MatrixOptions options,
        CancellationToken ct = default)
    {
        var identities = options.Identities
            .Where(IdentityStore.IsValidName)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        if (identities.Count < 2)
            throw new ArgumentException("Provide at least two valid identity names (e.g. user, admin).");

        foreach (var name in identities)
        {
            if (identityStore.Load(name) == null)
                throw new InvalidOperationException($"Identity '{name}' not found — capture via POST /api/identity/capture first.");
        }

        var endpoints = BuildEndpoints(options);
        var cells = new List<MatrixCell>();
        var byEndpoint = new Dictionary<string, List<MatrixCell>>(StringComparer.OrdinalIgnoreCase);

        foreach (var ep in endpoints)
        {
            ct.ThrowIfCancellationRequested();
            var method = ep.Method;
            var url = ep.Url;
            var key = $"{method}|{url}";

            foreach (var identity in identities)
            {
                await identityStore.ApplyAsync(ctx, identity, navigateTo: null, verify: null);
                var json = await ctx.Fetch(url, method, null, null, options.TimeoutMs);
                var (status, body) = ParseFetch(json);
                var cell = new MatrixCell
                {
                    Identity = identity,
                    Url = url,
                    Method = method,
                    Status = status,
                    Classification = Classify(status),
                    BodyHash = ComputeHash(body),
                    BodyLength = body.Length
                };
                cells.Add(cell);
                if (!byEndpoint.TryGetValue(key, out var list))
                {
                    list = [];
                    byEndpoint[key] = list;
                }
                list.Add(cell);
            }
        }

        var findings = Analyze(byEndpoint);
        var summary = new List<string>();
        if (findings.Count > 0)
            summary.Add($"{findings.Count} endpoint(s) show role-based authorization anomalies across {identities.Count} identities.");
        else
            summary.Add($"Matrix complete: {endpoints.Count} endpoint(s) × {identities.Count} identities — no BFLA/BOLA matrix anomalies.");

        return new MatrixResult
        {
            Cells = cells,
            Findings = findings,
            EndpointsTested = endpoints.Select(e => e.Url).Distinct(StringComparer.OrdinalIgnoreCase).ToList(),
            Summary = summary
        };
    }

    private sealed record Ep(string Url, string Method);

    private static List<Ep> BuildEndpoints(MatrixOptions options)
    {
        var list = new List<Ep>();
        if (options.Endpoints != null)
        {
            foreach (var u in options.Endpoints)
                if (!string.IsNullOrWhiteSpace(u))
                    list.Add(new Ep(u, "GET"));
        }

        if (options.AttackSurface != null)
        {
            foreach (var ep in options.AttackSurface)
            {
                var method = ep.Methods.FirstOrDefault(m => m.Equals("GET", StringComparison.OrdinalIgnoreCase))
                             ?? ep.Methods.FirstOrDefault() ?? "GET";
                if (options.IncludeAdminEndpoints
                    || ep.UrlTemplate.Contains("admin", StringComparison.OrdinalIgnoreCase)
                    || ep.TestPriority is "high" or "critical")
                    list.Add(new Ep(ep.Url, method));
            }
        }

        return list
            .DistinctBy(e => $"{e.Method}|{e.Url}", StringComparer.OrdinalIgnoreCase)
            .Take(Math.Max(1, options.MaxEndpoints))
            .ToList();
    }

    private static List<MatrixFinding> Analyze(Dictionary<string, List<MatrixCell>> byEndpoint)
    {
        var findings = new List<MatrixFinding>();

        foreach (var (key, cells) in byEndpoint)
        {
            if (cells.Count < 2) continue;

            var allowed = cells.Where(c => c.Classification == "allowed").ToList();
            var denied = cells.Where(c => c.Classification == "denied").ToList();
            if (allowed.Count == 0 || denied.Count == 0) continue;

            var hashes = allowed.Select(c => c.BodyHash).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            var isAdminPath = key.Contains("admin", StringComparison.OrdinalIgnoreCase);

            string finding;
            string severity;
            string detail;

            if (isAdminPath && allowed.Any(c => !c.Identity.Contains("admin", StringComparison.OrdinalIgnoreCase)))
            {
                finding = "BFLA_SUSPECTED";
                severity = "critical";
                detail = "Non-admin identity received success on admin endpoint.";
            }
            else if (hashes.Count == 1 && allowed.Count >= 2)
            {
                finding = "BOLA_SUSPECTED";
                severity = "high";
                detail = "Multiple identities received identical success responses — verify object ownership.";
            }
            else
            {
                finding = "ROLE_DIFFERENCE";
                severity = "medium";
                detail = "Different identities get different access on the same endpoint — review manually.";
            }

            var parts = key.Split('|', 2);
            findings.Add(new MatrixFinding
            {
                Url = parts.Length > 1 ? parts[1] : key,
                Method = parts[0],
                Finding = finding,
                Severity = severity,
                Detail = detail,
                Cells = cells
            });
        }

        return findings;
    }

    private static string Classify(int status) => status switch
    {
        >= 200 and < 300 => "allowed",
        401 or 403 => "denied",
        >= 500 => "error",
        _ => "other"
    };

    private static string ComputeHash(string body)
    {
        if (string.IsNullOrEmpty(body)) return "empty";
        var hash = System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(body));
        return Convert.ToHexString(hash)[..16].ToLowerInvariant();
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
