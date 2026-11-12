using System.Linq;
using System.Text.Json;
using System.Text.Json.Nodes;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// OWASP API risk: client-controlled fields in JSON or form bodies that the server should ignore (e.g. role, UserId, balance).
/// </summary>
public static class MassAssignmentProbes
{
    public sealed class MassAssignmentResult
    {
        public int BaselineStatus { get; init; }
        public string? BaselineBodySample { get; init; }
        /// <summary><c>json</c> or <c>form</c>.</summary>
        public string BodyKind { get; init; } = "json";
        public List<MassAssignmentRow> Probes { get; init; } = [];
        public List<string> Summary { get; init; } = [];
        public List<string> FieldsTested { get; init; } = [];
    }

    public sealed class MassAssignmentRow
    {
        public string Field { get; init; } = "";
        public string? InjectedValue { get; init; }
        public int Status { get; init; }
        public bool ValueReflected { get; init; }
        public bool? ValuePersisted { get; init; }
        /// <summary>Why reflected/persisted was set. Short tokens in unrelated HTML are not a hit.</summary>
        public string? Evidence { get; init; }
        public string? VerifyFetchUrl { get; init; }
        public string? BodySnippet { get; init; }
    }

    private static readonly string[] DefaultPrivilegedPatterns =
    [
        "role", "roles", "isadmin", "is_admin", "admin", "privilege", "root",
        "balance", "credit", "wallet", "salary", "points",
        "userid", "user_id", "ownerid", "owner_id", "createdby", "created_by", "accountid", "basketid", "orderid", "isvip"
    ];

    public static async Task<MassAssignmentResult> RunAsync(
        AutomationContext ctx,
        string url,
        string method,
        IReadOnlyDictionary<string, string>? headers,
        string jsonBody,
        IReadOnlyList<string>? extraPrivilegedFields,
        int timeoutMs,
        bool verifyPersistence = false,
        string? verifyFetchUrl = null,
        string verifyFetchMethod = "GET",
        CancellationToken ct = default)
    {
        method = string.IsNullOrWhiteSpace(method) ? "POST" : method.Trim().ToUpperInvariant();
        var head = headers is { Count: > 0 }
            ? new Dictionary<string, string>(headers, StringComparer.OrdinalIgnoreCase)
            : new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        head.TryGetValue("Content-Type", out var contentType);
        if (!MassAssignmentEvidence.TryPrepare(jsonBody, contentType, out var bodyModel, out var prepareError) || bodyModel == null)
            throw new ArgumentException(prepareError);

        if (!head.ContainsKey("Content-Type"))
            head["Content-Type"] = bodyModel.ContentType;

        var baseJson = await ctx.Fetch(url, method, head, bodyModel.Serialize(), timeoutMs);
        var (bStatus, bText, _) = ParseFetchJsonForProbe(baseJson);

        var candidates = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (extraPrivilegedFields != null)
        {
            foreach (var f in extraPrivilegedFields)
                if (!string.IsNullOrWhiteSpace(f)) candidates.Add(f.Trim());
        }
        foreach (var name in bodyModel.FieldNames)
        {
            if (DefaultPrivilegedMatch(name)) candidates.Add(name);
        }
        JsonObject? respObj = null;
        if (TryGetJsonObject(bText, out var ro))
            respObj = ro;
        else
            TryGetJsonInArray(bText, out respObj);
        if (respObj != null)
        {
            foreach (var p in respObj)
            {
                if (DefaultPrivilegedMatch(p.Key)) candidates.Add(p.Key);
            }
        }
        foreach (var name in MassAssignmentEvidence.HtmlControlNames(bText))
        {
            if (DefaultPrivilegedMatch(name)) candidates.Add(name);
        }

        var fields = candidates.ToList();
        var probes = new List<MassAssignmentRow>();
        var summary = new List<string>();

        if (fields.Count == 0)
        {
            summary.Add("No candidate server-controlled field names were found — pass privilegedFields or use a response/body with keys like role, userId, balance, etc.");
            return new MassAssignmentResult
            {
                BaselineStatus = bStatus,
                BaselineBodySample = Snip(bText, 2000),
                BodyKind = bodyModel.Kind,
                Probes = probes,
                Summary = summary,
                FieldsTested = fields
            };
        }

        string? baselineVerify = null;
        var persistenceUrl = verifyFetchUrl ?? url;
        var verifyMethod = string.IsNullOrWhiteSpace(verifyFetchMethod) ? "GET" : verifyFetchMethod.Trim().ToUpperInvariant();
        if (verifyPersistence)
        {
            var verifyHeaders = VerifyHeaders(head);
            var beforeJson = await ctx.Fetch(persistenceUrl, verifyMethod, verifyHeaders, null, timeoutMs);
            var (_, beforeText, _) = ParseFetchJsonForProbe(beforeJson);
            baselineVerify = beforeText;
        }

        foreach (var field in fields)
        {
            ct.ThrowIfCancellationRequested();
            var (injNode, display) = SuggestTestValue(field);
            var merged = bodyModel.WithInjection(field, injNode, display).Serialize();
            var rJson = await ctx.Fetch(url, method, head, merged, timeoutMs);
            var (st, text, _) = ParseFetchJsonForProbe(rJson);
            var reflected = MassAssignmentEvidence.Matches(text, field, display);
            bool? persisted = null;
            string? rowVerifyUrl = null;
            if (verifyPersistence && st is >= 200 and < 400)
            {
                rowVerifyUrl = persistenceUrl;
                var verifyHeaders = VerifyHeaders(head);
                var verifyJson = await ctx.Fetch(persistenceUrl, verifyMethod, verifyHeaders, null, timeoutMs);
                var (_, verifyText, _) = ParseFetchJsonForProbe(verifyJson);
                persisted = MassAssignmentEvidence.NewlyObserved(baselineVerify, verifyText, field, display);
                if (persisted == true)
                    summary.Add($"Field \"{field}\" changed server state: injected value is present after re-fetch and was absent before ({verifyMethod} {persistenceUrl}).");
            }

            var evidence = persisted == true
                ? "re-fetch shows the injected value and the baseline re-fetch did not"
                : persisted == false && reflected
                    ? "write response echoed the value; re-fetch did not show a new value"
                    : persisted == false
                        ? "re-fetch did not show a new value"
                        : reflected
                            ? "write response echoed the value; persistence was not checked"
                            : "injected value was not observed";

            probes.Add(new MassAssignmentRow
            {
                Field = field,
                InjectedValue = display,
                Status = st,
                ValueReflected = reflected,
                ValuePersisted = persisted,
                Evidence = evidence,
                VerifyFetchUrl = rowVerifyUrl,
                BodySnippet = Snip(text, 2000)
            });
            if (reflected && persisted == null)
                summary.Add($"Field \"{field}\" may be mass-assignable: injected value appears in the write response (status {st}). Re-fetch with verifyPersistence to confirm it stuck.");
            else if (reflected && persisted == false)
                summary.Add($"Field \"{field}\" was echoed in the write response but did not stick on re-fetch.");
        }

        if (probes.Count > 0 && !probes.Any(p => p.ValuePersisted == true || (p.ValueReflected && p.ValuePersisted == null)))
            summary.Add("No injected value was confirmed as reflected or persisted — not conclusive (the server may ignore unknown fields).");

        return new MassAssignmentResult
        {
            BaselineStatus = bStatus,
            BaselineBodySample = Snip(bText, 2000),
            BodyKind = bodyModel.Kind,
            Probes = probes,
            Summary = summary,
            FieldsTested = fields
        };
    }

    private static Dictionary<string, string> VerifyHeaders(Dictionary<string, string> head)
    {
        var verifyHeaders = new Dictionary<string, string>(head, StringComparer.OrdinalIgnoreCase);
        verifyHeaders.Remove("Content-Type");
        verifyHeaders.Remove("Content-Length");
        return verifyHeaders;
    }

    private static bool DefaultPrivilegedMatch(string name)
    {
        var lower = name.ToLowerInvariant();
        foreach (var p in DefaultPrivilegedPatterns)
        {
            if (lower.Contains(p, StringComparison.Ordinal)) return true;
        }
        if (name.Equals("_id", StringComparison.OrdinalIgnoreCase)) return true;
        return false;
    }

    private static (JsonNode value, string display) SuggestTestValue(string field)
    {
        var f = field.ToLowerInvariant();
        if (f.Contains("role", StringComparison.Ordinal) || f.Contains("scope", StringComparison.Ordinal)) return (JsonValue.Create("admin")!, "admin");
        if (f is "isadmin" or "admin" || f.Contains("is_admin", StringComparison.Ordinal)
            || (f.Contains("enabled", StringComparison.Ordinal) && f.Contains("is", StringComparison.Ordinal)))
            return (JsonValue.Create(true)!, "true");
        if (f.Contains("balance", StringComparison.Ordinal) || f.Contains("credit", StringComparison.Ordinal) || f.Contains("wallet", StringComparison.Ordinal) || f.Contains("salary", StringComparison.Ordinal) || f.Contains("points", StringComparison.Ordinal) || f.Contains("price", StringComparison.Ordinal))
            return (JsonValue.Create(999999.99d)!, "999999.99");
        if (f.Contains("userid", StringComparison.Ordinal) || f.Contains("user_id", StringComparison.Ordinal) || f.Contains("ownerid", StringComparison.Ordinal) || f.Contains("accountid", StringComparison.Ordinal) || f.Contains("basketid", StringComparison.Ordinal) || (f.Contains("basket", StringComparison.Ordinal) && f.Contains("id", StringComparison.Ordinal)))
            return (JsonValue.Create(2)!, "2");
        if (f == "_id" || f == "id")
            return (JsonValue.Create("507f1f77bcf86cd799439011")!, "507f1f77bcf86cd799439011");
        if (f.Contains("email", StringComparison.Ordinal)) return (JsonValue.Create("privesc-test@trowser.test")!, "privesc-test@trowser.test");
        return (JsonValue.Create("TrowserMassAssignProveValue9f2c")!, "TrowserMassAssignProveValue9f2c");
    }

    private static bool TryGetJsonObject(string text, out JsonObject? o)
    {
        o = null;
        if (string.IsNullOrWhiteSpace(text)) return false;
        try
        {
            var n = JsonNode.Parse(text);
            o = n as JsonObject;
            return o != null;
        }
        catch
        {
            return false;
        }
    }

    private static bool TryGetJsonInArray(string text, out JsonObject? o)
    {
        o = null;
        try
        {
            var n = JsonNode.Parse(text);
            if (n is JsonArray { Count: > 0 } a && a[0] is JsonObject jo)
            {
                o = jo;
                return true;
            }
        }
        catch
        {
            // ignore
        }
        return false;
    }

    private static (int status, string body, bool ok) ParseFetchJsonForProbe(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            var status = root.GetProperty("status").GetInt32();
            var readBody = root.TryGetProperty("body", out var b)
                ? b.ValueKind == JsonValueKind.String ? b.GetString() ?? "" : b.GetRawText()
                : "";
            var ok = root.TryGetProperty("ok", out var o) && o.ValueKind == JsonValueKind.True;
            return (status, readBody, ok);
        }
        catch
        {
            return (0, "", false);
        }
    }

    private static string? Snip(string? s, int n)
    {
        if (string.IsNullOrEmpty(s)) return s;
        return s.Length <= n ? s : s[..n] + "…";
    }
}
