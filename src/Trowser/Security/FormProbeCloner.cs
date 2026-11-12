using System.Text.Json;
using System.Web;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Clones full HTML form submissions (including Submit buttons and hidden fields) when building
/// injection probes. Classic PHP apps often ignore the request unless sibling fields are present.
/// </summary>
public static class FormProbeCloner
{
    /// <summary>
    /// When <paramref name="url"/> targets a GET form on the current page, ensure non-injected
    /// fields (e.g. <c>Submit=Submit</c>, CSRF tokens) are preserved alongside the marker param.
    /// </summary>
    public static async Task<string> MergeGetFormSiblingsAsync(
        AutomationContext ctx,
        string url,
        string injectParam,
        CancellationToken ct = default)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            return url;

        ct.ThrowIfCancellationRequested();
        var forms = await CaptureFormsAsync(ctx);
        if (forms.Count == 0)
            return url;

        var targetPath = uri.GetLeftPart(UriPartial.Path);
        foreach (var form in forms)
        {
            if (!string.Equals(form.Method, "GET", StringComparison.OrdinalIgnoreCase))
                continue;
            if (!Uri.TryCreate(form.Action, UriKind.Absolute, out var actionUri))
                continue;
            if (!string.Equals(actionUri.GetLeftPart(UriPartial.Path), targetPath, StringComparison.OrdinalIgnoreCase))
                continue;
            if (!form.Fields.Any(f => f.Name.Equals(injectParam, StringComparison.OrdinalIgnoreCase)))
                continue;

            return BuildGetUrlWithSiblings(uri, injectParam, form);
        }

        return url;
    }

    /// <summary>
    /// Build a GET URL that keeps existing query keys, adds missing sibling form fields, and
    /// ensures <paramref name="injectParam"/> carries a literal §marker§ (or keeps an existing one).
    /// </summary>
    public static string BuildGetUrlWithSiblings(Uri uri, string injectParam, CapturedForm form)
    {
        var qs = HttpUtility.ParseQueryString(uri.Query);
        foreach (var field in form.Fields)
        {
            if (field.Name.Equals(injectParam, StringComparison.OrdinalIgnoreCase))
                continue;
            if (qs.AllKeys?.Any(k => k != null && k.Equals(field.Name, StringComparison.OrdinalIgnoreCase)) == true)
                continue;
            // Prefer submit-button value when present; otherwise keep captured value / field name.
            qs[field.Name] = string.IsNullOrEmpty(field.Value) && field.IsSubmit
                ? field.Name
                : field.Value;
        }

        var marker = "§" + injectParam + "§";
        var existing = qs[injectParam];
        if (string.IsNullOrEmpty(existing)
            || (!existing.Contains('§', StringComparison.Ordinal) && !existing.Contains("{{", StringComparison.Ordinal)))
            qs[injectParam] = marker;

        // Rebuild without percent-encoding the marker so RequestMarkerSubstitute can find it.
        var parts = new List<string>();
        foreach (string? key in qs.AllKeys ?? [])
        {
            if (key == null) continue;
            var val = qs[key] ?? "";
            if (key.Equals(injectParam, StringComparison.OrdinalIgnoreCase)
                && (val.Contains('§', StringComparison.Ordinal) || val.Contains("{{", StringComparison.Ordinal)))
                parts.Add($"{Uri.EscapeDataString(key)}={val}");
            else
                parts.Add($"{Uri.EscapeDataString(key)}={Uri.EscapeDataString(val)}");
        }

        return uri.GetLeftPart(UriPartial.Path) + "?" + string.Join("&", parts);
    }

    public static async Task<List<CapturedForm>> CaptureFormsAsync(AutomationContext ctx)
    {
        const string js = """
            (function(){
              var out=[];
              document.querySelectorAll('form').forEach(function(form){
                var action=form.action||location.href;
                var method=(form.method||'GET').toUpperCase();
                var fields=[];
                form.querySelectorAll('input,textarea,select,button').forEach(function(el){
                  var name=el.name||'';
                  if(!name) return;
                  var type=(el.type||el.tagName||'').toLowerCase();
                  var isSubmit = type==='submit' || type==='image' || (el.tagName==='BUTTON' && (type==='submit'||!el.type));
                  if(type==='button' && !isSubmit) return;
                  fields.push({
                    name:name,
                    value:(el.value||'').substring(0,500),
                    type:type,
                    isSubmit:!!isSubmit
                  });
                });
                out.push({action:action,method:method,fields:fields});
              });
              return JSON.stringify(out);
            })()
            """;

        try
        {
            var json = await ctx.ExecuteJs(js);
            if (string.IsNullOrWhiteSpace(json))
                return [];

            using var doc = JsonDocument.Parse(json);
            var list = new List<CapturedForm>();
            foreach (var el in doc.RootElement.EnumerateArray())
            {
                var form = new CapturedForm
                {
                    Action = el.TryGetProperty("action", out var a) ? a.GetString() ?? "" : "",
                    Method = el.TryGetProperty("method", out var m) ? m.GetString() ?? "GET" : "GET"
                };
                if (el.TryGetProperty("fields", out var fields) && fields.ValueKind == JsonValueKind.Array)
                {
                    foreach (var f in fields.EnumerateArray())
                    {
                        var name = f.TryGetProperty("name", out var n) ? n.GetString() ?? "" : "";
                        if (string.IsNullOrWhiteSpace(name)) continue;
                        form.Fields.Add(new CapturedFormField
                        {
                            Name = name,
                            Value = f.TryGetProperty("value", out var v) ? v.GetString() ?? "" : "",
                            Type = f.TryGetProperty("type", out var t) ? t.GetString() ?? "" : "",
                            IsSubmit = f.TryGetProperty("isSubmit", out var s) && s.ValueKind == JsonValueKind.True
                        });
                    }
                }

                if (form.Fields.Count > 0)
                    list.Add(form);
            }

            return list;
        }
        catch
        {
            return [];
        }
    }

    public sealed class CapturedForm
    {
        public string Action { get; init; } = "";
        public string Method { get; init; } = "GET";
        public List<CapturedFormField> Fields { get; } = [];
    }

    public sealed class CapturedFormField
    {
        public string Name { get; init; } = "";
        public string Value { get; init; } = "";
        public string Type { get; init; } = "";
        public bool IsSubmit { get; init; }
    }
}
