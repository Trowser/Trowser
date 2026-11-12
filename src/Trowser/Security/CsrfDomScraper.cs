using System.Text.Json;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Live-page CSRF extraction via direct DOM queries (never <c>interactiveElements</c>).
/// Returns form-action bindings so probes can pick the token for the target endpoint.
/// </summary>
public static class CsrfDomScraper
{
    private static readonly string[] ExplicitFieldNames =
    [
        "csrf", "_csrf", "csrf_token", "csrfmiddlewaretoken", "_token",
        "__RequestVerificationToken", "authenticity_token", "anti_forgery_token",
        "_csrf_token", "xsrf-token", "xsrf_token", "user_token", "form_token",
        "session_token", "security_token", "request_token", "verification_token", "nonce", "_nonce"
    ];

    private const string ScrapeJs = """
        (function(){
          try {
            var tokens = {};
            var forms = [];
            var explicitNames = __EXPLICIT_NAMES__;

            function addFlat(name, value) {
              if (name && value && !tokens[name]) tokens[name] = value;
            }

            function queryInRoot(root, selector) {
              try { return root.querySelector(selector); } catch (e) { return null; }
            }

            function queryAllInRoot(root, selector) {
              try { return Array.from(root.querySelectorAll(selector)); } catch (e) { return []; }
            }

            function walkRoots(root, fn) {
              fn(root);
              queryAllInRoot(root, '*').forEach(function(el) {
                if (el.shadowRoot) walkRoots(el.shadowRoot, fn);
              });
            }

            function readInput(el) {
              var name = el.getAttribute('name') || el.name || '';
              var val = el.value || el.getAttribute('value') || '';
              var type = (el.getAttribute('type') || el.type || '').toLowerCase();
              return { name: name, value: val, type: type };
            }

            function isCsrfName(name) {
              if (!name) return false;
              var lower = name.toLowerCase();
              if (lower === 'csrf' || lower.indexOf('csrf') >= 0 || lower.indexOf('xsrf') >= 0) return true;
              if (lower.indexOf('forgery') >= 0 || lower === '_token') return true;
              return explicitNames.some(function(n) { return n.toLowerCase() === lower; });
            }

            function findCsrfInput(form) {
              var direct = form.querySelector('input[type=hidden][name=csrf]')
                        || form.querySelector('input[type=hidden][name="csrf"]');
              if (direct) return readInput(direct);
              var inputs = form.querySelectorAll('input[type=hidden], input[type="hidden"]');
              for (var i = 0; i < inputs.length; i++) {
                var field = readInput(inputs[i]);
                if (isCsrfName(field.name) && field.value) return field;
              }
              return null;
            }

            function collectForm(root, form) {
              var csrfField = findCsrfInput(form);
              if (!csrfField || !csrfField.value) return;
              var hidden = {};
              queryAllInRoot(form, 'input[type=hidden], input[type="hidden"]').forEach(function(el) {
                var f = readInput(el);
                if (f.name && f.value) hidden[f.name] = f.value;
              });
              forms.push({
                action: form.action || location.href,
                method: (form.getAttribute('method') || form.method || 'GET').toUpperCase(),
                enctype: form.enctype || form.getAttribute('enctype') || '',
                fieldName: csrfField.name,
                value: csrfField.value,
                hiddenFields: hidden
              });
              addFlat(csrfField.name, csrfField.value);
            }

            walkRoots(document, function(root) {
              queryAllInRoot(root, 'form').forEach(function(form) { collectForm(root, form); });
            });

            walkRoots(document, function(root) {
              explicitNames.forEach(function(fieldName) {
                var escaped = fieldName.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
                var el = queryInRoot(root, 'input[type=hidden][name="' + escaped + '"]')
                      || queryInRoot(root, 'input[name="' + escaped + '"]');
                if (!el) return;
                var field = readInput(el);
                if (field.name && field.value) addFlat(field.name, field.value);
              });
            });

            walkRoots(document, function(root) {
              queryAllInRoot(root, 'meta[name]').forEach(function(m) {
                var name = m.getAttribute('name') || '';
                var content = m.getAttribute('content') || '';
                if (!name || !content) return;
                var lower = name.toLowerCase();
                if (lower.indexOf('csrf') >= 0 || lower.indexOf('xsrf') >= 0 || lower.indexOf('forgery') >= 0)
                  addFlat(name, content);
              });
            });

            return JSON.stringify({ tokens: tokens, forms: forms, pageUrl: location.href });
          } catch (e) {
            return JSON.stringify({ error: e.message || String(e), tokens: {}, forms: [] });
          }
        })()
        """;

    public sealed class FormBinding
    {
        public string FormAction { get; init; } = "";
        public string Method { get; init; } = "POST";
        public string Enctype { get; init; } = "";
        public string FieldName { get; init; } = "csrf";
        public string Value { get; init; } = "";
        public Dictionary<string, string> HiddenFields { get; init; } = new(StringComparer.OrdinalIgnoreCase);
    }

    public sealed class ScrapeResult
    {
        public Dictionary<string, string> Tokens { get; set; } = new(StringComparer.OrdinalIgnoreCase);
        public List<FormBinding> Forms { get; set; } = [];
        public string PageUrl { get; set; } = "";
        public bool HasTokens => Tokens.Count > 0 || Forms.Any(f => !string.IsNullOrEmpty(f.Value));
    }

    public static async Task<ScrapeResult> ScrapeDetailedAsync(AutomationContext ctx)
    {
        var result = new ScrapeResult();
        try
        {
            var namesJson = JsonSerializer.Serialize(ExplicitFieldNames);
            var js = ScrapeJs.Replace("__EXPLICIT_NAMES__", namesJson);
            var json = await ctx.ExecuteJs(js);
            if (string.IsNullOrWhiteSpace(json)) return result;

            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            if (root.TryGetProperty("error", out _))
                return result;

            if (root.TryGetProperty("pageUrl", out var pageUrlEl) && pageUrlEl.ValueKind == JsonValueKind.String)
                result.PageUrl = pageUrlEl.GetString() ?? "";

            if (root.TryGetProperty("tokens", out var tokEl) && tokEl.ValueKind == JsonValueKind.Object)
            {
                foreach (var prop in tokEl.EnumerateObject())
                {
                    if (prop.Value.ValueKind != JsonValueKind.String) continue;
                    var val = prop.Value.GetString();
                    if (!string.IsNullOrWhiteSpace(prop.Name) && !string.IsNullOrWhiteSpace(val))
                        result.Tokens[prop.Name] = val;
                }
            }

            if (root.TryGetProperty("forms", out var formsEl) && formsEl.ValueKind == JsonValueKind.Array)
            {
                foreach (var formEl in formsEl.EnumerateArray())
                {
                    var binding = ParseFormBinding(formEl);
                    if (binding != null)
                        result.Forms.Add(binding);
                }
            }
        }
        catch
        {
            // Best-effort — callers classify CSRF-blocked responses.
        }

        return result;
    }

    public static async Task<Dictionary<string, string>> ScrapeAsync(AutomationContext ctx)
    {
        var detailed = await ScrapeDetailedAsync(ctx);
        return detailed.Tokens;
    }

    public static FormBinding? PickFormForTarget(ScrapeResult scrape, string? targetUrl)
    {
        if (string.IsNullOrWhiteSpace(targetUrl) || scrape.Forms.Count == 0)
            return null;

        if (!Uri.TryCreate(targetUrl, UriKind.Absolute, out var targetUri))
            return null;

        FormBinding? best = null;
        var bestScore = -1;

        foreach (var form in scrape.Forms)
        {
            if (!Uri.TryCreate(form.FormAction, UriKind.Absolute, out var formUri))
                continue;

            var score = ScoreFormActionMatch(targetUri, formUri);
            if (score > bestScore)
            {
                bestScore = score;
                best = form;
            }
        }

        return bestScore >= 0 ? best : null;
    }

    private static int ScoreFormActionMatch(Uri target, Uri formAction)
    {
        if (string.Equals(target.AbsoluteUri, formAction.AbsoluteUri, StringComparison.OrdinalIgnoreCase))
            return 100;
        if (string.Equals(target.AbsolutePath, formAction.AbsolutePath, StringComparison.OrdinalIgnoreCase))
            return 90;
        if (target.AbsolutePath.EndsWith(formAction.AbsolutePath, StringComparison.OrdinalIgnoreCase))
            return 80;
        if (formAction.AbsolutePath.EndsWith(target.AbsolutePath, StringComparison.OrdinalIgnoreCase))
            return 70;
        return -1;
    }

    private static FormBinding? ParseFormBinding(JsonElement formEl)
    {
        var value = formEl.TryGetProperty("value", out var v) ? v.GetString() ?? "" : "";
        if (string.IsNullOrWhiteSpace(value)) return null;

        var hidden = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (formEl.TryGetProperty("hiddenFields", out var hiddenEl) && hiddenEl.ValueKind == JsonValueKind.Object)
        {
            foreach (var prop in hiddenEl.EnumerateObject())
            {
                if (prop.Value.ValueKind == JsonValueKind.String)
                {
                    var hv = prop.Value.GetString();
                    if (!string.IsNullOrWhiteSpace(hv))
                        hidden[prop.Name] = hv;
                }
            }
        }

        return new FormBinding
        {
            FormAction = formEl.TryGetProperty("action", out var a) ? a.GetString() ?? "" : "",
            Method = formEl.TryGetProperty("method", out var m) ? m.GetString() ?? "POST" : "POST",
            Enctype = formEl.TryGetProperty("enctype", out var e) ? e.GetString() ?? "" : "",
            FieldName = formEl.TryGetProperty("fieldName", out var fn) ? fn.GetString() ?? "csrf" : "csrf",
            Value = value,
            HiddenFields = hidden
        };
    }
}
