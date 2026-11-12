using System.Text.Json;

namespace Trowser.Security;

internal static class PostMessageProbeBuilder
{
    public const string AttackerOrigin = "https://evil.trowser.test";

    public static string ProbePageUrl(string runId, string topology, string? attackerOrigin = null) =>
        $"{(string.IsNullOrWhiteSpace(attackerOrigin) ? AttackerOrigin : attackerOrigin.TrimEnd('/'))}/pm/{runId}/{topology}";

    /// <summary>Attacker page that posts schema payload into parent (child-iframe topology).</summary>
    public static string BuildChildIframeHtml(string payloadJson, string targetOriginWildcard = "*")
    {
        var payload = JsonSerializer.Serialize(payloadJson);
        var target = JsonSerializer.Serialize(targetOriginWildcard);
        return $$"""
<!DOCTYPE html><html><body><script>
(function(){
  var payload = {{payload}};
  try {
    var data = JSON.parse(payload);
    parent.postMessage(data, {{target}});
  } catch(e) {
    try { parent.postMessage(payload, {{target}}); } catch(e2) {}
  }
  try { document.title = 'TROUSER_PM:posted'; } catch(e3) {}
})();
</script></body></html>
""";
    }

    /// <summary>Attacker popup page that posts to opener (popup-to-opener topology).</summary>
    public static string BuildPopupToOpenerHtml(string payloadJson)
    {
        var payload = JsonSerializer.Serialize(payloadJson);
        return $$"""
<!DOCTYPE html><html><body><script>
(function(){
  var payload = {{payload}};
  var ok = false;
  try {
    if (window.opener && !window.opener.closed) {
      var data = JSON.parse(payload);
      window.opener.postMessage(data, '*');
      ok = true;
    }
  } catch(e) {}
  try { document.title = ok ? 'TROUSER_PM:opener-posted' : 'TROUSER_PM:opener-blocked'; } catch(e2) {}
})();
</script></body></html>
""";
    }

    public static string BuildFramedTargetHtml(string victimUrl, string payloadJson)
    {
        var victim = JsonSerializer.Serialize(victimUrl);
        var payload = JsonSerializer.Serialize(payloadJson);
        return $$"""
<!DOCTYPE html><html><body><script>
(function(){
  var victim = {{victim}};
  var payload = {{payload}};
  var iframe = document.createElement('iframe');
  iframe.style.display = 'none';
  iframe.onload = function() {
    try {
      var data = JSON.parse(payload);
      iframe.contentWindow.postMessage(data, '*');
    } catch(e) {
      try { iframe.contentWindow.postMessage(payload, '*'); } catch(e2) {}
    }
    try { document.title = 'TROUSER_PM:framed-posted'; } catch(e3) {}
  };
  iframe.src = victim;
  document.body.appendChild(iframe);
})();
</script></body></html>
""";
    }

    public static string BuildOpenerToPopupHtml(string victimUrl, string payloadJson)
    {
        var victim = JsonSerializer.Serialize(victimUrl);
        var payload = JsonSerializer.Serialize(payloadJson);
        return $$"""
<!DOCTYPE html><html><body><script>
(function(){
  var victim = {{victim}};
  var payload = {{payload}};
  var w = window.open(victim, '_blank');
  setTimeout(function(){
    try {
      if (w && !w.closed) {
        var data = JSON.parse(payload);
        w.postMessage(data, '*');
      }
    } catch(e) {
      try { if (w && !w.closed) w.postMessage(payload, '*'); } catch(e2) {}
    }
    try { document.title = w ? 'TROUSER_PM:popup-posted' : 'TROUSER_PM:popup-blocked'; } catch(e3) {}
  }, 2500);
})();
</script></body></html>
""";
    }

    public static string WatermarkPocHtml(string topology, string payloadPreview) =>
        $"<!-- Trowser postMessage PoC topology={topology} -->\n" +
        BuildChildIframeHtml(payloadPreview);
}
