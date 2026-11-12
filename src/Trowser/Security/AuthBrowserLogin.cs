using System.Text.Json;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Browser-DOM login for auth probes — fills forms in the live page so CSRF tokens,
/// hidden fields, and multi-step flows work without constructing raw HTTP requests.
/// </summary>
public static class AuthBrowserLogin
{
    public sealed class BrowserSessionLoginResult
    {
        public bool LoginSucceeded { get; init; }
        public string LoginUrl { get; init; } = "";
        public string? FinalUrl { get; init; }
        public List<(string Name, string Value)> PreLoginCookies { get; init; } = [];
        public List<(string Name, string Value)> PostLoginCookies { get; init; } = [];
        public string? Detail { get; init; }
    }

    private const string AnalyzeLoginPageJs = """
        (function(usernameField, passwordField) {
          function css(el) {
            if (!el) return null;
            if (el.id) return '#' + CSS.escape(el.id);
            if (el.name) return 'input[name="' + el.name.replace(/\\/g,'\\\\').replace(/"/g,'\\"') + '"]';
            return null;
          }
          function visible(el) {
            if (!el) return false;
            var r = el.getBoundingClientRect();
            return r.width > 0 && r.height > 0 && el.offsetParent !== null && !el.disabled && !el.readOnly;
          }
          function pickUser(form) {
            if (usernameField) {
              var named = form.querySelector('input[name="' + usernameField.replace(/"/g,'\\"') + '"], #' + CSS.escape(usernameField));
              if (named && visible(named)) return named;
            }
            var inputs = Array.prototype.slice.call(form.querySelectorAll('input'));
            var pass = form.querySelector('input[type=password]');
            var passIdx = pass ? inputs.indexOf(pass) : -1;
            if (passIdx > 0) {
              for (var i = passIdx - 1; i >= 0; i--) {
                var t = (inputs[i].type || '').toLowerCase();
                if (t === 'hidden' || t === 'submit' || t === 'button' || t === 'checkbox' || t === 'radio') continue;
                if (visible(inputs[i])) return inputs[i];
              }
            }
            var q = form.querySelector('input[type=email],input[type=text],input[name*=user i],input[name*=email i],input[id*=user i],input[name*=uid i]');
            return q && visible(q) ? q : null;
          }
          function pickPass(form) {
            if (passwordField) {
              var named = form.querySelector('input[name="' + passwordField.replace(/"/g,'\\"') + '"], #' + CSS.escape(passwordField));
              if (named) return named;
            }
            return form.querySelector('input[type=password]');
          }
          function pickSubmit(form) {
            var buttons = form.querySelectorAll('button, input[type=submit]');
            for (var i = 0; i < buttons.length; i++) {
              var b = buttons[i];
              if (!visible(b)) continue;
              var t = (b.textContent || b.value || '').toLowerCase();
              if (t.indexOf('log in') >= 0 || t.indexOf('login') >= 0 || t.indexOf('sign in') >= 0
                  || t.indexOf('continue') >= 0 || t.indexOf('next') >= 0 || t.indexOf('submit') >= 0)
                return css(b) || null;
            }
            var submit = form.querySelector('input[type=submit], button[type=submit], button:not([type])');
            return submit && visible(submit) ? css(submit) : null;
          }

          var forms = Array.prototype.slice.call(document.querySelectorAll('form'));
          var best = null;
          for (var f = 0; f < forms.length; f++) {
            var form = forms[f];
            var passEl = pickPass(form);
            if (!passEl && !form.querySelector('input[type=password]')) continue;
            var userEl = pickUser(form);
            var passVisible = passEl && visible(passEl);
            var userVisible = userEl && visible(userEl);
            if (!passVisible && !userVisible) continue;
            best = {
              usernameSelector: userEl ? css(userEl) : null,
              passwordSelector: passEl ? css(passEl) : null,
              passwordVisible: !!passVisible,
              usernameVisible: !!userVisible,
              submitSelector: pickSubmit(form),
              formAction: form.action || location.href
            };
            break;
          }

          if (!best) {
            var loosePass = document.querySelector('input[type=password]');
            var looseUser = document.querySelector('input[type=email],input[type=text],input[name*=user i],input[name*=email i],input[name*=uid i]');
            if (loosePass || looseUser) {
              best = {
                usernameSelector: looseUser && visible(looseUser) ? css(looseUser) : null,
                passwordSelector: loosePass ? css(loosePass) : null,
                passwordVisible: !!(loosePass && visible(loosePass)),
                usernameVisible: !!(looseUser && visible(looseUser)),
                submitSelector: null,
                formAction: location.href
              };
            }
          }

          return JSON.stringify(best);
        })
        """;

    public static async Task<BrowserSessionLoginResult> TrySessionLoginAsync(
        AutomationContext ctx,
        string loginUrl,
        string username,
        string password,
        string? usernameField,
        string? passwordField,
        int timeoutMs,
        CancellationToken ct = default)
    {
        await ctx.Navigate(loginUrl);
        await ctx.WaitForFinalNavigation(400, Math.Min(timeoutMs, 12_000));

        var preCookies = await AuthProbeDiscovery.GetBrowserCookiesAsync(ctx);
        var urlBefore = await ctx.GetCurrentUrl() ?? loginUrl;

        for (var step = 0; step < 3; step++)
        {
            ct.ThrowIfCancellationRequested();
            var state = await ReadLoginPageStateAsync(ctx, usernameField, passwordField, ct);
            if (state == null)
                break;

            if (state.PasswordVisible && !string.IsNullOrEmpty(state.PasswordSelector))
            {
                if (!string.IsNullOrEmpty(state.UsernameSelector))
                    await SafeTypeAsync(ctx, state.UsernameSelector, username, timeoutMs);
                await SafeTypeAsync(ctx, state.PasswordSelector, password, timeoutMs);
            }
            else if (state.UsernameVisible && !string.IsNullOrEmpty(state.UsernameSelector))
            {
                await SafeTypeAsync(ctx, state.UsernameSelector, username, timeoutMs);
            }
            else
            {
                break;
            }

            await SubmitAsync(ctx, state, timeoutMs);
            await ctx.WaitForFinalNavigation(500, Math.Min(timeoutMs, 12_000));

            if (await IsLoginSuccessfulAsync(ctx, urlBefore, ct))
            {
                return new BrowserSessionLoginResult
                {
                    LoginSucceeded = true,
                    LoginUrl = loginUrl,
                    FinalUrl = await ctx.GetCurrentUrl(),
                    PreLoginCookies = preCookies,
                    PostLoginCookies = await AuthProbeDiscovery.GetBrowserCookiesAsync(ctx),
                    Detail = step > 0 ? $"Authenticated after {step + 1} browser form step(s)." : "Authenticated via browser form submit."
                };
            }

            var next = await ReadLoginPageStateAsync(ctx, usernameField, passwordField, ct);
            if (next?.PasswordVisible == true && state.PasswordVisible != true)
                continue;

            break;
        }

        return new BrowserSessionLoginResult
        {
            LoginSucceeded = false,
            LoginUrl = loginUrl,
            FinalUrl = await ctx.GetCurrentUrl(),
            PreLoginCookies = preCookies,
            PostLoginCookies = await AuthProbeDiscovery.GetBrowserCookiesAsync(ctx),
            Detail = "Browser form login did not reach an authenticated page state."
        };
    }

    private static async Task<LoginPageState?> ReadLoginPageStateAsync(
        AutomationContext ctx,
        string? usernameField,
        string? passwordField,
        CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var uField = JsonSerializer.Serialize(usernameField ?? "");
        var pField = JsonSerializer.Serialize(passwordField ?? "");
        var raw = await ctx.ExecuteJs($"{AnalyzeLoginPageJs}({uField},{pField})");
        if (string.IsNullOrWhiteSpace(raw) || raw == "null")
            return null;

        using var doc = JsonDocument.Parse(raw);
        var root = doc.RootElement;
        return new LoginPageState
        {
            UsernameSelector = ReadNullableString(root, "usernameSelector"),
            PasswordSelector = ReadNullableString(root, "passwordSelector"),
            SubmitSelector = ReadNullableString(root, "submitSelector"),
            PasswordVisible = ReadBool(root, "passwordVisible"),
            UsernameVisible = ReadBool(root, "usernameVisible")
        };
    }

    private static string? ReadNullableString(JsonElement root, string name)
    {
        if (!root.TryGetProperty(name, out var el) || el.ValueKind is JsonValueKind.Null or JsonValueKind.Undefined)
            return null;
        return el.GetString();
    }

    private static bool ReadBool(JsonElement root, string name)
    {
        if (!root.TryGetProperty(name, out var el))
            return false;
        return el.ValueKind switch
        {
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            _ => false
        };
    }

    private static async Task SafeTypeAsync(AutomationContext ctx, string selector, string text, int timeoutMs)
    {
        try
        {
            await ctx.Type(selector, text, timeoutMs, clearFirst: true);
        }
        catch
        {
            await ctx.ExecuteJs(BuildDirectFillJs(selector, text));
        }
    }

    private static string BuildDirectFillJs(string selector, string text)
    {
        var sel = JsonSerializer.Serialize(selector);
        var val = JsonSerializer.Serialize(text);
        return $$"""
            (function(){
              var sel = {{sel}};
              var el = document.querySelector(sel);
              if (!el) return 'MISSING';
              var proto = el instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
              var setter = Object.getOwnPropertyDescriptor(proto, 'value')?.set;
              if (setter) setter.call(el, {{val}}); else el.value = {{val}};
              el.dispatchEvent(new Event('input', { bubbles: true }));
              el.dispatchEvent(new Event('change', { bubbles: true }));
              return 'OK';
            })()
            """;
    }

    private static async Task SubmitAsync(AutomationContext ctx, LoginPageState state, int timeoutMs)
    {
        if (!string.IsNullOrEmpty(state.SubmitSelector))
        {
            try
            {
                await ctx.Click(state.SubmitSelector, timeoutMs: timeoutMs);
                return;
            }
            catch { /* fall through to JS submit */ }
        }

        await ctx.ExecuteJs(
            """
            (function(){
              var pass = document.querySelector('input[type=password]');
              var form = pass ? pass.form : document.querySelector('form');
              if (!form) {
                var btn = document.querySelector('button[type=submit], input[type=submit], button');
                if (btn) { btn.click(); return 'clicked'; }
                return 'no-form';
              }
              var btn = form.querySelector('button[type=submit], input[type=submit], button:not([type])');
              if (btn) btn.click();
              else if (form.requestSubmit) form.requestSubmit();
              else form.submit();
              return 'submitted';
            })()
            """);
    }

    private static async Task<bool> IsLoginSuccessfulAsync(AutomationContext ctx, string urlBefore, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var currentUrl = await ctx.GetCurrentUrl() ?? "";
        string body;
        try
        {
            body = await ctx.ExecuteJs("document.body ? document.body.innerText : ''") ?? "";
        }
        catch
        {
            body = "";
        }

        if (AuthAccessHeuristics.LooksLikeLoginPage(body))
            return false;

        if (AuthAccessHeuristics.LooksLikeProtectedHtml(body))
            return true;

        if (!string.IsNullOrEmpty(currentUrl)
            && !currentUrl.Equals(urlBefore, StringComparison.OrdinalIgnoreCase)
            && !currentUrl.Contains("login", StringComparison.OrdinalIgnoreCase)
            && !currentUrl.Contains("signin", StringComparison.OrdinalIgnoreCase))
            return true;

        var lower = body.ToLowerInvariant();
        if (lower.Contains("invalid password") || lower.Contains("login failed")
            || lower.Contains("incorrect") || lower.Contains("wrong password")
            || lower.Contains("authentication failed") || lower.Contains("invalid credentials")
            || lower.Contains("unknown user") || lower.Contains("user not found"))
            return false;

        return false;
    }

    private sealed class LoginPageState
    {
        public string? UsernameSelector { get; init; }
        public string? PasswordSelector { get; init; }
        public string? SubmitSelector { get; init; }
        public bool PasswordVisible { get; init; }
        public bool UsernameVisible { get; init; }
    }
}
