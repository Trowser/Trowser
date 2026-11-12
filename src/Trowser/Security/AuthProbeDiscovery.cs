using System.Text.Json;
using System.Text.RegularExpressions;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Shared login / reset / logout URL discovery and session-cookie helpers for A07 auth probes.
/// </summary>
public static class AuthProbeDiscovery
{
    public static readonly string[] LoginPathHints =
    [
        "/rest/user/login",
        "/api/auth/login",
        "/api/Users/login",
        "/auth/login",
        "/login",
        "/signin",
        "/api/login",
        "/doLogin",
        "/wp-login.php"
    ];

    public static readonly string[] ResetPathHints =
    [
        "/rest/user/reset-password",
        "/rest/user/forgot-password",
        "/api/auth/reset-password",
        "/api/auth/forgot-password",
        "/api/reset-password",
        "/api/forgot-password",
        "/reset-password",
        "/forgot-password",
        "/password/reset",
        "/recover"
    ];

    public static readonly string[] SecurityQuestionPathHints =
    [
        "/rest/user/security-question",
        "/api/auth/security-question",
        "/api/security-question",
        "/security-question",
        "/api/reset/security-question"
    ];

    public static readonly string[] LogoutPathHints =
    [
        "/logout",
        "/signout",
        "/sign-out",
        "/rest/user/logout",
        "/api/auth/logout",
        "/api/logout",
        "/auth/logout",
        "/logout.jsp"
    ];

    public static readonly string[] RegisterPathHints =
    [
        "/rest/user/register",
        "/api/auth/register",
        "/api/Users",
        "/register",
        "/signup",
        "/api/register"
    ];

    public static readonly string[] ProtectedPathHints =
    [
        "/bank/main.jsp",
        "/bank/",
        "/rest/user/whoami",
        "/api/users/me",
        "/api/me",
        "/rest/basket",
        "/api/BasketItems",
        "/profile",
        "/account"
    ];

    public static readonly (string QuestionNeedle, string[] Answers)[] CanonicalSecurityAnswers =
    [
        ("mother", ["Johnson", "Smith", "Williams", "Jones", "Brown", "Davis", "Miller", "Wilson", "Moore", "Taylor"]),
        ("maiden", ["Johnson", "Smith", "Williams", "Jones", "Brown", "Davis", "Miller", "Wilson", "Moore", "Taylor"]),
        ("pet", ["Spot", "Fluffy", "Max", "Buddy", "Charlie", "Lucy", "Rocky", "Bailey", "Daisy", "Molly"]),
        ("school", ["Elementary", "High School", "Lincoln", "Washington", "Jefferson", "Roosevelt", "Kennedy"]),
        ("teacher", ["Smith", "Johnson", "Williams", "Brown", "Jones", "Davis", "Miller", "Wilson"]),
        ("color", ["blue", "red", "green", "black", "white", "yellow", "purple", "orange"]),
        ("city", ["New York", "London", "Paris", "Chicago", "Boston", "Seattle", "Denver", "Austin"]),
        ("car", ["Toyota", "Honda", "Ford", "BMW", "Audi", "Tesla", "Volkswagen", "Mercedes"]),
        ("food", ["pizza", "pasta", "sushi", "burger", "steak", "salad", "chicken", "rice"]),
        ("sport", ["football", "soccer", "basketball", "tennis", "baseball", "hockey", "golf", "swimming"])
    ];

    private static readonly string[] SessionCookieNamePatterns =
    [
        "session", "sess", "sid", "token", "auth", "jwt", "connect.sid", "asp.net_sessionid", "jsessionid"
    ];

    private static readonly Regex EmailInBody =
        new(@"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", RegexOptions.Compiled);

    public sealed class LoginSurface
    {
        public string Url { get; set; } = "";
        public string Method { get; set; } = "POST";
        public string? BodyTemplate { get; set; }
        public string? ContentType { get; set; }
        public string UserField { get; set; } = "email";
        public string PassField { get; set; } = "password";
    }

    public sealed class LoginSurfaceOverrides
    {
        public string? BodyTemplate { get; set; }
        public string? ContentType { get; set; }
        public string? UsernameField { get; set; }
        public string? PasswordField { get; set; }
        public string? Method { get; set; }
    }

    public static async Task<List<LoginSurface>> DiscoverLoginSurfacesAsync(
        AutomationContext ctx,
        string? explicitLoginUrl,
        int maxTargets,
        bool discoverFromPage,
        bool discoverFromNetwork,
        LoginSurfaceOverrides? overrides = null,
        CancellationToken ct = default)
    {
        var currentUrl = await ctx.GetCurrentUrl();
        if (string.IsNullOrEmpty(currentUrl) || !Uri.TryCreate(currentUrl, UriKind.Absolute, out var pageUri))
            throw new InvalidOperationException("Navigate to a page before running auth probes.");

        var origin = pageUri.GetLeftPart(UriPartial.Authority);
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var surfaces = new List<LoginSurface>();
        var pageForms = discoverFromPage
            ? await DiscoverPageLoginFormsAsync(ctx, ct)
            : [];

        void Add(LoginSurface s)
        {
            ApplyOverrides(s, overrides);
            EnrichFromNetwork(ctx, s, pageUri);
            EnrichFromPageForms(s, pageForms);
            InferDefaultLoginTemplate(s);
            if (!seen.Add(s.Url)) return;
            surfaces.Add(s);
        }

        if (!string.IsNullOrWhiteSpace(explicitLoginUrl))
        {
            var url = explicitLoginUrl.StartsWith("http", StringComparison.OrdinalIgnoreCase)
                ? explicitLoginUrl
                : origin + (explicitLoginUrl.StartsWith('/') ? explicitLoginUrl : "/" + explicitLoginUrl);
            var surface = new LoginSurface { Url = url };
            // Do not guess JSON vs form from path alone — prefer the live login form on the current page when paths match.
            var domMatch = pageForms.FirstOrDefault(f => UrlsMatch(f.Url, url));
            if (domMatch != null)
            {
                surface.BodyTemplate = domMatch.BodyTemplate;
                surface.ContentType = domMatch.ContentType;
                surface.UserField = domMatch.UserField;
                surface.PassField = domMatch.PassField;
                surface.Method = domMatch.Method;
            }

            Add(surface);
            await TryHydrateExplicitLoginFromLoginPageAsync(ctx, surface, pageUri, overrides, ct);
            return surfaces;
        }

        if (discoverFromNetwork)
        {
            foreach (var e in ctx.Network.Entries)
            {
                if (e.Method != "POST") continue;
                var path = e.Url ?? "";
                if (!LooksLikeLoginPath(path)) continue;
                if (!Uri.TryCreate(path, UriKind.Absolute, out var u)
                    || !string.Equals(u.Host, pageUri.Host, StringComparison.OrdinalIgnoreCase))
                    continue;
                Add(new LoginSurface
                {
                    Url = path,
                    BodyTemplate = e.RequestBody,
                    ContentType = NormalizeContentType(e.ContentType),
                    Method = "POST"
                });
            }
        }

        foreach (var hint in LoginPathHints)
            Add(new LoginSurface { Url = origin + hint });

        foreach (var form in pageForms)
            Add(form);

        return surfaces.Take(Math.Max(1, maxTargets)).ToList();
    }

    public static List<string> CollectUserListPaths(AutomationContext ctx, Uri pageUri, int max = 16)
    {
        var origin = pageUri.GetLeftPart(UriPartial.Authority);
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var paths = new List<string>();

        void AddPath(string path)
        {
            if (string.IsNullOrWhiteSpace(path)) return;
            if (!path.StartsWith('/')) path = "/" + path;
            if (seen.Add(path)) paths.Add(path);
        }

        // Prefer known REST user-list scaffolds so TargetUrl / dense network logs cannot crowd them out.
        foreach (var hint in new[] { "/api/users", "/api/Users", "/admin/api/users", "/api/v1/users", "/api/v2/users",
                     "/api/user", "/api/account", "/api/accounts", "/api/me", "/api/profile", "/rest/user/whoami" })
            AddPath(hint);

        foreach (var e in ctx.Network.Entries)
        {
            if (e.Method != "GET" || string.IsNullOrEmpty(e.Url)) continue;
            if (!Uri.TryCreate(e.Url, UriKind.Absolute, out var u)
                || !string.Equals(u.Host, pageUri.Host, StringComparison.OrdinalIgnoreCase))
                continue;
            var p = u.AbsolutePath;
            if (p.Contains("/user", StringComparison.OrdinalIgnoreCase)
                && !p.Contains("{", StringComparison.Ordinal)
                && !p.Contains("login", StringComparison.OrdinalIgnoreCase)
                && !p.Contains("logout", StringComparison.OrdinalIgnoreCase))
                AddPath(p);
        }

        return paths.Take(Math.Max(1, max)).ToList();
    }

    public static async Task<List<string>> DiscoverLogoutUrlsFromPageAsync(AutomationContext ctx, CancellationToken ct = default)
    {
        var json = await ctx.ExecuteJs(
            """
            (function(){
              var out = [];
              try {
                document.querySelectorAll('a[href]').forEach(function(a) {
                  var t = (a.textContent || '').trim().toLowerCase();
                  var h = a.href || '';
                  if (!h) return;
                  if (t.indexOf('sign off') >= 0 || t.indexOf('sign out') >= 0 || t.indexOf('log out') >= 0
                      || t.indexOf('logout') >= 0 || h.toLowerCase().indexOf('logout') >= 0)
                    out.push(h);
                });
              } catch(e) {}
              return JSON.stringify(out);
            })()
            """);
        ct.ThrowIfCancellationRequested();

        using var doc = JsonDocument.Parse(json);
        return doc.RootElement.EnumerateArray()
            .Select(e => e.GetString())
            .Where(u => !string.IsNullOrWhiteSpace(u))
            .Cast<string>()
            .ToList();
    }

    public static bool LooksLikePublicHomepage(Uri pageUri)
    {
        var path = pageUri.AbsolutePath.TrimEnd('/');
        return path.Length == 0 || path.Equals("/index", StringComparison.OrdinalIgnoreCase)
               || path.Equals("/index.html", StringComparison.OrdinalIgnoreCase)
               || path.Equals("/index.jsp", StringComparison.OrdinalIgnoreCase)
               || path.Equals("/default.jsp", StringComparison.OrdinalIgnoreCase);
    }

    public static List<string> DiscoverPaths(
        AutomationContext ctx,
        Uri pageUri,
        IEnumerable<string> hints,
        Func<string, bool>? networkFilter = null,
        int max = 8)
    {
        var origin = pageUri.GetLeftPart(UriPartial.Authority);
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var urls = new List<string>();

        void Add(string url)
        {
            if (seen.Add(url)) urls.Add(url);
        }

        networkFilter ??= _ => true;
        foreach (var e in ctx.Network.Entries.OrderByDescending(x => x.Timestamp))
        {
            var path = e.Url ?? "";
            if (!networkFilter(path)) continue;
            if (Uri.TryCreate(path, UriKind.Absolute, out var u)
                && string.Equals(u.Host, pageUri.Host, StringComparison.OrdinalIgnoreCase))
                Add(path);
        }

        foreach (var hint in hints)
            Add(origin + hint);

        return urls.Take(Math.Max(1, max)).ToList();
    }

    internal static bool MatchesSessionCookieNamePattern(string name) =>
        SessionCookieNamePatterns.Any(p => name.Contains(p, StringComparison.OrdinalIgnoreCase));

    internal static bool IsExcludedFromSessionFixationCompare(string name)
    {
        var lower = name.ToLowerInvariant();
        if (lower.Contains("csrf", StringComparison.Ordinal) || lower.Contains("xsrf", StringComparison.Ordinal))
            return true;
        if (lower.StartsWith("_ga", StringComparison.Ordinal) || lower.StartsWith("_gid", StringComparison.Ordinal)
            || lower.StartsWith("_fbp", StringComparison.Ordinal) || lower.StartsWith("_hj", StringComparison.Ordinal))
            return true;
        return false;
    }

    public static async Task<List<(string Name, string Value)>> GetBrowserCookiesAsync(AutomationContext ctx)
    {
        var cookies = await ctx.GetCookies();
        var result = new List<(string Name, string Value)>();
        foreach (var c in cookies)
        {
            if (!c.TryGetValue("name", out var nameObj) || nameObj is not string name) continue;
            if (!c.TryGetValue("value", out var valueObj) || valueObj is not string value) continue;
            if (string.IsNullOrEmpty(value)) continue;
            result.Add((name, value));
        }

        return result;
    }

    public static async Task<List<(string Name, string Value)>> GetSessionCookiesAsync(AutomationContext ctx)
    {
        var cookies = await ctx.GetCookies();
        var result = new List<(string Name, string Value)>();
        foreach (var c in cookies)
        {
            if (!c.TryGetValue("name", out var nameObj) || nameObj is not string name) continue;
            if (!c.TryGetValue("value", out var valueObj) || valueObj is not string value) continue;
            if (string.IsNullOrEmpty(value)) continue;
            if (SessionCookieNamePatterns.Any(p => name.Contains(p, StringComparison.OrdinalIgnoreCase)))
                result.Add((name, value));
        }

        if (result.Count == 0)
        {
            foreach (var c in cookies)
            {
                if (!c.TryGetValue("name", out var nameObj) || nameObj is not string name) continue;
                if (!c.TryGetValue("value", out var valueObj) || valueObj is not string value) continue;
                if (string.IsNullOrEmpty(value) || value.Length < 8) continue;
                result.Add((name, value));
            }
        }

        return result;
    }

    public static string? ExtractEmailFromNetwork(AutomationContext ctx)
    {
        foreach (var e in ctx.Network.Entries.OrderByDescending(x => x.Timestamp))
        {
            foreach (var text in new[] { e.RequestBody, e.ResponseBody })
            {
                if (string.IsNullOrEmpty(text)) continue;
                var m = EmailInBody.Match(text);
                if (m.Success && !m.Value.Contains("invalid", StringComparison.OrdinalIgnoreCase)
                             && !m.Value.Contains("example.com", StringComparison.OrdinalIgnoreCase))
                    return m.Value;
            }
        }

        return null;
    }

    public static async Task<SecurityProbeHttp.FetchResult> PostLoginAsync(
        AutomationContext ctx,
        LoginSurface surface,
        string user,
        string pass,
        int timeoutMs,
        CancellationToken ct)
    {
        var bodyTemplate = surface.BodyTemplate
                           ?? AuthAccessHeuristics.BuildJsonLoginBodyTemplate(surface.UserField, surface.PassField);

        var body = bodyTemplate
            .Replace("§USER§", user, StringComparison.Ordinal)
            .Replace("{{USER}}", user, StringComparison.OrdinalIgnoreCase)
            .Replace("§PASS§", pass, StringComparison.Ordinal)
            .Replace("{{PASS}}", pass, StringComparison.OrdinalIgnoreCase);

        var contentType = AuthAccessHeuristics.ResolveContentType(surface.ContentType, bodyTemplate);

        if (!body.TrimStart().StartsWith('{') && bodyTemplate.Contains('='))
        {
            body = bodyTemplate
                .Replace("§USER§", Uri.EscapeDataString(user), StringComparison.Ordinal)
                .Replace("§PASS§", Uri.EscapeDataString(pass), StringComparison.Ordinal)
                .Replace("{{USER}}", Uri.EscapeDataString(user), StringComparison.OrdinalIgnoreCase)
                .Replace("{{PASS}}", Uri.EscapeDataString(pass), StringComparison.OrdinalIgnoreCase);
        }

        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["Content-Type"] = contentType
        };

        return await SecurityProbeHttp.FetchAsync(
            ctx, surface.Url, surface.Method, headers, body, timeoutMs,
            includeBrowserCookies: true, ct);
    }

    public static Dictionary<string, string> BuildLoginHeaders(LoginSurface surface)
    {
        var bodyTemplate = surface.BodyTemplate
                           ?? AuthAccessHeuristics.BuildJsonLoginBodyTemplate(surface.UserField, surface.PassField);
        return new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["Content-Type"] = AuthAccessHeuristics.ResolveContentType(surface.ContentType, bodyTemplate)
        };
    }

    public static string ResolveEffectiveContentType(LoginSurface surface)
    {
        var bodyTemplate = surface.BodyTemplate
                           ?? AuthAccessHeuristics.BuildJsonLoginBodyTemplate(surface.UserField, surface.PassField);
        return AuthAccessHeuristics.ResolveContentType(surface.ContentType, bodyTemplate);
    }

    public static string BuildLoginBody(LoginSurface surface, string user, string pass)
    {
        var bodyTemplate = surface.BodyTemplate
                           ?? AuthAccessHeuristics.BuildJsonLoginBodyTemplate(surface.UserField, surface.PassField);
        if (!bodyTemplate.TrimStart().StartsWith('{') && bodyTemplate.Contains('='))
        {
            return bodyTemplate
                .Replace("§USER§", Uri.EscapeDataString(user), StringComparison.Ordinal)
                .Replace("§PASS§", Uri.EscapeDataString(pass), StringComparison.Ordinal)
                .Replace("{{USER}}", Uri.EscapeDataString(user), StringComparison.OrdinalIgnoreCase)
                .Replace("{{PASS}}", Uri.EscapeDataString(pass), StringComparison.OrdinalIgnoreCase);
        }

        return bodyTemplate
            .Replace("§USER§", user, StringComparison.Ordinal)
            .Replace("§PASS§", pass, StringComparison.Ordinal)
            .Replace("{{USER}}", user, StringComparison.OrdinalIgnoreCase)
            .Replace("{{PASS}}", pass, StringComparison.OrdinalIgnoreCase);
    }

    public static bool LooksLikeLoginPath(string path) =>
        path.Contains("login", StringComparison.OrdinalIgnoreCase)
        || path.Contains("signin", StringComparison.OrdinalIgnoreCase)
        || path.Contains("dologin", StringComparison.OrdinalIgnoreCase)
        || path.Contains("/auth", StringComparison.OrdinalIgnoreCase);

    public static bool LooksLikeResetPath(string path) =>
        path.Contains("reset", StringComparison.OrdinalIgnoreCase)
        || path.Contains("forgot", StringComparison.OrdinalIgnoreCase)
        || path.Contains("recover", StringComparison.OrdinalIgnoreCase);

    public static bool LooksLikeLogoutPath(string path) =>
        path.Contains("logout", StringComparison.OrdinalIgnoreCase)
        || path.Contains("signout", StringComparison.OrdinalIgnoreCase)
        || path.Contains("sign-out", StringComparison.OrdinalIgnoreCase);

    public static bool LooksLikeRegisterPath(string path) =>
        path.Contains("register", StringComparison.OrdinalIgnoreCase)
        || path.Contains("signup", StringComparison.OrdinalIgnoreCase);

    public static void RegisterChainFinding(
        AutomationContext ctx,
        string category,
        string severity,
        string title,
        string endpoint,
        string method,
        string detail)
    {
        ctx.AddManualChainFinding(new ChainEngine.ChainableFinding
        {
            Id = $"{category}-{Math.Abs((endpoint + title).GetHashCode(StringComparison.Ordinal))}",
            Source = "scan",
            Category = category,
            Severity = severity,
            Title = title,
            Endpoint = endpoint,
            Method = method,
            Detail = detail
        });
    }

    /// <summary>
    /// When the user passes <c>loginUrl</c> but the current document is not the login page, navigate once to
    /// capture the real form field names (avoids defaulting <c>/login</c> to JSON and missing form apps).
    /// </summary>
    private static async Task TryHydrateExplicitLoginFromLoginPageAsync(
        AutomationContext ctx,
        LoginSurface surface,
        Uri pageUri,
        LoginSurfaceOverrides? overrides,
        CancellationToken ct)
    {
        if (overrides != null && !string.IsNullOrWhiteSpace(overrides.BodyTemplate))
            return;

        static bool LooksLikeJsonTemplate(string? body) =>
            !string.IsNullOrWhiteSpace(body) && body.TrimStart().StartsWith('{');

        // Already have a concrete form template from the current DOM or network log.
        if (!string.IsNullOrWhiteSpace(surface.BodyTemplate) && !LooksLikeJsonTemplate(surface.BodyTemplate))
            return;

        string? backUrl = null;
        try
        {
            backUrl = await ctx.GetCurrentUrl();
            if (string.IsNullOrEmpty(surface.Url)
                || !Uri.TryCreate(surface.Url, UriKind.Absolute, out _))
                return;

            await ctx.Navigate(surface.Url);
            await Task.Delay(250, ct);
            var formsOnLogin = await DiscoverPageLoginFormsAsync(ctx, ct);
            var match = formsOnLogin.FirstOrDefault(f => UrlsMatch(f.Url, surface.Url));
            if (match == null) return;

            var userField = !string.IsNullOrWhiteSpace(overrides?.UsernameField)
                ? overrides.UsernameField!
                : match.UserField;
            var passField = !string.IsNullOrWhiteSpace(overrides?.PasswordField)
                ? overrides.PasswordField!
                : match.PassField;
            surface.UserField = userField;
            surface.PassField = passField;
            surface.BodyTemplate = AuthAccessHeuristics.BuildFormLoginBodyTemplate(userField, passField);
            surface.ContentType = match.ContentType ?? "application/x-www-form-urlencoded";
            surface.Method = match.Method;
        }
        catch
        {
            // Best-effort — enumeration still runs with heuristic template.
        }
        finally
        {
            if (!string.IsNullOrWhiteSpace(backUrl))
            {
                try
                {
                    await ctx.Navigate(backUrl);
                }
                catch
                {
                    /* ignore */
                }
            }
        }
    }

    private static async Task<List<LoginSurface>> DiscoverPageLoginFormsAsync(AutomationContext ctx, CancellationToken ct)
    {
        var formJson = await ctx.ExecuteJs(
            """
            (function(){
              var out = [];
              try {
                document.querySelectorAll('form').forEach(function(f) {
                  var action = f.action || location.href;
                  var pass = f.querySelector('input[type=password]');
                  if (!pass) return;
                  var inputs = Array.prototype.slice.call(f.querySelectorAll('input'));
                  var passIdx = inputs.indexOf(pass);
                  var user = null;
                  if (passIdx > 0) {
                    for (var i = passIdx - 1; i >= 0; i--) {
                      var t = (inputs[i].type || '').toLowerCase();
                      if (t === 'hidden' || t === 'submit' || t === 'button' || t === 'checkbox' || t === 'radio') continue;
                      user = inputs[i]; break;
                    }
                  }
                  if (!user) user = f.querySelector('input[type=email],input[type=text],input[name*=user i],input[name*=email i],input[id*=user i],input[name*=uid i]');
                  out.push({
                    action: action,
                    method: (f.method || 'POST').toUpperCase(),
                    userName: user ? (user.name || user.id || 'username') : 'username',
                    passName: pass.name || pass.id || 'password'
                  });
                });
              } catch(e) {}
              return JSON.stringify(out);
            })()
            """);
        ct.ThrowIfCancellationRequested();

        var forms = new List<LoginSurface>();
        using var doc = JsonDocument.Parse(formJson);
        foreach (var el in doc.RootElement.EnumerateArray())
        {
            var action = el.GetProperty("action").GetString() ?? "";
            if (string.IsNullOrEmpty(action)) continue;
            var userName = el.GetProperty("userName").GetString() ?? "username";
            var passName = el.GetProperty("passName").GetString() ?? "password";
            forms.Add(new LoginSurface
            {
                Url = action,
                Method = el.GetProperty("method").GetString() ?? "POST",
                BodyTemplate = AuthAccessHeuristics.BuildFormLoginBodyTemplate(userName, passName),
                ContentType = "application/x-www-form-urlencoded",
                UserField = userName,
                PassField = passName
            });
        }

        return forms;
    }

    private static void ApplyOverrides(LoginSurface surface, LoginSurfaceOverrides? overrides)
    {
        if (overrides == null) return;
        if (!string.IsNullOrWhiteSpace(overrides.BodyTemplate))
            surface.BodyTemplate = overrides.BodyTemplate;
        if (!string.IsNullOrWhiteSpace(overrides.ContentType))
            surface.ContentType = overrides.ContentType;
        if (!string.IsNullOrWhiteSpace(overrides.UsernameField))
            surface.UserField = overrides.UsernameField!;
        if (!string.IsNullOrWhiteSpace(overrides.PasswordField))
            surface.PassField = overrides.PasswordField!;
        if (!string.IsNullOrWhiteSpace(overrides.Method))
            surface.Method = overrides.Method!;
    }

    private static void EnrichFromNetwork(AutomationContext ctx, LoginSurface surface, Uri pageUri)
    {
        Uri.TryCreate(surface.Url, UriKind.Absolute, out var surfaceUri);
        var surfaceHost = surfaceUri?.Host ?? pageUri.Host;

        foreach (var e in ctx.Network.Entries.Where(x => x.Method == "POST"))
        {
            if (string.IsNullOrEmpty(e.Url) || !UrlsMatch(e.Url, surface.Url)) continue;
            if (!Uri.TryCreate(e.Url, UriKind.Absolute, out var u)
                || !string.Equals(u.Host, surfaceHost, StringComparison.OrdinalIgnoreCase))
                continue;

            if (string.IsNullOrWhiteSpace(surface.BodyTemplate) && !string.IsNullOrWhiteSpace(e.RequestBody))
                surface.BodyTemplate = e.RequestBody;
            if (string.IsNullOrWhiteSpace(surface.ContentType))
                surface.ContentType = NormalizeContentType(e.ContentType);
        }
    }

    private static void EnrichFromPageForms(LoginSurface surface, List<LoginSurface> pageForms)
    {
        var match = pageForms.FirstOrDefault(f => UrlsMatch(f.Url, surface.Url));
        if (match == null) return;

        if (string.IsNullOrWhiteSpace(surface.BodyTemplate))
            surface.BodyTemplate = match.BodyTemplate;
        if (string.IsNullOrWhiteSpace(surface.ContentType))
            surface.ContentType = match.ContentType;
        if (surface.UserField is "email" or "username")
            surface.UserField = match.UserField;
        if (surface.PassField == "password")
            surface.PassField = match.PassField;
    }

    internal static void InferDefaultLoginTemplate(LoginSurface surface)
    {
        if (!string.IsNullOrWhiteSpace(surface.BodyTemplate)) return;

        if (PrefersFormLoginBody(surface))
        {
            surface.BodyTemplate = AuthAccessHeuristics.BuildFormLoginBodyTemplate(surface.UserField, surface.PassField);
            surface.ContentType ??= "application/x-www-form-urlencoded";
            return;
        }

        var customFields = (surface.UserField is not ("email" or "username") || surface.PassField != "password")
                           && !string.IsNullOrWhiteSpace(surface.UserField)
                           && !string.IsNullOrWhiteSpace(surface.PassField);
        if (customFields)
        {
            surface.BodyTemplate = AuthAccessHeuristics.BuildFormLoginBodyTemplate(surface.UserField, surface.PassField);
            surface.ContentType ??= "application/x-www-form-urlencoded";
            return;
        }

        if (Uri.TryCreate(surface.Url, UriKind.Absolute, out var uri))
        {
            var path = uri.AbsolutePath.ToLowerInvariant();
            if (path.Contains("/api/") || (path.EndsWith("/login", StringComparison.Ordinal) && !path.EndsWith(".jsp", StringComparison.Ordinal)))
            {
                if (PrefersFormLoginBody(surface))
                {
                    surface.BodyTemplate = AuthAccessHeuristics.BuildFormLoginBodyTemplate(surface.UserField, surface.PassField);
                    surface.ContentType ??= "application/x-www-form-urlencoded";
                    return;
                }

                surface.UserField = string.IsNullOrWhiteSpace(surface.UserField) || surface.UserField == "email"
                    ? "username"
                    : surface.UserField;
                surface.BodyTemplate = AuthAccessHeuristics.BuildJsonLoginBodyTemplate(surface.UserField, surface.PassField);
                surface.ContentType ??= "application/json";
                return;
            }

            if (path.Contains("dologin") || path.EndsWith(".jsp", StringComparison.Ordinal))
            {
                surface.UserField = surface.UserField is "email" or "username" ? "uid" : surface.UserField;
                surface.PassField = surface.PassField == "password" ? "passw" : surface.PassField;
                surface.BodyTemplate = AuthAccessHeuristics.BuildFormLoginBodyTemplate(surface.UserField, surface.PassField);
                surface.ContentType ??= "application/x-www-form-urlencoded";
            }
        }
    }

    private static string? NormalizeContentType(string? contentType) =>
        string.IsNullOrWhiteSpace(contentType) ? null : contentType.Trim();

    internal static bool PrefersFormLoginBody(LoginSurface surface)
    {
        if (IsFormUrlEncodedContentType(surface.ContentType))
            return true;

        if (!string.IsNullOrWhiteSpace(surface.BodyTemplate)
            && !surface.BodyTemplate.TrimStart().StartsWith('{')
            && surface.BodyTemplate.Contains('='))
            return true;

        return false;
    }

    internal static bool IsFormUrlEncodedContentType(string? contentType)
    {
        if (string.IsNullOrWhiteSpace(contentType)) return false;
        var ct = contentType.Trim();
        return ct.Contains("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase)
               || ct.Contains("multipart/form-data", StringComparison.OrdinalIgnoreCase);
    }

    private static bool UrlsMatch(string a, string b)
    {
        if (string.Equals(a, b, StringComparison.OrdinalIgnoreCase)) return true;
        if (!Uri.TryCreate(a, UriKind.Absolute, out var ua) || !Uri.TryCreate(b, UriKind.Absolute, out var ub))
            return false;
        return string.Equals(ua.AbsolutePath.TrimEnd('/'), ub.AbsolutePath.TrimEnd('/'), StringComparison.OrdinalIgnoreCase)
               && string.Equals(ua.Host, ub.Host, StringComparison.OrdinalIgnoreCase);
    }
}
