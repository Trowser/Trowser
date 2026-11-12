using System.IO;
using System.Net.Http;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Persists portable identity snapshots under %LocalAppData%\Trowser\Identities\{name}\.
/// </summary>
public sealed class IdentityStore
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        WriteIndented = true
    };

    private static readonly Regex ValidNamePattern = new(@"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$", RegexOptions.Compiled);

    private readonly string _rootDir;

    public IdentityStore(string? rootDir = null)
    {
        _rootDir = rootDir ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Trowser", "Identities");
    }

    public static bool IsValidName(string? name) =>
        !string.IsNullOrWhiteSpace(name) && ValidNamePattern.IsMatch(name.Trim());

    public string GetSnapshotPath(string name) =>
        Path.Combine(_rootDir, SanitizeName(name), "snapshot.json");

    public async Task<IdentitySnapshot> CaptureAsync(
        AutomationContext context,
        string name,
        string? sessionName,
        bool includeAuthHeaders = true,
        int authHeaderMaxAgeMinutes = 30)
    {
        ValidateName(name);

        var cookies = await context.GetCookies();
        var currentUrl = await context.GetCurrentUrl();
        string? domain = null;
        if (Uri.TryCreate(currentUrl, UriKind.Absolute, out var uri))
            domain = uri.Host;

        var mechanism = SessionIdentityIntrospection.InferMechanismFromCookies(cookies);
        var localStorage = await context.GetAllStorage("local");
        var sessionStorage = await context.GetAllStorage("session");

        var snapshot = new IdentitySnapshot
        {
            Name = name.Trim(),
            Metadata = new IdentityMetadata
            {
                SessionName = sessionName,
                CapturedAt = DateTime.UtcNow,
                CurrentUrl = currentUrl,
                Domain = domain,
                InferredMechanism = mechanism.Mechanism,
                SessionCookie = mechanism.SessionCookie,
                CookieCount = cookies.Count,
                LocalStorageCount = localStorage.Count,
                SessionStorageCount = sessionStorage.Count
            },
            Cookies = cookies.Select(ToIdentityCookie).ToList(),
            LocalStorage = localStorage,
            SessionStorage = sessionStorage
        };

        if (includeAuthHeaders)
        {
            snapshot.AuthHeaders = SessionIdentityIntrospection.ExtractAuthHeadersFromNetwork(
                context.ActiveTab.Network.Entries,
                domain,
                authHeaderMaxAgeMinutes);
        }

        await SaveAsync(snapshot);
        return snapshot;
    }

    public async Task<IdentityApplyResult> ApplyAsync(
        AutomationContext context,
        string name,
        string? navigateTo = null,
        IdentityVerifyOptions? verify = null)
    {
        ValidateName(name);
        var snapshot = Load(name);
        if (snapshot == null)
            throw new InvalidOperationException($"Identity '{name}' not found. Capture it first with POST /api/identity/capture.");

        await context.ClearCookies();
        await context.ClearStorage("local");
        await context.ClearStorage("session");

        foreach (var cookie in snapshot.Cookies)
        {
            await context.SetCookie(
                cookie.Name,
                cookie.Value,
                domain: string.IsNullOrWhiteSpace(cookie.Domain) ? null : cookie.Domain,
                path: string.IsNullOrWhiteSpace(cookie.Path) ? "/" : cookie.Path,
                secure: cookie.Secure,
                httpOnly: cookie.HttpOnly,
                sameSite: cookie.SameSite);
        }

        foreach (var (key, value) in snapshot.LocalStorage)
            await context.SetStorageItem("local", key, value);
        foreach (var (key, value) in snapshot.SessionStorage)
            await context.SetStorageItem("session", key, value);

        string? navigatedTo = null;
        if (!string.IsNullOrWhiteSpace(navigateTo))
        {
            navigatedTo = navigateTo.Trim();
            await context.ForceNavigateAsync(navigatedTo, terminateScripts: true);
        }

        var result = new IdentityApplyResult
        {
            Applied = true,
            NavigatedTo = navigatedTo,
            CookiesApplied = snapshot.Cookies.Count,
            LocalStorageApplied = snapshot.LocalStorage.Count,
            SessionStorageApplied = snapshot.SessionStorage.Count,
            Verified = verify == null
        };

        if (verify != null && !string.IsNullOrWhiteSpace(verify.Url))
        {
            var (status, _, _, _) = await FetchWithBrowserCookiesAsync(
                context, verify.Url, verify.Method ?? "GET", verify.Headers, verify.Body, verify.TimeoutMs);
            result.Verified = status == verify.ExpectStatus;
            result.VerifyStatus = status;
            result.VerifyError = result.Verified
                ? null
                : $"Expected HTTP {verify.ExpectStatus}, got {status}.";
        }

        return result;
    }

    public static async Task<(int Status, string Body, bool Redirected, string? FinalUrl)> FetchWithBrowserCookiesAsync(
        AutomationContext context,
        string url,
        string method = "GET",
        Dictionary<string, string>? headers = null,
        string? body = null,
        int timeoutMs = 30000)
    {
        var cookieHeader = await context.GetCookieHeaderForUrl(url);

        using var handler = new HttpClientHandler
        {
            AllowAutoRedirect = true,
            UseCookies = false,
            ServerCertificateCustomValidationCallback = (_, _, _, _) => true
        };
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromMilliseconds(timeoutMs) };

        var msg = new HttpRequestMessage(new HttpMethod(method), url);
        if (!string.IsNullOrEmpty(cookieHeader))
            msg.Headers.TryAddWithoutValidation("Cookie", cookieHeader);

        if (body != null)
        {
            msg.Content = RequestContentBuilder.FromText(
                body, headers?.GetValueOrDefault("Content-Type"), "text/plain");
        }

        if (headers != null)
        {
            foreach (var kv in headers)
            {
                if (kv.Key.Equals("Content-Type", StringComparison.OrdinalIgnoreCase)) continue;
                if (!msg.Headers.TryAddWithoutValidation(kv.Key, kv.Value))
                    msg.Content?.Headers.TryAddWithoutValidation(kv.Key, kv.Value);
            }
        }

        var resp = await client.SendAsync(msg);
        var respBody = await resp.Content.ReadAsStringAsync();
        var finalUrl = resp.RequestMessage?.RequestUri?.ToString();
        var redirected = finalUrl != null && !string.Equals(finalUrl, url, StringComparison.OrdinalIgnoreCase);
        return ((int)resp.StatusCode, respBody, redirected, finalUrl);
    }

    public List<IdentityCatalogEntry> List()
    {
        if (!Directory.Exists(_rootDir))
            return [];

        var entries = new List<IdentityCatalogEntry>();
        foreach (var dir in Directory.EnumerateDirectories(_rootDir))
        {
            var name = Path.GetFileName(dir);
            var snapshot = Load(name);
            if (snapshot == null) continue;
            entries.Add(ToCatalogEntry(snapshot));
        }

        return entries.OrderBy(e => e.Name, StringComparer.OrdinalIgnoreCase).ToList();
    }

    public IdentitySnapshot? Load(string name)
    {
        ValidateName(name);
        var path = GetSnapshotPath(name);
        if (!File.Exists(path)) return null;

        var json = File.ReadAllText(path);
        return JsonSerializer.Deserialize<IdentitySnapshot>(json, JsonOptions);
    }

    public object ToResponsePayload(IdentitySnapshot snapshot, bool reveal)
    {
        if (reveal)
        {
            return new
            {
                snapshot.Name,
                metadata = snapshot.Metadata,
                cookies = snapshot.Cookies,
                localStorage = snapshot.LocalStorage,
                sessionStorage = snapshot.SessionStorage,
                authHeaders = snapshot.AuthHeaders
            };
        }

        return new
        {
            snapshot.Name,
            metadata = snapshot.Metadata,
            cookies = snapshot.Cookies.Select(c => new
            {
                c.Name,
                value = SessionIdentityIntrospection.RedactPreview(c.Value),
                c.Domain,
                c.Path,
                c.Secure,
                c.HttpOnly,
                c.SameSite,
                c.Session,
                c.Expires
            }),
            localStorage = snapshot.LocalStorage.ToDictionary(
                kv => kv.Key,
                kv => SessionIdentityIntrospection.RedactPreview(kv.Value)),
            sessionStorage = snapshot.SessionStorage.ToDictionary(
                kv => kv.Key,
                kv => SessionIdentityIntrospection.RedactPreview(kv.Value)),
            authHeaders = snapshot.AuthHeaders.Select(h => new
            {
                h.Name,
                value = SessionIdentityIntrospection.RedactPreview(h.Value),
                h.Host,
                h.LastSeen,
                h.Url
            }),
            redacted = true,
            revealHint = "Pass ?reveal=true for full values (local debug only)."
        };
    }

    public bool Delete(string name)
    {
        ValidateName(name);
        var dir = Path.Combine(_rootDir, SanitizeName(name));
        if (!Directory.Exists(dir)) return false;
        Directory.Delete(dir, recursive: true);
        return true;
    }

    public async Task SaveAsync(IdentitySnapshot snapshot)
    {
        ValidateName(snapshot.Name);
        var dir = Path.Combine(_rootDir, SanitizeName(snapshot.Name));
        Directory.CreateDirectory(dir);
        var json = JsonSerializer.Serialize(snapshot, JsonOptions);
        await File.WriteAllTextAsync(GetSnapshotPath(snapshot.Name), json);
    }

    private static IdentityCatalogEntry ToCatalogEntry(IdentitySnapshot snapshot) => new()
    {
        Name = snapshot.Name,
        CapturedAt = snapshot.Metadata.CapturedAt,
        Domain = snapshot.Metadata.Domain,
        InferredMechanism = snapshot.Metadata.InferredMechanism,
        SessionName = snapshot.Metadata.SessionName,
        CookieCount = snapshot.Metadata.CookieCount,
        LocalStorageCount = snapshot.Metadata.LocalStorageCount,
        SessionStorageCount = snapshot.Metadata.SessionStorageCount,
        CurrentUrl = snapshot.Metadata.CurrentUrl
    };

    private static IdentityCookie ToIdentityCookie(Dictionary<string, object> cookie) => new()
    {
        Name = cookie.TryGetValue("name", out var n) ? n?.ToString() ?? "" : "",
        Value = cookie.TryGetValue("value", out var v) ? v?.ToString() ?? "" : "",
        Domain = cookie.TryGetValue("domain", out var d) ? d?.ToString() ?? "" : "",
        Path = cookie.TryGetValue("path", out var p) ? p?.ToString() ?? "/" : "/",
        Secure = cookie.TryGetValue("secure", out var s) && s is true,
        HttpOnly = cookie.TryGetValue("httpOnly", out var h) && h is true,
        SameSite = cookie.TryGetValue("sameSite", out var ss) ? ss?.ToString()?.ToLowerInvariant() ?? "lax" : "lax",
        Session = cookie.TryGetValue("session", out var ses) && ses is true,
        Expires = cookie.TryGetValue("expires", out var ex) ? ex?.ToString() : null
    };

    private static void ValidateName(string name)
    {
        if (!IsValidName(name))
            throw new ArgumentException(
                "Invalid identity name. Use 1-64 characters: letters, digits, dot, underscore, hyphen.");
    }

    private static string SanitizeName(string name) => name.Trim();
}

public sealed class IdentityVerifyOptions
{
    public string Url { get; init; } = "";
    public int ExpectStatus { get; init; } = 200;
    public string? Method { get; init; }
    public Dictionary<string, string>? Headers { get; init; }
    public string? Body { get; init; }
    public int TimeoutMs { get; init; } = 30000;
}
