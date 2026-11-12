using System.Text.Json;
using Microsoft.Web.WebView2.Core;

namespace Trowser.Automation;

public partial class AutomationContext
{
    #region Emulation

    private EmulationState _emulation = new();
    private string? _localeDocumentScriptId;

    /// <summary>Current environment overrides for the active session (geo, locale, UA, etc.).</summary>
    public EmulationState Emulation => _emulation.Clone();

    /// <summary>
    /// Apply any subset of environment overrides via CDP. Null fields are left unchanged.
    /// Pass empty string for userAgent / locale / timezone to clear that override alone.
    /// </summary>
    public async Task SetEmulation(EmulationUpdate update)
    {
        ArgumentNullException.ThrowIfNull(update);
        var webView = ActiveTab.WebView;

        await await webView.Dispatcher.InvokeAsync(async () =>
        {
            var core = webView.CoreWebView2
                       ?? throw new InvalidOperationException("WebView2 is not initialized.");

            if (update.Geolocation != null)
            {
                if (update.Geolocation.Clear)
                {
                    await core.CallDevToolsProtocolMethodAsync("Emulation.clearGeolocationOverride", "{}");
                    _emulation.Geolocation = null;
                }
                else
                {
                    var lat = update.Geolocation.Latitude
                              ?? throw new ArgumentException("geolocation.latitude is required unless clear=true.");
                    var lng = update.Geolocation.Longitude
                              ?? throw new ArgumentException("geolocation.longitude is required unless clear=true.");
                    var payload = new Dictionary<string, object?>
                    {
                        ["latitude"] = lat,
                        ["longitude"] = lng
                    };
                    if (update.Geolocation.Accuracy is { } acc)
                        payload["accuracy"] = acc;
                    await core.CallDevToolsProtocolMethodAsync(
                        "Emulation.setGeolocationOverride",
                        JsonSerializer.Serialize(payload));
                    _emulation.Geolocation = new GeoOverride(lat, lng, update.Geolocation.Accuracy);
                }
            }

            if (update.Locale != null)
            {
                if (update.Locale.Length == 0)
                {
                    // CDP has no clearLocaleOverride on all WebView2 builds — set empty and track cleared.
                    try
                    {
                        await core.CallDevToolsProtocolMethodAsync(
                            "Emulation.setLocaleOverride", "{\"locale\":\"\"}");
                    }
                    catch (Exception ex)
                    {
                        TrowserLog.Warn($"clear locale override: {ex.Message}");
                    }

                    _emulation.Locale = null;
                    await ClearLocaleBrowserSurfaceAsync(core);
                }
                else
                {
                    await core.CallDevToolsProtocolMethodAsync(
                        "Emulation.setLocaleOverride",
                        JsonSerializer.Serialize(new { locale = update.Locale }));
                    _emulation.Locale = update.Locale;
                    await ApplyLocaleBrowserSurfaceAsync(core, update.Locale);
                }
            }

            if (update.Timezone != null)
            {
                if (update.Timezone.Length == 0)
                {
                    try
                    {
                        await core.CallDevToolsProtocolMethodAsync(
                            "Emulation.setTimezoneOverride", "{\"timezoneId\":\"\"}");
                    }
                    catch (Exception ex)
                    {
                        TrowserLog.Warn($"clear timezone override: {ex.Message}");
                    }

                    _emulation.Timezone = null;
                }
                else
                {
                    await core.CallDevToolsProtocolMethodAsync(
                        "Emulation.setTimezoneOverride",
                        JsonSerializer.Serialize(new { timezoneId = update.Timezone }));
                    _emulation.Timezone = update.Timezone;
                }
            }

            if (update.ColorScheme != null || update.ReducedMotion != null)
            {
                var features = new List<object>();
                var scheme = update.ColorScheme ?? _emulation.ColorScheme;
                if (!string.IsNullOrEmpty(scheme) &&
                    !scheme.Equals("no-preference", StringComparison.OrdinalIgnoreCase))
                {
                    features.Add(new { name = "prefers-color-scheme", value = scheme });
                    _emulation.ColorScheme = scheme;
                }
                else if (update.ColorScheme != null)
                {
                    _emulation.ColorScheme = null;
                }

                var motion = update.ReducedMotion ?? _emulation.ReducedMotion;
                if (!string.IsNullOrEmpty(motion) &&
                    !motion.Equals("no-preference", StringComparison.OrdinalIgnoreCase))
                {
                    features.Add(new { name = "prefers-reduced-motion", value = motion });
                    _emulation.ReducedMotion = motion;
                }
                else if (update.ReducedMotion != null)
                {
                    _emulation.ReducedMotion = null;
                }

                await core.CallDevToolsProtocolMethodAsync(
                    "Emulation.setEmulatedMedia",
                    JsonSerializer.Serialize(new { features }));
            }

            if (update.UserAgent != null)
            {
                if (update.UserAgent.Length == 0)
                {
                    try
                    {
                        await core.CallDevToolsProtocolMethodAsync(
                            "Emulation.setUserAgentOverride",
                            JsonSerializer.Serialize(new { userAgent = "" }));
                    }
                    catch (Exception ex)
                    {
                        TrowserLog.Warn($"clear UA override: {ex.Message}");
                    }

                    _emulation.UserAgent = null;
                }
                else
                {
                    await core.CallDevToolsProtocolMethodAsync(
                        "Emulation.setUserAgentOverride",
                        JsonSerializer.Serialize(new { userAgent = update.UserAgent }));
                    _emulation.UserAgent = update.UserAgent;
                }
            }

            if (update.Permissions != null)
            {
                foreach (var kv in update.Permissions)
                {
                    var permission = kv.Key;
                    var setting = kv.Value?.ToLowerInvariant() ?? "prompt";
                    // Store desired setting; apply for current origin (and re-apply on each navigation).
                    _emulation.Permissions[permission] = setting;
                    try
                    {
                        await ApplyPermissionOverrideAsync(core, permission, setting);
                    }
                    catch (Exception ex)
                    {
                        throw new InvalidOperationException(
                            $"Permission override for '{permission}' is not supported in this WebView2 build: {ex.Message}",
                            ex);
                    }
                }
            }
        });

        try
        {
            await RecordTraceStepAsync("emulation", new
            {
                geolocation = update.Geolocation != null,
                locale = update.Locale,
                timezone = update.Timezone,
                colorScheme = update.ColorScheme,
                userAgent = update.UserAgent != null,
                permissions = update.Permissions != null
            });
        }
        catch { /* best-effort */ }
    }

    /// <summary>
    /// Re-apply geolocation override and per-origin permission grants after navigation.
    /// CDP geo can drop across origins; <c>Browser.setPermission</c> is always origin-scoped.
    /// </summary>
    public async Task ReapplyEmulationAfterNavigationAsync()
    {
        if (_emulation.Geolocation == null && _emulation.Permissions.Count == 0 && string.IsNullOrEmpty(_emulation.Locale))
            return;

        var webView = ActiveTab.WebView;
        try
        {
            await await webView.Dispatcher.InvokeAsync(async () =>
            {
                var core = webView.CoreWebView2;
                if (core == null) return;

                if (!string.IsNullOrEmpty(_emulation.Locale))
                    await ApplyLocaleBrowserSurfaceAsync(core, _emulation.Locale);

                if (_emulation.Geolocation is { } geo)
                {
                    var payload = new Dictionary<string, object?>
                    {
                        ["latitude"] = geo.Latitude,
                        ["longitude"] = geo.Longitude
                    };
                    if (geo.Accuracy is { } acc)
                        payload["accuracy"] = acc;
                    try
                    {
                        await core.CallDevToolsProtocolMethodAsync(
                            "Emulation.setGeolocationOverride",
                            JsonSerializer.Serialize(payload));
                    }
                    catch (Exception ex)
                    {
                        TrowserLog.Warn($"Reapply geolocation override failed: {ex.Message}");
                    }
                }

                foreach (var kv in _emulation.Permissions.ToList())
                {
                    try
                    {
                        await ApplyPermissionOverrideAsync(core, kv.Key, kv.Value);
                    }
                    catch (Exception ex)
                    {
                        TrowserLog.Warn($"Reapply permission '{kv.Key}' failed: {ex.Message}");
                    }
                }
            });
        }
        catch (Exception ex)
        {
            TrowserLog.Warn($"ReapplyEmulationAfterNavigation failed: {ex.Message}");
        }
    }

    private static async Task ApplyPermissionOverrideAsync(CoreWebView2 core, string permission, string setting)
    {
        var origin = core.Source;
        if (string.IsNullOrEmpty(origin) || origin.StartsWith("about:", StringComparison.OrdinalIgnoreCase))
            origin = "https://trowser.local/";
        var originUri = Uri.TryCreate(origin, UriKind.Absolute, out var u)
            ? $"{u.Scheme}://{u.Authority}"
            : origin;
        await core.CallDevToolsProtocolMethodAsync(
            "Browser.setPermission",
            JsonSerializer.Serialize(new
            {
                origin = originUri,
                permission = new { name = permission },
                setting
            }));
    }

    /// <summary>Clear all environment overrides applied via <see cref="SetEmulation"/>.</summary>
    public async Task ClearEmulation()
    {
        var webView = ActiveTab.WebView;
        await await webView.Dispatcher.InvokeAsync(async () =>
        {
            var core = webView.CoreWebView2;
            if (core == null) return;

            try { await core.CallDevToolsProtocolMethodAsync("Emulation.clearGeolocationOverride", "{}"); }
            catch { /* ignore */ }

            try
            {
                await core.CallDevToolsProtocolMethodAsync(
                    "Emulation.setLocaleOverride", "{\"locale\":\"\"}");
            }
            catch { /* ignore */ }

            try
            {
                await core.CallDevToolsProtocolMethodAsync(
                    "Emulation.setTimezoneOverride", "{\"timezoneId\":\"\"}");
            }
            catch { /* ignore */ }

            try
            {
                await core.CallDevToolsProtocolMethodAsync(
                    "Emulation.setEmulatedMedia",
                    JsonSerializer.Serialize(new { features = Array.Empty<object>() }));
            }
            catch { /* ignore */ }

            try
            {
                await core.CallDevToolsProtocolMethodAsync(
                    "Emulation.setUserAgentOverride",
                    JsonSerializer.Serialize(new { userAgent = "" }));
            }
            catch { /* ignore */ }
        });

        _emulation = new EmulationState();
        _localeDocumentScriptId = null;

        try { await RecordTraceStepAsync("emulation.clear", null); }
        catch { /* best-effort */ }
    }

    private async Task ApplyLocaleBrowserSurfaceAsync(CoreWebView2 core, string locale)
    {
        var ua = _emulation.UserAgent;
        if (string.IsNullOrEmpty(ua))
        {
            try { ua = core.Settings.UserAgent; }
            catch { ua = ""; }
        }

        await core.CallDevToolsProtocolMethodAsync(
            "Emulation.setUserAgentOverride",
            JsonSerializer.Serialize(new
            {
                userAgent = ua,
                acceptLanguage = LocaleEmulationHelpers.BuildAcceptLanguageHeader(locale)
            }));

        if (!string.IsNullOrEmpty(_localeDocumentScriptId))
        {
            try { core.RemoveScriptToExecuteOnDocumentCreated(_localeDocumentScriptId); }
            catch { /* ignore */ }
            _localeDocumentScriptId = null;
        }

        var langJson = JsonSerializer.Serialize(locale);
        var bootstrap = $$"""
            (function(){
              var locale = {{langJson}};
              var shortLang = locale.indexOf('-') >= 0 ? locale.split('-')[0] : locale;
              var langList = [locale, shortLang];
              try {
                Object.defineProperty(navigator, 'language', { configurable: true, get: function() { return locale; } });
                Object.defineProperty(navigator, 'languages', { configurable: true, get: function() { return langList.slice(); } });
              } catch (e) {}
              try {
                var _DTF = Intl.DateTimeFormat;
                function wrapDTF(locales, options) {
                  if (locales === undefined) locales = langList;
                  return new _DTF(locales, options);
                }
                wrapDTF.prototype = _DTF.prototype;
                wrapDTF.supportedLocalesOf = _DTF.supportedLocalesOf.bind(_DTF);
                Intl.DateTimeFormat = wrapDTF;
              } catch (e) {}
              try {
                var _NF = Intl.NumberFormat;
                function wrapNF(locales, options) {
                  if (locales === undefined) locales = langList;
                  return new _NF(locales, options);
                }
                wrapNF.prototype = _NF.prototype;
                wrapNF.supportedLocalesOf = _NF.supportedLocalesOf.bind(_NF);
                Intl.NumberFormat = wrapNF;
              } catch (e) {}
            })();
            """;
        _localeDocumentScriptId = await core.AddScriptToExecuteOnDocumentCreatedAsync(bootstrap);
    }

    private async Task ClearLocaleBrowserSurfaceAsync(CoreWebView2 core)
    {
        if (!string.IsNullOrEmpty(_localeDocumentScriptId))
        {
            try { core.RemoveScriptToExecuteOnDocumentCreated(_localeDocumentScriptId); }
            catch { /* ignore */ }
            _localeDocumentScriptId = null;
        }
    }

    #endregion
}

/// <summary>Snapshot of active environment overrides.</summary>
public sealed class EmulationState
{
    public GeoOverride? Geolocation { get; set; }
    public string? Locale { get; set; }
    public string? Timezone { get; set; }
    public string? ColorScheme { get; set; }
    public string? ReducedMotion { get; set; }
    public string? UserAgent { get; set; }
    public Dictionary<string, string> Permissions { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    public EmulationState Clone() => new()
    {
        Geolocation = Geolocation,
        Locale = Locale,
        Timezone = Timezone,
        ColorScheme = ColorScheme,
        ReducedMotion = ReducedMotion,
        UserAgent = UserAgent,
        Permissions = new Dictionary<string, string>(Permissions, StringComparer.OrdinalIgnoreCase)
    };

    public object ToApiObject() => new
    {
        geolocation = Geolocation == null
            ? null
            : new
            {
                latitude = Geolocation.Latitude,
                longitude = Geolocation.Longitude,
                accuracy = Geolocation.Accuracy
            },
        locale = Locale,
        timezone = Timezone,
        colorScheme = ColorScheme,
        reducedMotion = ReducedMotion,
        userAgent = UserAgent,
        permissions = Permissions
    };
}

public sealed record GeoOverride(double Latitude, double Longitude, double? Accuracy);

/// <summary>Partial update for <see cref="AutomationContext.SetEmulation"/>.</summary>
public sealed class EmulationUpdate
{
    public GeoUpdate? Geolocation { get; set; }
    public string? Locale { get; set; }
    public string? Timezone { get; set; }
    public string? ColorScheme { get; set; }
    public string? ReducedMotion { get; set; }
    public string? UserAgent { get; set; }
    public Dictionary<string, string>? Permissions { get; set; }
}

public sealed class GeoUpdate
{
    public bool Clear { get; set; }
    public double? Latitude { get; set; }
    public double? Longitude { get; set; }
    public double? Accuracy { get; set; }
}
