using System.Collections.Concurrent;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Waits for human SSO/MFA completion, detects cookie/storage deltas, auto-captures identity.
/// </summary>
public sealed class IdentityHandoffManager
{
    private readonly ConcurrentDictionary<string, IdentityHandoffState> _active = new(StringComparer.OrdinalIgnoreCase);
    private readonly IdentityStore _store;

    public IdentityHandoffManager(IdentityStore store)
    {
        _store = store;
    }

    public async Task<IdentityHandoffState> StartAsync(
        AutomationContext context,
        string name,
        int timeoutMs,
        string? livenessUrl)
    {
        if (!IdentityStore.IsValidName(name))
            throw new ArgumentException("Invalid identity name.");

        timeoutMs = Math.Clamp(timeoutMs, 5_000, 600_000);

        var cookies = await context.GetCookies();
        var localStorage = await context.GetAllStorage("local");
        var sessionStorage = await context.GetAllStorage("session");

        int? baselineLiveness = null;
        if (!string.IsNullOrWhiteSpace(livenessUrl))
        {
            var (status, _, _, _) = await IdentityStore.FetchWithBrowserCookiesAsync(
                context, livenessUrl.Trim(), "GET");
            baselineLiveness = status;
        }

        var state = new IdentityHandoffState
        {
            Name = name.Trim(),
            Status = "waiting",
            StartedAt = DateTime.UtcNow,
            ExpiresAt = DateTime.UtcNow.AddMilliseconds(timeoutMs),
            LivenessUrl = string.IsNullOrWhiteSpace(livenessUrl) ? null : livenessUrl.Trim(),
            BaselineCookieCount = cookies.Count,
            BaselineCookieFingerprint = SessionIdentityIntrospection.ComputeCookieFingerprint(cookies),
            BaselineLocalStorageCount = localStorage.Count,
            BaselineSessionStorageCount = sessionStorage.Count,
            BaselineLivenessStatus = baselineLiveness,
            Message = "Complete SSO/MFA in the browser. Poll GET /api/identity/handoff?name=" + name.Trim()
        };

        _active[name.Trim()] = state;
        return state;
    }

    public async Task<IdentityHandoffState> PollAsync(
        AutomationContext context,
        string name,
        string? sessionName,
        bool autoCapture = true)
    {
        if (!IdentityStore.IsValidName(name))
            throw new ArgumentException("Invalid identity name.");

        name = name.Trim();
        if (!_active.TryGetValue(name, out var state))
        {
            return new IdentityHandoffState
            {
                Name = name,
                Status = "not_found",
                Message = "No active handoff for this name. POST /api/identity/handoff to start."
            };
        }

        if (DateTime.UtcNow >= state.ExpiresAt)
        {
            state.Status = "expired";
            state.Message = "Handoff timed out before identity change was detected.";
            _active.TryRemove(name, out _);
            return state;
        }

        if (state.Status == "captured")
            return state;

        var cookies = await context.GetCookies();
        var localStorage = await context.GetAllStorage("local");
        var sessionStorage = await context.GetAllStorage("session");
        var fingerprint = SessionIdentityIntrospection.ComputeCookieFingerprint(cookies);

        var cookieDelta = cookies.Count != state.BaselineCookieCount ||
                          !string.Equals(fingerprint, state.BaselineCookieFingerprint, StringComparison.Ordinal);
        var storageDelta = localStorage.Count != state.BaselineLocalStorageCount ||
                           sessionStorage.Count != state.BaselineSessionStorageCount;

        var livenessPassed = false;
        if (!string.IsNullOrWhiteSpace(state.LivenessUrl))
        {
            var (status, _, _, _) = await IdentityStore.FetchWithBrowserCookiesAsync(
                context, state.LivenessUrl, "GET");
            livenessPassed = status >= 200 && status < 300 &&
                             state.BaselineLivenessStatus is not (>= 200 and < 300);
        }

        if (!cookieDelta && !storageDelta && !livenessPassed)
        {
            state.Message = "Waiting for login/MFA — no cookie, storage, or liveness change yet.";
            return state;
        }

        if (!autoCapture)
        {
            state.Status = "ready";
            state.Message = "Identity change detected. POST /api/identity/capture to save, or poll with autoCapture=true.";
            return state;
        }

        var snapshot = await _store.CaptureAsync(context, name, sessionName);
        state.Status = "captured";
        state.CapturedIdentity = name;
        state.Message = $"Identity captured at {snapshot.Metadata.CapturedAt:O}.";
        _active.TryRemove(name, out _);
        return state;
    }

    public bool Cancel(string name)
    {
        if (!IdentityStore.IsValidName(name)) return false;
        return _active.TryRemove(name.Trim(), out _);
    }

    public IdentityHandoffState? Get(string name) =>
        _active.TryGetValue(name.Trim(), out var state) ? state : null;
}
