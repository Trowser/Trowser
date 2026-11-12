using System.Diagnostics;
using System.Globalization;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Opt-in 429 / Retry-After backoff for security probes (RFC 6585).
/// Records URLs that ultimately remain rate-limited after retries. Industry backoff pattern;
/// historically similar to pentest-ai <c>_safety.py</c> helpers — not a port of that module.
/// </summary>
public static class RateLimitRespectHelper
{
    public const double RetryAfterCapSeconds = 30.0;
    public const int DefaultMaxBackoffAttempts = 3;
    public const double DefaultBackoffSeconds = 2.0;

    public sealed class RespectState
    {
        /// <summary>True when the probe backed off due to HTTP 429 (Retry-After), not "target has no rate limit".</summary>
        public bool RateLimitRespected { get; set; }
        public int Http429Responses { get; set; }
        public List<string> SkippedDueTo429 { get; } = [];
        public int BackoffEvents { get; set; }

        public void NoteResponse(int status)
        {
            if (status == 429)
                Http429Responses++;
        }
    }

    public static double ParseRetryAfterSeconds(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return DefaultBackoffSeconds;

        if (double.TryParse(value.Trim(), NumberStyles.Float, CultureInfo.InvariantCulture, out var seconds))
            return Math.Clamp(seconds, 0, RetryAfterCapSeconds);

        if (DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var when))
        {
            var delta = (when - DateTimeOffset.UtcNow).TotalSeconds;
            return Math.Clamp(delta, 0, RetryAfterCapSeconds);
        }

        return DefaultBackoffSeconds;
    }

    public static async Task<SecurityProbeHttp.FetchResult> FetchAsync(
        AutomationContext ctx,
        string url,
        string method,
        IReadOnlyDictionary<string, string>? headers,
        string? body,
        int timeoutMs,
        bool includeBrowserCookies,
        bool respectRateLimits,
        RespectState? state,
        CancellationToken ct = default)
    {
        for (var attempt = 0; ; attempt++)
        {
            var result = await SecurityProbeHttp.FetchAsync(
                ctx, url, method, headers, body, timeoutMs, includeBrowserCookies, ct);
            state?.NoteResponse(result.Status);

            if (!respectRateLimits || result.Status != 429 || attempt >= DefaultMaxBackoffAttempts)
            {
                // Only record when the final attempt remains rate-limited (retry did not recover).
                if (respectRateLimits && result.Status == 429 && state != null
                    && !state.SkippedDueTo429.Contains(url, StringComparer.OrdinalIgnoreCase))
                    state.SkippedDueTo429.Add(url);
                return result;
            }

            if (state != null)
            {
                state.RateLimitRespected = true;
                state.BackoffEvents++;
            }

            var retryAfter = SecurityProbeHttp.GetResponseHeader(result, "Retry-After")
                             ?? SecurityProbeHttp.GetResponseHeader(result, "retry-after");
            var delay = ParseRetryAfterSeconds(retryAfter);
            await Task.Delay(TimeSpan.FromSeconds(delay), ct);
        }
    }

    public static async Task<SecurityProbeHttp.TimedFetchResult> FetchTimedAsync(
        AutomationContext ctx,
        string url,
        string method,
        IReadOnlyDictionary<string, string>? headers,
        string? body,
        int timeoutMs,
        bool includeBrowserCookies,
        bool respectRateLimits,
        RespectState? state,
        CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        var result = await FetchAsync(
            ctx, url, method, headers, body, timeoutMs, includeBrowserCookies, respectRateLimits, state, ct);
        return new SecurityProbeHttp.TimedFetchResult
        {
            Result = result,
            ElapsedSeconds = sw.Elapsed.TotalSeconds
        };
    }

    public static async Task<SecurityProbeHttp.TimedFetchResult> FetchTimedRawAsync(
        AutomationContext ctx,
        string url,
        string method,
        IReadOnlyDictionary<string, string>? headers,
        byte[]? bodyBytes,
        int timeoutMs,
        bool includeBrowserCookies,
        bool respectRateLimits,
        RespectState? state,
        CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        for (var attempt = 0; ; attempt++)
        {
            var result = await SecurityProbeHttp.FetchTimedRawAsync(
                ctx, url, method, headers, bodyBytes, timeoutMs, includeBrowserCookies, ct);
            state?.NoteResponse(result.Result.Status);

            if (!respectRateLimits || result.Result.Status != 429 || attempt >= DefaultMaxBackoffAttempts)
            {
                if (respectRateLimits && result.Result.Status == 429 && state != null
                    && !state.SkippedDueTo429.Contains(url, StringComparer.OrdinalIgnoreCase))
                    state.SkippedDueTo429.Add(url);
                return new SecurityProbeHttp.TimedFetchResult
                {
                    Result = result.Result,
                    ElapsedSeconds = sw.Elapsed.TotalSeconds
                };
            }

            if (state != null)
            {
                state.RateLimitRespected = true;
                state.BackoffEvents++;
            }

            var retryAfter = SecurityProbeHttp.GetResponseHeader(result.Result, "Retry-After")
                             ?? SecurityProbeHttp.GetResponseHeader(result.Result, "retry-after");
            var delay = ParseRetryAfterSeconds(retryAfter);
            await Task.Delay(TimeSpan.FromSeconds(delay), ct);
        }
    }
}
