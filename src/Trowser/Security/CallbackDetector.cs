using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// A detected out-of-band interaction from the browser's network log.
/// </summary>
public class CallbackInteraction
{
    private static int _nextId;

    public int Id { get; init; } = Interlocked.Increment(ref _nextId);
    public DateTime Timestamp { get; init; } = DateTime.UtcNow;
    public string Tier { get; init; } = "client";
    public string Type { get; init; } = "http-request";
    public string From { get; init; } = "browser";
    public string Url { get; init; } = "";
    public string? Method { get; init; }
    public int? StatusCode { get; init; }
    public string? CorrelationId { get; init; }
    public string? Finding { get; init; }
}

/// <summary>
/// Tier 1 OOB detection: monitors the browser's network log for requests to callback domains.
/// When injected payloads cause the browser to make unexpected requests (blind XSS, DOM SSRF,
/// CSS injection exfiltration), those appear in the network log and are caught here.
/// No external infrastructure needed — this exploits the fact that Trowser IS the browser.
/// </summary>
public class CallbackDetector
{
    private readonly object _lock = new();
    private readonly List<CallbackInteraction> _interactions = [];
    private readonly HashSet<string> _seenUrls = new(StringComparer.OrdinalIgnoreCase);
    private int _lastPolledId;

    /// <summary>The callback domain used in payload markers. Requests to this domain are detected.</summary>
    public string CallbackDomain { get; private set; } = "callback.trowser.test";

    /// <summary>The full callback URL base for substitution in payloads.</summary>
    public string CallbackUrl => $"https://{CallbackDomain}";

    /// <summary>The marker string to use in fuzz payloads. Will be substituted with the callback URL.</summary>
    /// <remarks>
    /// Prefer ASCII-safe <see cref="MarkerAscii"/> (<c>{{CALLBACK}}</c>) — the legacy
    /// <c>§CALLBACK§</c> form can mojibake when clients mis-decode UTF-8.
    /// </remarks>
    public const string Marker = "{{CALLBACK}}";

    /// <summary>Legacy section-sign marker (still accepted by <see cref="SubstituteMarkers"/>).</summary>
    /// <remarks>Uses Unicode escapes so source-file encoding cannot mojibake <c>§</c>.</remarks>
    public const string MarkerLegacy = "\u00A7CALLBACK\u00A7";

    /// <summary>ASCII-safe marker alias (same as <see cref="Marker"/>).</summary>
    public const string MarkerAscii = "{{CALLBACK}}";

    public bool Active { get; private set; }

    /// <summary>Fired when a new callback interaction is detected.</summary>
    public event Action<CallbackInteraction>? InteractionDetected;

    public void Start(string? customDomain = null)
    {
        if (customDomain != null) CallbackDomain = customDomain;
        Active = true;
    }

    public void Stop()
    {
        Active = false;
    }

    public void Clear()
    {
        lock (_lock)
        {
            _interactions.Clear();
            _seenUrls.Clear();
            _lastPolledId = 0;
        }
    }

    /// <summary>
    /// Called for each new network entry. Checks if the request is to the callback domain.
    /// </summary>
    public void OnNetworkEntry(NetworkEntry entry)
    {
        if (!Active) return;
        if (!IsRequestToCallbackHost(entry.Url, CallbackDomain)) return;

        lock (_lock)
        {
            if (!_seenUrls.Add(entry.Url)) return; // deduplicate

            var correlationId = ExtractCorrelationId(entry.Url);
            var interaction = new CallbackInteraction
            {
                Url = entry.Url,
                Method = entry.Method,
                StatusCode = entry.StatusCode,
                CorrelationId = correlationId,
                Finding = $"Browser made request to callback domain: {entry.Method} {entry.Url}" +
                          (correlationId != null ? $" (correlation: {correlationId})" : "")
            };
            _interactions.Add(interaction);
            InteractionDetected?.Invoke(interaction);
        }
    }

    /// <summary>
    /// True when the request URL's host is the callback domain (not merely mentioned in query/path).
    /// </summary>
    internal static bool IsRequestToCallbackHost(string url, string callbackDomain)
    {
        if (string.IsNullOrWhiteSpace(url) || string.IsNullOrWhiteSpace(callbackDomain))
            return false;
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            return false;

        var host = uri.Host;
        if (host.Equals(callbackDomain, StringComparison.OrdinalIgnoreCase))
            return true;

        // Allow probe subdomains when the configured domain is a registrable suffix
        // (e.g. host "abc.oast.fun" with domain "oast.fun").
        return host.EndsWith("." + callbackDomain, StringComparison.OrdinalIgnoreCase);
    }

    public List<CallbackInteraction> GetInteractions(int? sinceId = null)
    {
        lock (_lock)
        {
            return sinceId.HasValue
                ? _interactions.Where(i => i.Id > sinceId.Value).ToList()
                : [.. _interactions];
        }
    }

    public int NewSinceLastPoll
    {
        get
        {
            lock (_lock) { return _interactions.Count(i => i.Id > _lastPolledId); }
        }
    }

    public void MarkPolled()
    {
        lock (_lock)
        {
            if (_interactions.Count > 0) _lastPolledId = _interactions[^1].Id;
        }
    }

    /// <summary>
    /// Generate a unique probe URL for use in payloads.
    /// </summary>
    public string GenerateProbeUrl(string? label = null)
    {
        var id = Guid.NewGuid().ToString("N")[..8];
        var path = label != null ? $"/probe-{label}-{id}" : $"/probe-{id}";
        return $"{CallbackUrl}{path}";
    }

    /// <summary>
    /// Substitute {{CALLBACK}} / §CALLBACK§ markers in a payload string with the callback URL.
    /// </summary>
    public string SubstituteMarkers(string payload)
    {
        if (string.IsNullOrEmpty(payload)) return payload;
        var result = payload.Replace(MarkerAscii, CallbackUrl, StringComparison.OrdinalIgnoreCase);
        result = result.Replace(MarkerLegacy, CallbackUrl, StringComparison.OrdinalIgnoreCase);
        // Also accept percent-encoded section signs that survived a bad URL round-trip.
        result = result.Replace("%C2%A7CALLBACK%C2%A7", CallbackUrl, StringComparison.OrdinalIgnoreCase);
        result = result.Replace("%c2%a7CALLBACK%c2%a7", CallbackUrl, StringComparison.OrdinalIgnoreCase);
        return result;
    }

    /// <summary>True when the string contains any recognized CALLBACK marker form.</summary>
    public static bool ContainsCallbackMarker(string? text)
    {
        if (string.IsNullOrEmpty(text)) return false;
        return text.Contains(MarkerAscii, StringComparison.OrdinalIgnoreCase)
            || text.Contains(MarkerLegacy, StringComparison.OrdinalIgnoreCase)
            || text.Contains("%C2%A7CALLBACK%C2%A7", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Format interactions for text/LLM output.</summary>
    public string Format()
    {
        lock (_lock)
        {
            if (_interactions.Count == 0)
                return Active
                    ? $"OOB Callbacks active. Domain: {CallbackDomain}. No interactions detected yet."
                    : "OOB Callbacks not active.";

            var lines = new List<string>
            {
                $"=== OOB Callback Interactions ({_interactions.Count}) ===",
                $"Callback domain: {CallbackDomain}",
                ""
            };
            foreach (var i in _interactions)
            {
                lines.Add($"  [{i.Timestamp:HH:mm:ss}] {i.Method} {i.Url}");
                if (i.CorrelationId != null) lines.Add($"    Correlation: {i.CorrelationId}");
                if (i.Finding != null) lines.Add($"    {i.Finding}");
            }
            return string.Join(Environment.NewLine, lines);
        }
    }

    private static string? ExtractCorrelationId(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            return null;

        // Only inspect the path — ignore query strings where SSRF payloads may embed callback URLs.
        var path = uri.AbsolutePath;
        var pathStart = path.LastIndexOf("/probe-", StringComparison.OrdinalIgnoreCase);
        if (pathStart >= 0)
        {
            var probePath = path[(pathStart + 1)..];
            var qIdx = probePath.IndexOf('?');
            return qIdx >= 0 ? probePath[..qIdx] : probePath;
        }
        return null;
    }
}
