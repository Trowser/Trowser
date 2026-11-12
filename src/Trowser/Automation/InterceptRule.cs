using System.Text.RegularExpressions;
using Microsoft.Web.WebView2.Core;

namespace Trowser.Automation;

/// <summary>
/// A rule for pausing (breakpointing) network requests that match a URL regex.
/// Unlike mock rules which auto-respond, intercept rules hold the request until
/// the user or API decides to continue, fulfill, or abort.
/// </summary>
public class InterceptRule
{
    /// <summary>URL regex pattern to match against the full request URL.</summary>
    public string UrlPattern { get; set; } = "";

    /// <summary>HTTP method to match (null = any method).</summary>
    public string? Method { get; set; }

    /// <summary>
    /// When true, intercepted requests don't open the breakpoint dialog in the UI.
    /// Set automatically for rules added via REST API, MCP, or scripting.
    /// </summary>
    public bool Silent { get; set; }

    /// <summary>When false, this rule is kept but not applied (toggle off without removing).</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// When set, matching requests are fulfilled immediately (no breakpoint / pending queue).
    /// Used by verify-workflow CDN tamper proofs and auto-fulfill intercept rules.
    /// </summary>
    public InterceptDecision? AutoFulfill { get; set; }

    private Regex? _compiled;

    public bool Matches(string url, string method)
    {
        if (Method != null && !Method.Equals(method, StringComparison.OrdinalIgnoreCase))
            return false;

        try
        {
            _compiled ??= new Regex(UrlPattern, RegexOptions.IgnoreCase | RegexOptions.Compiled);
            return _compiled.IsMatch(url);
        }
        catch (RegexParseException)
        {
            return url.Contains(UrlPattern, StringComparison.OrdinalIgnoreCase);
        }
    }
}

/// <summary>
/// What to do with an intercepted request.
/// </summary>
public enum InterceptAction
{
    /// <summary>Let the request proceed (optionally with modified URL/method/headers).</summary>
    Continue,
    /// <summary>Return a custom response without hitting the server.</summary>
    Fulfill,
    /// <summary>Abort the request as if the network were unreachable.</summary>
    Abort
}

/// <summary>
/// The decision made for a pending intercepted request.
/// </summary>
public class InterceptDecision
{
    public InterceptAction Action { get; init; } = InterceptAction.Continue;

    // Continue: optional request modifications
    public string? ModifiedUrl { get; init; }
    public string? ModifiedMethod { get; init; }
    public Dictionary<string, string>? ModifiedHeaders { get; init; }
    public string? ModifiedBody { get; init; }

    // Fulfill: custom response
    public int StatusCode { get; init; } = 200;
    public string? Body { get; init; }
    public Dictionary<string, string>? ResponseHeaders { get; init; }
}

/// <summary>
/// A network request that has been intercepted and is waiting for a decision.
/// The WebView2 deferral holds the browser request open until resolved.
/// </summary>
public class PendingRequest
{
    private static int _nextId;

    public int Id { get; } = Interlocked.Increment(ref _nextId);
    public string Url { get; init; } = "";
    public string Method { get; init; } = "";
    public Dictionary<string, string> Headers { get; init; } = new();
    public string? Body { get; init; }
    public string ResourceType { get; init; } = "";
    public DateTime Timestamp { get; init; } = DateTime.UtcNow;
    public string MatchedPattern { get; init; } = "";

    internal CoreWebView2Deferral Deferral { get; init; } = null!;
    internal CoreWebView2WebResourceRequestedEventArgs EventArgs { get; init; } = null!;

    private readonly TaskCompletionSource<InterceptDecision> _decision = new();

    /// <summary>True once a decision has been made (via Resolve or timeout).</summary>
    public bool IsResolved => _decision.Task.IsCompleted;

    /// <summary>
    /// Wait for the user/API to make a decision about this request.
    /// Returns the default (Continue) on timeout.
    /// </summary>
    public async Task<InterceptDecision> WaitForDecision(TimeSpan timeout)
    {
        using var cts = new CancellationTokenSource(timeout);
        try
        {
            cts.Token.Register(() => _decision.TrySetResult(new InterceptDecision { Action = InterceptAction.Continue }));
            return await _decision.Task;
        }
        catch
        {
            return new InterceptDecision { Action = InterceptAction.Continue };
        }
    }

    /// <summary>
    /// Resolve this pending request with a decision.
    /// </summary>
    public bool Resolve(InterceptDecision decision) => _decision.TrySetResult(decision);
}
