namespace Trowser.Automation;

/// <summary>One request in a <see cref="AutomationContext.FetchBatchAsync"/> call.</summary>
public sealed class FetchBatchRequestItem
{
    public string Url { get; set; } = "";
    public string Method { get; set; } = "GET";
    public Dictionary<string, string>? Headers { get; set; }
    public string? Body { get; set; }
    public int TimeoutMs { get; set; } = 30000;
    /// <summary>"follow" (default), "manual" (capture redirect), or "error" (throw on redirect).</summary>
    public string? Redirect { get; set; }
    public bool UseServerSide { get; set; }
    public bool IncludeBrowserCookies { get; set; } = true;
    public string? IdentitySource { get; set; }
}

/// <summary>Result for one entry in <see cref="AutomationContext.FetchBatchAsync"/>.</summary>
public sealed class FetchBatchResultItem
{
    /// <summary>Echoes the input request (url, method, body) for correlating with the response.</summary>
    public string? RequestUrl { get; set; }
    public string? RequestMethod { get; set; }
    public string? RequestBody { get; set; }

    public int Index { get; set; }
    public bool Ok { get; set; }
    public int Status { get; set; }
    public string? StatusText { get; set; }
    public bool Redirected { get; set; }
    public string? ResponseType { get; set; }
    public string? ResponseUrl { get; set; }
    public Dictionary<string, string> Headers { get; set; } = new();
    public string? Body { get; set; }
    public string? Error { get; set; }
    /// <summary>Wall-clock duration of this fetch call in milliseconds.</summary>
    public long DurationMs { get; set; }
    public string? IdentitySource { get; set; }
    /// <summary>Cookie names sent on this request. Values are never included.</summary>
    public List<string> CookiesSent { get; set; } = [];
    public bool? IncludeBrowserCookies { get; set; }
    /// <summary><c>browser-page</c>, <c>browser-session</c>, <c>anonymous</c>, <c>peer:…</c>, or <c>identity:…</c>.</summary>
    public string? IdentityUsed { get; set; }
}
