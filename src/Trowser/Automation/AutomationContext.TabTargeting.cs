namespace Trowser.Automation;

public partial class AutomationContext
{
    /// <summary>Active tab context for API responses.</summary>
    public object GetActiveTabContext()
    {
        var tab = ActiveTab;
        return new
        {
            tabIndex = _activeTabIndex,
            tabId = tab?.Id,
            url = tab?.Url ?? "",
            title = tab?.Title ?? "",
            owner = tab?.Owner ?? TabOwners.Human
        };
    }

    /// <summary>
    /// Resolve optional <paramref name="tabIndex"/> or first tab whose URL contains <paramref name="urlMatch"/>.
    /// </summary>
    public int? ResolveTabTarget(int? tabIndex, string? urlMatch)
    {
        if (tabIndex is int idx)
        {
            if (idx < 0 || idx >= _tabs.Count)
                throw new ArgumentOutOfRangeException(nameof(tabIndex),
                    $"Invalid tab index: {idx}. There are {_tabs.Count} tab(s) (0-based).");
            return idx;
        }

        if (string.IsNullOrWhiteSpace(urlMatch))
            return null;

        for (var i = 0; i < _tabs.Count; i++)
        {
            if ((_tabs[i].Url ?? "").Contains(urlMatch, StringComparison.OrdinalIgnoreCase))
                return i;
        }

        throw new InvalidOperationException(
            $"No open tab URL contains \"{urlMatch}\". Use GET /api/tabs to list tabs, or POST /api/tabs/switch.");
    }

    /// <summary>
    /// Run an operation against a specific tab without leaving the prior active tab selected afterward.
    /// </summary>
    public async Task<T> InvokeOnTabAsync<T>(int? tabIndex, Func<Task<T>> action)
    {
        if (tabIndex is not int idx || idx == _activeTabIndex)
            return await action();

        if (idx < 0 || idx >= _tabs.Count)
            throw new ArgumentOutOfRangeException(nameof(tabIndex),
                $"Invalid tab index: {idx}. There are {_tabs.Count} tab(s) (0-based).");

        var prior = _activeTabIndex;
        SetActiveTab(idx);
        try
        {
            return await action();
        }
        finally
        {
            if (prior != idx)
                SetActiveTab(prior);
        }
    }

    /// <summary>
    /// Fail fast when web storage APIs cannot run on the current document (wrong/empty tab).
    /// </summary>
    public void EnsureWebStoragePageContext()
    {
        var tab = ActiveTab;
        var url = tab?.Url ?? "";
        var index = GetActiveTabIndex();

        if (string.IsNullOrWhiteSpace(url)
            || url.Equals("about:blank", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                $"Storage unavailable: active tab [{index}] is \"{url}\" (no origin). " +
                "Switch to the logged-in page (POST /api/tabs/switch), or pass tabIndex/urlMatch on this request.");
        }

        if (url.StartsWith("file:", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                $"Storage unavailable: active tab [{index}] is file:// — use an https:// page tab instead.");
        }
    }

    internal static string? TryFindCorsConsoleHint(BrowserTab tab, DateTime sinceUtc)
    {
        foreach (var e in tab.Console.Entries)
        {
            if (e.Timestamp < sinceUtc)
                continue;

            var m = e.Message;
            if (m.Contains("CORS", StringComparison.OrdinalIgnoreCase)
                || m.Contains("Access-Control", StringComparison.OrdinalIgnoreCase)
                || (m.Contains("blocked", StringComparison.OrdinalIgnoreCase)
                    && m.Contains("fetch", StringComparison.OrdinalIgnoreCase)))
            {
                return "Browser console reported a cross-origin blocked request — use POST /api/fetch (browser cookie jar, no CORS) instead of in-page fetch() via execute-js.";
            }
        }

        return null;
    }

    internal string FormatJsAsyncTimeout(int timeoutMs, DateTime startedUtc, string asyncExpressionScript)
    {
        var msg =
            $"JavaScript execution timed out after {timeoutMs / 1000} seconds. " +
            "The script may have triggered a navigation, failed to parse, or never resolved its Promise.";

        var cors = TryFindCorsConsoleHint(ActiveTab, startedUtc);
        if (cors != null)
            return msg + " " + cors;

        if (asyncExpressionScript.Contains("fetch(", StringComparison.Ordinal))
        {
            msg += " Cross-origin POST/GET from execute-js is often blocked by CORS — prefer POST /api/fetch.";
        }

        return msg;
    }
}
