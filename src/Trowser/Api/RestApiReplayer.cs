using System.Text.Json;
using Trowser.Automation;

namespace Trowser.Api;

/// <summary>
/// Replay a subset of REST automation routes inside workflow verify (.trw trigger steps).
/// Keeps parity with the public API bodies agents already capture in the journal.
/// </summary>
public static class RestApiReplayer
{
    private static readonly HashSet<string> SupportedPaths = new(StringComparer.OrdinalIgnoreCase)
    {
        "/api/navigate",
        "/api/click",
        "/api/type",
        "/api/fill",
        "/api/select",
        "/api/hover",
        "/api/key",
        "/api/press",
        "/api/scroll",
        "/api/go-back",
        "/api/go-forward"
    };

    public static bool IsSupportedPath(string? path) =>
        !string.IsNullOrWhiteSpace(path) && SupportedPaths.Contains(path.Trim());

    public static async Task<string?> TryReplayAsync(
        AutomationContext ctx,
        string method,
        string path,
        JsonElement? bodyEl,
        CancellationToken cancellation = default)
    {
        cancellation.ThrowIfCancellationRequested();
        path = path.Trim();
        method = method.Trim().ToUpperInvariant();
        if (method != "POST" || !SupportedPaths.Contains(path))
            return $"Unsupported REST workflow step: {method} {path}";

        JsonBody body = bodyEl is { } el && el.ValueKind == JsonValueKind.Object
            ? JsonBody.FromToolArguments(el)
            : new JsonBody(null);

        try
        {
            switch (path.ToLowerInvariant())
            {
                case "/api/navigate":
                    return await ReplayNavigateAsync(ctx, body);
                case "/api/go-back":
                    await ctx.GoBack();
                    return null;
                case "/api/go-forward":
                    await ctx.GoForward();
                    return null;
                case "/api/click":
                    return await ReplayClickAsync(ctx, body);
                case "/api/type":
                case "/api/fill":
                    return await ReplayTypeAsync(ctx, body);
                case "/api/select":
                    return await ReplaySelectAsync(ctx, body);
                case "/api/hover":
                    return await ReplayHoverAsync(ctx, body);
                case "/api/key":
                case "/api/press":
                    return await ReplayKeyAsync(ctx, body);
                case "/api/scroll":
                    return await ReplayScrollAsync(ctx, body);
                default:
                    return $"Unsupported REST workflow step: {method} {path}";
            }
        }
        catch (Exception ex)
        {
            return ex.Message;
        }
    }

    private static async Task<string?> ReplayNavigateAsync(AutomationContext ctx, JsonBody body)
    {
        var action = body.GetString("action")?.Trim().ToLowerInvariant();
        if (action is "back")
        {
            await ctx.GoBack();
            return null;
        }

        if (action is "forward")
        {
            await ctx.GoForward();
            return null;
        }

        if (action is "reload")
        {
            await ctx.Reload();
            return null;
        }

        var url = body.GetString("url");
        if (string.IsNullOrWhiteSpace(url))
            return "navigate step requires url.";

        var target = url.Trim();
        if (!target.Contains("://", StringComparison.Ordinal) && !target.StartsWith("about:", StringComparison.OrdinalIgnoreCase))
            target = "https://" + target;
        await ctx.Navigate(target, body.GetBool("reload", false), body.GetBool("ignoreCertificateErrors", false));
        return null;
    }

    private static async Task<string?> ReplayClickAsync(AutomationContext ctx, JsonBody body)
    {
        var (selector, error, _) = ResolveSelector(ctx, body);
        if (selector == null) return error ?? "click: missing target.";
        var button = body.GetString("button") ?? "left";
        var clickCount = Math.Max(1, body.GetInt("clickCount", 1));
        var timeout = body.GetInt("timeout", 0);
        await ctx.Click(selector, button, clickCount, timeout > 0 ? timeout : null);
        var waitMs = body.GetInt("waitAfterMs", 150);
        if (waitMs > 0) await Task.Delay(Math.Clamp(waitMs, 0, 30_000));
        return null;
    }

    private static async Task<string?> ReplayTypeAsync(AutomationContext ctx, JsonBody body)
    {
        var (selector, error, _) = ResolveSelector(ctx, body);
        if (selector == null) return error ?? "type: missing target.";
        var text = body.GetString("text") ?? body.GetString("value") ?? "";
        var clearFirst = !body.HasProperty("clear") || body.GetBool("clear", true);
        await ctx.Type(selector, text, timeoutMs: body.GetInt("timeout", 0) > 0 ? body.GetInt("timeout", 0) : null,
            clearFirst: clearFirst);
        return null;
    }

    private static async Task<string?> ReplaySelectAsync(AutomationContext ctx, JsonBody body)
    {
        var (selector, error, _) = ResolveSelector(ctx, body);
        if (selector == null) return error ?? "select: missing target.";
        var value = body.GetString("value");
        var label = body.GetString("label");
        await ctx.Select(selector, value ?? "", label);
        return null;
    }

    private static async Task<string?> ReplayHoverAsync(AutomationContext ctx, JsonBody body)
    {
        var (selector, error, _) = ResolveSelector(ctx, body);
        if (selector == null) return error ?? "hover: missing target.";
        await ctx.Hover(selector);
        return null;
    }

    private static async Task<string?> ReplayKeyAsync(AutomationContext ctx, JsonBody body)
    {
        var key = body.GetString("key");
        if (string.IsNullOrWhiteSpace(key)) return "key step requires key.";
        await ctx.PressKey(key);
        return null;
    }

    private static async Task<string?> ReplayScrollAsync(AutomationContext ctx, JsonBody body)
    {
        var selector = body.GetString("selector");
        var direction = body.GetString("direction") ?? "down";
        var scrollIntoView = body.GetBool("scrollIntoView", false);
        var x = body.HasProperty("x") ? body.GetDouble("x") : (double?)null;
        var y = body.HasProperty("y") ? body.GetDouble("y") : (double?)null;
        await ctx.Scroll(selector, direction, scrollIntoView, timeoutMs: null, x, y);
        return null;
    }

    private static (string? selector, string? error, string? staleWarning) ResolveSelector(AutomationContext ctx, JsonBody body)
    {
        string? explicitFrame = body.GetString("frame");

        var sel = body.GetString("selector");
        if (!string.IsNullOrWhiteSpace(sel))
            return (AutomationContext.ApplyFrame(sel, explicitFrame), null, null);

        if (body.HasProperty("ref"))
        {
            var refIndex = body.GetInt("ref", -1);
            var selector = ctx.GetSelectorByRef(refIndex);
            if (selector == null)
                return (null, $"Invalid ref: {refIndex}. Call GET /api/state first to get valid ref numbers.", null);
            var frame = !string.IsNullOrWhiteSpace(explicitFrame) ? explicitFrame : ctx.GetFrameIdByRef(refIndex);
            return (AutomationContext.ApplyFrame(selector, frame), null, null);
        }

        if (body.HasProperty("role"))
        {
            var role = body.GetString("role") ?? "";
            var name = body.GetString("name");
            var locator = !string.IsNullOrEmpty(name) ? $"@role:{role}:{name}" : $"@role:{role}:";
            return (AutomationContext.ApplyFrame(locator, explicitFrame), null, null);
        }

        if (body.HasProperty("label"))
            return (AutomationContext.ApplyFrame($"@label:{body.GetString("label") ?? ""}", explicitFrame), null, null);
        if (body.HasProperty("getByText") || body.HasProperty("byText"))
        {
            var text = body.GetString("getByText") ?? body.GetString("byText") ?? "";
            return (AutomationContext.ApplyFrame($"@text:{text}", explicitFrame), null, null);
        }

        if (body.HasProperty("placeholder"))
            return (AutomationContext.ApplyFrame($"@placeholder:{body.GetString("placeholder") ?? ""}", explicitFrame), null, null);
        if (body.HasProperty("testId"))
            return (AutomationContext.ApplyFrame($"@testid:{body.GetString("testId") ?? ""}", explicitFrame), null, null);
        if (body.HasProperty("value"))
            return (AutomationContext.ApplyFrame($"@value:{body.GetString("value") ?? ""}", explicitFrame), null, null);

        return (null, "Provide 'ref', 'selector', or a locator.", null);
    }
}