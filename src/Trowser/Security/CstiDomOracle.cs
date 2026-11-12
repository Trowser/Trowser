using System.Text.Json;
using System.Text.RegularExpressions;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Captures rendered DOM text/input values and detects template arithmetic evaluation (e.g. 49 from {{7*7}}).
/// </summary>
internal static class CstiDomOracle
{
    private static readonly Regex Token49 = new(@"(?<!\d)49(?!\d)", RegexOptions.Compiled);
    private static readonly Regex Token56 = new(@"(?<!\d)56(?!\d)", RegexOptions.Compiled);

    internal sealed class DomSnapshot
    {
        public string VisibleText { get; init; } = "";
        public string InputValues { get; init; } = "";
        public string Combined => $"{VisibleText}\n{InputValues}";
    }

    internal static async Task<DomSnapshot> CaptureAsync(AutomationContext ctx)
    {
        var json = await ctx.ExecuteJs(CaptureScript);
        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            return new DomSnapshot
            {
                VisibleText = root.TryGetProperty("visibleText", out var vt) ? vt.GetString() ?? "" : "",
                InputValues = root.TryGetProperty("inputValues", out var iv) ? iv.GetString() ?? "" : ""
            };
        }
        catch
        {
            return new DomSnapshot();
        }
    }

    internal static bool DetectEvaluation(string payload, DomSnapshot baseline, DomSnapshot probe, out string token)
    {
        token = ExpectedToken(payload);
        return DetectToken(baseline, probe, token);
    }

    internal static bool DetectToken(DomSnapshot baseline, DomSnapshot probe, string? token)
    {
        if (string.IsNullOrEmpty(token)) return false;

        var regex = token switch
        {
            "56" => Token56,
            "49" => Token49,
            "7777777" => new Regex(@"(?<!\d)7777777(?!\d)", RegexOptions.Compiled),
            _ => new Regex($@"(?<!\w){Regex.Escape(token)}(?!\w)", RegexOptions.Compiled)
        };

        if (!regex.IsMatch(probe.Combined)) return false;
        if (regex.IsMatch(baseline.Combined)) return false;
        return true;
    }

    internal static string ExpectedToken(string payload)
    {
        if (payload.Contains("globalThis", StringComparison.OrdinalIgnoreCase)
            || payload.Contains("return this", StringComparison.OrdinalIgnoreCase))
            return "[object Window]";
        if (payload.Contains("7*'7'", StringComparison.Ordinal)) return "7777777";
        if (payload.Contains("7*8", StringComparison.Ordinal)) return "56";
        if (payload.Contains("7*7", StringComparison.Ordinal)) return "49";
        if (payload.Contains("1+1", StringComparison.Ordinal)) return "2";
        return "";
    }

    internal static bool DetectWindowObject(DomSnapshot baseline, DomSnapshot probe) =>
        probe.Combined.Contains("[object Window]", StringComparison.Ordinal)
        && !baseline.Combined.Contains("[object Window]", StringComparison.Ordinal);

    private const string CaptureScript = """
        (function() {
            try {
                var parts = [];
                if (document.body) {
                    var bodyText = (document.body.innerText || '').trim();
                    if (bodyText) parts.push(bodyText);
                }
                var inputParts = [];
                document.querySelectorAll('input, textarea, select').forEach(function(el) {
                    var val = el.value || '';
                    if (!val) return;
                    var name = el.name || el.id || el.getAttribute('ng-model') || '';
                    inputParts.push((name ? name + '=' : '') + val);
                });
                document.querySelectorAll('[ng-bind], [data-ng-bind], [ng-bind-html]').forEach(function(el) {
                    var t = (el.textContent || '').trim();
                    if (t) parts.push(t);
                });
                return JSON.stringify({
                    visibleText: parts.join('\n'),
                    inputValues: inputParts.join('\n')
                });
            } catch (e) {
                return JSON.stringify({ visibleText: '', inputValues: '', error: e.message || String(e) });
            }
        })()
        """;
}
