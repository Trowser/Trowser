using System.IO;
using System.Reflection;
using System.Text.Json;
using Microsoft.Web.WebView2.Wpf;
using Trowser.Automation;

namespace Trowser.Security;

/// <summary>
/// Evaluates Content-Security-Policy headers using Google's csp-evaluator library
/// injected into the current WebView2 page.
/// </summary>
public static class CspEvaluatorChecker
{
    private const string ReferenceUrl = "https://csp-evaluator.withgoogle.com/";
    private const string Recommendation =
        "See https://csp-evaluator.withgoogle.com/ and OWASP CSP Cheat Sheet";

    private static string? _bundleScript;

    public static async Task<List<HeaderFinding>> EvaluateAsync(
        WebView2 webView,
        string cspPolicy,
        CancellationToken cancellationToken = default)
    {
        if (webView == null) throw new ArgumentNullException(nameof(webView));
        if (string.IsNullOrWhiteSpace(cspPolicy))
            return new List<HeaderFinding>();

        cancellationToken.ThrowIfCancellationRequested();
        var bundleScript = await GetBundleScriptAsync();

        var injectResult = await WebViewUiScript.RunAsync(webView,
            bundleScript + "\n; typeof cspEvaluator !== 'undefined' ? 'OK' : 'FAIL'", cancellationToken,
            operationLabel: "CSP evaluation");

        if (injectResult != "OK")
            throw new InvalidOperationException(
                $"Failed to inject csp-evaluator into the page. Result: {injectResult}");

        var cspJson = JsonSerializer.Serialize(cspPolicy);
        var evalScript = $@"
(function() {{
    try {{
        var csp = {cspJson};
        var parsed = new cspEvaluator.CspParser(csp).csp;
        var findings = new cspEvaluator.CspEvaluator(parsed).evaluate();
        return JSON.stringify(findings.map(function(f) {{
            return {{
                description: f.description,
                severity: f.severity,
                directive: f.directive || null,
                value: f.value || null
            }};
        }}));
    }} catch (e) {{
        return JSON.stringify({{ error: e.message || String(e) }});
    }}
}})()";

        var json = await WebViewUiScript.RunAsync(webView, evalScript, cancellationToken,
            operationLabel: "CSP evaluation");
        if (string.IsNullOrEmpty(json))
            throw new InvalidOperationException("csp-evaluator returned no results.");

        return ParseFindings(json, cspPolicy);
    }

    private static async Task<string> GetBundleScriptAsync()
    {
        if (_bundleScript != null) return _bundleScript;

        var assembly = Assembly.GetExecutingAssembly();
        using var stream = assembly.GetManifestResourceStream("Trowser.Resources.csp-evaluator.bundle.js");

        if (stream == null)
        {
            throw new InvalidOperationException(
                "csp-evaluator script not found as embedded resource. " +
                "Ensure csp-evaluator.bundle.js is in Resources/ and marked as EmbeddedResource in the .csproj.");
        }

        using var reader = new StreamReader(stream);
        _bundleScript = await reader.ReadToEndAsync();
        return _bundleScript;
    }

    private static List<HeaderFinding> ParseFindings(string json, string cspPolicy)
    {
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        if (root.ValueKind == JsonValueKind.Object && root.TryGetProperty("error", out var errorProp))
        {
            throw new InvalidOperationException(
                $"csp-evaluator error: {errorProp.GetString() ?? "Unknown error"}");
        }

        if (root.ValueKind != JsonValueKind.Array)
            throw new InvalidOperationException("csp-evaluator returned unexpected JSON.");

        var findings = new List<HeaderFinding>();

        foreach (var item in root.EnumerateArray())
        {
            if (!item.TryGetProperty("severity", out var severityProp)
                || !severityProp.TryGetInt32(out var severityValue))
                continue;

            if (severityValue == 100) // NONE
                continue;

            var mappedSeverity = MapSeverity(severityValue);
            if (mappedSeverity == null)
                continue;

            var description = item.TryGetProperty("description", out var descProp)
                ? descProp.GetString() ?? ""
                : "";

            var directive = item.TryGetProperty("directive", out var directiveProp)
                             && directiveProp.ValueKind == JsonValueKind.String
                ? directiveProp.GetString()
                : null;

            var value = item.TryGetProperty("value", out var valueProp)
                        && valueProp.ValueKind == JsonValueKind.String
                ? valueProp.GetString()
                : null;

            if (!string.IsNullOrEmpty(directive))
                description = string.IsNullOrEmpty(description)
                    ? $"Directive: {directive}"
                    : $"{description} (directive: {directive})";

            if (!string.IsNullOrEmpty(value))
                description = string.IsNullOrEmpty(description)
                    ? $"Value: {value}"
                    : $"{description}; value: {value}";

            findings.Add(new HeaderFinding
            {
                Header = "Content-Security-Policy",
                Severity = mappedSeverity.Value,
                Description = description,
                Recommendation = Recommendation,
                CurrentValue = value ?? cspPolicy,
                Reference = ReferenceUrl
            });
        }

        return findings;
    }

    private static Severity? MapSeverity(int severityValue) => severityValue switch
    {
        10 => Severity.High,       // HIGH
        20 => Severity.Medium,      // SYNTAX
        30 => Severity.Medium,      // MEDIUM
        40 => Severity.Medium,      // HIGH_MAYBE
        45 => Severity.Info,        // STRICT_CSP
        50 => Severity.Info,        // MEDIUM_MAYBE
        60 => Severity.Info,        // INFO
        100 => null,                // NONE (skipped earlier)
        _ => null
    };

}
