using System.IO;
using System.Reflection;
using System.Text.Json;
using Microsoft.Web.WebView2.Wpf;
using Trowser.Automation;

namespace Trowser.HtmlValidation;

/// <summary>
/// Injects html-validate into the current page and runs HTML markup validation.
/// Uses the html-validate:recommended preset with html5 element definitions.
/// </summary>
public class HtmlValidateChecker
{
    private readonly WebView2 _webView;
    private static string? _bundleScript;

    public HtmlValidateChecker(WebView2 webView)
    {
        _webView = webView ?? throw new ArgumentNullException(nameof(webView));
    }

    /// <summary>
    /// Run HTML validation on the current page's markup.
    /// </summary>
    public async Task<HtmlValidateResult> RunAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var bundleScript = await GetBundleScriptAsync();
        var callbackId = $"__trowser_htmlval_{Guid.NewGuid():N}";

        var injectResult = await WebViewUiScript.RunAsync(_webView,
            bundleScript + "\n; typeof htmlvalidate !== 'undefined' ? 'OK' : 'FAIL'", cancellationToken,
            operationLabel: "HTML validation");

        if (injectResult != "OK")
        {
            throw new InvalidOperationException(
                $"Failed to inject html-validate into the page. Result: {injectResult}");
        }

        // Build and run the validation script
        var validationScript = BuildValidationScript(callbackId);
        var startResult = await WebViewUiScript.RunAsync(_webView, validationScript, cancellationToken,
            operationLabel: "HTML validation");

        if (startResult != "STARTED")
        {
            throw new InvalidOperationException(
                $"Failed to start HTML validation. Result: {startResult}");
        }

        // Poll for results
        var deadline = DateTime.UtcNow.AddSeconds(15);
        string? json = null;

        while (DateTime.UtcNow < deadline)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var doneCheck = await WebViewUiScript.RunAsync(_webView, $"window['{callbackId}_done']",
                cancellationToken, operationLabel: "HTML validation");
            if (doneCheck == "true")
            {
                json = await WebViewUiScript.RunAsync(_webView, $"window['{callbackId}']",
                    cancellationToken, operationLabel: "HTML validation");
                await WebViewUiScript.RunAsync(_webView,
                    $"delete window['{callbackId}']; delete window['{callbackId}_done']; 'OK'",
                    cancellationToken, operationLabel: "HTML validation");
                break;
            }
            await Task.Delay(100, cancellationToken);
        }

        if (string.IsNullOrEmpty(json))
        {
            throw new TimeoutException("HTML validation did not complete within 15 seconds.");
        }

        return ParseResults(json);
    }

    #region Script Building

    private static string BuildValidationScript(string callbackId)
    {
        return $@"
(function() {{
    window['{callbackId}'] = null;
    window['{callbackId}_done'] = false;

    try {{
        var HtmlValidate = htmlvalidate.HtmlValidate;
        var StaticConfigLoader = htmlvalidate.StaticConfigLoader;

        var loader = new StaticConfigLoader({{
            extends: ['html-validate:recommended'],
            elements: ['html5'],
            rules: {{
                'no-trailing-whitespace': 'off',
                'no-inline-style': 'off',
                'attr-quotes': 'off',
                'doctype-style': 'off',
                'void-style': 'off',
                'no-self-closing': 'off',
                'attribute-boolean-style': 'off',
                'attribute-empty-style': 'off',
                'no-implicit-close': 'off',
                'prefer-tbody': 'off'
            }}
        }});

        var validator = new HtmlValidate(loader);
        var html = document.documentElement.outerHTML;
        var doctypeNode = document.doctype;
        if (doctypeNode) {{
            var doctype = '<!DOCTYPE ' + doctypeNode.name;
            if (doctypeNode.publicId) doctype += ' PUBLIC ""' + doctypeNode.publicId + '""';
            if (doctypeNode.systemId) doctype += ' ""' + doctypeNode.systemId + '""';
            doctype += '>';
            html = doctype + '\n' + html;
        }}

        validator.validateString(html).then(function(report) {{
            var messages = [];
            if (report.results && report.results.length > 0) {{
                report.results[0].messages.forEach(function(msg) {{
                    messages.push({{
                        ruleId: msg.ruleId || '',
                        severity: msg.severity || 2,
                        message: msg.message || '',
                        line: msg.line || 0,
                        column: msg.column || 0,
                        offset: msg.offset || 0,
                        size: msg.size || 0,
                        ruleUrl: msg.ruleUrl || null
                    }});
                }});
            }}

            window['{callbackId}'] = JSON.stringify({{
                url: location.href,
                valid: report.valid,
                errorCount: report.errorCount || 0,
                warningCount: report.warningCount || 0,
                messages: messages
            }});
            window['{callbackId}_done'] = true;
        }}).catch(function(err) {{
            window['{callbackId}'] = JSON.stringify({{
                error: err.message || String(err)
            }});
            window['{callbackId}_done'] = true;
        }});
    }} catch(e) {{
        window['{callbackId}'] = JSON.stringify({{ error: e.message || String(e) }});
        window['{callbackId}_done'] = true;
    }}

    return 'STARTED';
}})()";
    }

    #endregion

    #region Result Parsing

    private static HtmlValidateResult ParseResults(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        if (root.TryGetProperty("error", out var errorProp))
        {
            throw new InvalidOperationException(
                $"HTML validation error: {errorProp.GetString()}");
        }

        var url = root.TryGetProperty("url", out var u) ? u.GetString() ?? "" : "";
        var messages = new List<HtmlValidateMessage>();

        if (root.TryGetProperty("messages", out var msgsArray))
        {
            foreach (var msgEl in msgsArray.EnumerateArray())
            {
                messages.Add(new HtmlValidateMessage
                {
                    RuleId = msgEl.TryGetProperty("ruleId", out var r) ? r.GetString() ?? "" : "",
                    Severity = msgEl.TryGetProperty("severity", out var s) && s.GetInt32() == 1
                        ? HtmlSeverity.Warning
                        : HtmlSeverity.Error,
                    Message = msgEl.TryGetProperty("message", out var m) ? m.GetString() ?? "" : "",
                    Line = msgEl.TryGetProperty("line", out var l) ? l.GetInt32() : 0,
                    Column = msgEl.TryGetProperty("column", out var c) ? c.GetInt32() : 0,
                    Offset = msgEl.TryGetProperty("offset", out var o) ? o.GetInt32() : 0,
                    Size = msgEl.TryGetProperty("size", out var sz) ? sz.GetInt32() : 0,
                    RuleUrl = msgEl.TryGetProperty("ruleUrl", out var ru)
                        ? ru.GetString()
                        : null
                });
            }
        }

        return new HtmlValidateResult
        {
            Url = url,
            Timestamp = DateTime.UtcNow,
            Messages = messages
        };
    }

    #endregion

    #region Resource Loading

    private static async Task<string> GetBundleScriptAsync()
    {
        if (_bundleScript != null) return _bundleScript;

        var assembly = Assembly.GetExecutingAssembly();
        using var stream = assembly.GetManifestResourceStream("Trowser.Resources.html-validate.bundle.js")
            ?? throw new FileNotFoundException("html-validate bundle not found as embedded resource.");

        using var reader = new StreamReader(stream);
        _bundleScript = await reader.ReadToEndAsync();
        return _bundleScript;
    }

    #endregion

}
