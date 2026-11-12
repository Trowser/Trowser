using System.Text.Json;

namespace Trowser.Automation;

/// <summary>
/// Decodes WebView2 <c>ExecuteScriptAsync</c> JSON-encoded results without
/// lossy quote-stripping that can corrupt emoji / non-ASCII escapes.
/// </summary>
public static class WebViewScriptResult
{
    /// <summary>
    /// Unwrap a JSON-encoded script result string. Returns empty for null/undefined.
    /// On deserialize failure, returns the original payload unchanged (never <c>Trim('"')</c>).
    /// </summary>
    public static string UnwrapJsonString(string? jsonResult)
    {
        if (string.IsNullOrEmpty(jsonResult) || jsonResult == "null" || jsonResult == "undefined")
            return "";

        if (jsonResult.Length >= 2 && jsonResult[0] == '"' && jsonResult[^1] == '"')
        {
            try
            {
                return JsonSerializer.Deserialize<string>(jsonResult) ?? "";
            }
            catch
            {
                // Do not Trim('"') — that leaves \uXXXX / surrogate escapes undecoded
                // and can surface as "??" for emoji after a later ANSI mis-decode.
                return jsonResult;
            }
        }

        return jsonResult;
    }
}
