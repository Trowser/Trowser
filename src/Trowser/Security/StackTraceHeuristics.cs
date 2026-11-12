using System.Text.RegularExpressions;

namespace Trowser.Security;

/// <summary>
/// Shared detection for stack traces and verbose error disclosure in HTTP responses.
/// </summary>
public static class StackTraceHeuristics
{
    /// <summary>Interactive debug consoles / leaked framework secrets — elevate to CRITICAL.</summary>
    private static readonly string[] CriticalDebugConsoleMarkers =
    [
        "Werkzeug Debugger",
        ">> this is a terminal-like client that has access to all variables in the current environment",
        "the console is locked and needs to be unlocked by entering the PIN",
        "SECRET = \"",
        "SECRET = '",
        "console.eval",
        "Django Debug Toolbar",
        "You're seeing this error because you have DEBUG = True",
        "django.views.debug",
    ];

    private static readonly string[] HighConfidenceMarkers =
    [
        "node_modules/express/",
        "/var/www/",
        "/usr/local/lib/",
        "/home/administrator/",
        "/home/runner/",
        "C:\\\\",
        "C:\\Users\\",
        "/Users/",
        "/app/build/",
        "/app/src/",
        "Werkzeug/debug",
        "Debugger PIN:",
        "DEBUG = True",
    ];

    private static readonly string[] MediumConfidenceMarkers =
    [
        "at Object.",
        "at Module._compile",
        "at process.processTicksAndRejections",
        "Traceback (most recent call last)",
        "java.lang.",
        "System.IO.",
        "TypeError:",
        "SyntaxError:",
        "ReferenceError:",
        "RangeError:",
        "ENOENT",
        "EADDRINUSE",
        "Error: Unexpected token",
        "JsonParseError",
        "stack trace",
        "Stack trace:",
        "Exception in thread",
        "sqlite3.OperationalError",
        "OperationalError",
        // ASP.NET yellow screens are verbose error disclosure, not interactive debug consoles.
        "ASP.NET yellow screen",
        "Server Error in '/' Application",
    ];

    /// <summary>Stack frame with file path and line:column (Node, Express, etc.).</summary>
    private static readonly Regex StackFramePathRegex = new(
        @"(?:at\s+[^\n]+\([^)]+\.(?:js|ts|jsx|tsx|mjs|cjs|vue|cs|java|py|rb|php|go):\d+:\d+\)|\([/\\][^)]+\:\d+\:\d+\))",
        RegexOptions.Compiled | RegexOptions.IgnoreCase,
        matchTimeout: TimeSpan.FromSeconds(2));

    /// <summary>Returns true when text appears to contain a server-side stack trace.</summary>
    public static bool HasStackTrace(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return false;

        if (CriticalDebugConsoleMarkers.Any(m => text.Contains(m, StringComparison.OrdinalIgnoreCase)))
            return true;

        if (HighConfidenceMarkers.Any(m => text.Contains(m, StringComparison.Ordinal)))
            return true;

        if (MediumConfidenceMarkers.Any(m => text.Contains(m, StringComparison.OrdinalIgnoreCase)))
            return true;

        return StackFramePathRegex.IsMatch(text);
    }

    /// <summary>
    /// Classify error disclosure relative to a baseline body.
    /// Returns (severity, marker) when probe body leaks more than baseline.
    /// </summary>
    public static (string Severity, string Marker)? ClassifyRelativeToBaseline(string probeBody, string baselineBody)
    {
        if (string.IsNullOrEmpty(probeBody)) return null;

        foreach (var marker in CriticalDebugConsoleMarkers)
        {
            if (probeBody.Contains(marker, StringComparison.OrdinalIgnoreCase)
                && !baselineBody.Contains(marker, StringComparison.OrdinalIgnoreCase))
                return ("critical", marker);
        }

        foreach (var marker in HighConfidenceMarkers)
        {
            if (probeBody.Contains(marker, StringComparison.Ordinal)
                && !baselineBody.Contains(marker, StringComparison.Ordinal))
                return ("high", marker);
        }

        if (StackFramePathRegex.IsMatch(probeBody) && !StackFramePathRegex.IsMatch(baselineBody))
            return ("high", "stack-frame-with-path");

        foreach (var marker in MediumConfidenceMarkers)
        {
            if (probeBody.Contains(marker, StringComparison.OrdinalIgnoreCase)
                && !baselineBody.Contains(marker, StringComparison.OrdinalIgnoreCase))
                return ("medium", marker);
        }

        return null;
    }
}
