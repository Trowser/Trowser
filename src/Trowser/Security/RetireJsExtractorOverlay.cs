using System.Text.RegularExpressions;

namespace Trowser.Security;

/// <summary>
/// Trowser-owned Retire.js extractor supplements. The upstream
/// <c>jsrepository.json</c> is left untouched so GitHub updates stay drop-in.
/// </summary>
internal static class RetireJsExtractorOverlay
{
    public const long LargeScriptBytes = 80 * 1024;

    /// <summary>
    /// Live-DOM version probes for Bootstrap 3/4 jQuery plugins and the Bootstrap 4/5
    /// <c>bootstrap.*</c> namespace. Upstream Retire.js has no <c>func</c> extractors
    /// for Bootstrap (uri/filename/filecontent only).
    /// </summary>
    public static readonly IReadOnlyDictionary<string, string[]> ExtraFuncExtractors =
        new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
        {
            ["bootstrap"] =
            [
                "jQuery.fn.modal.Constructor.VERSION",
                "jQuery.fn.tooltip.Constructor.VERSION",
                "jQuery.fn.popover.Constructor.VERSION",
                "jQuery.fn.collapse.Constructor.VERSION",
                "jQuery.fn.carousel.Constructor.VERSION",
                "jQuery.fn.dropdown.Constructor.VERSION",
                "jQuery.fn.tab.Constructor.VERSION",
                "jQuery.fn.alert.Constructor.VERSION",
                "jQuery.fn.button.Constructor.VERSION",
                "jQuery.fn.affix.Constructor.VERSION",
                "jQuery.fn.scrollspy.Constructor.VERSION",
                "$.fn.modal.Constructor.VERSION",
                "$.fn.tooltip.Constructor.VERSION",
                "$.fn.popover.Constructor.VERSION",
                "$.fn.collapse.Constructor.VERSION",
                "$.fn.carousel.Constructor.VERSION",
                "$.fn.dropdown.Constructor.VERSION",
                "bootstrap.Modal.VERSION",
                "bootstrap.Tooltip.VERSION",
                "bootstrap.Popover.VERSION",
                "bootstrap.Collapse.VERSION",
                "bootstrap.Carousel.VERSION",
                "bootstrap.Dropdown.VERSION",
                "bootstrap.Tab.VERSION",
                "bootstrap.Alert.VERSION",
                "bootstrap.Offcanvas.VERSION"
            ]
        };

    /// <summary>
    /// Bundle-resilient content patterns. Upstream filecontent mainly matches the
    /// license banner or a specific Bootstrap 3 minified close() body, both of which
    /// webpack/terser rewrites can destroy. These look for VERSION next to a
    /// distinctive Bootstrap plugin token.
    /// </summary>
    public static readonly IReadOnlyDictionary<string, string[]> ExtraFileContentExtractors =
        new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
        {
            ["bootstrap"] =
            [
                @"bs\.(?:modal|tooltip|popover|collapse|carousel|dropdown|affix|tab|alert|button|scrollspy)[\s\S]{0,240}VERSION[""']?\s*[:=]\s*[""'](§§version§§)",
                @"\.fn\.(?:modal|tooltip|popover|collapse|carousel|dropdown|affix)[\s\S]{0,400}VERSION[""']?\s*[:=]\s*[""'](§§version§§)",
                @"(?:bootstrap|Bootstrap)\.(?:Modal|Tooltip|Collapse)\.VERSION\s*=\s*[""'](§§version§§)"
            ]
        };

    private static readonly Regex BundledName = new(
        @"bundle|chunk|vendor|webpack|runtime",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex AppShellName = new(
        @"^(app|main|index)(\.[\w.-]+)*\.js$",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public static bool LooksBundled(string? url, long encodedBodySize = 0)
    {
        if (encodedBodySize >= LargeScriptBytes)
            return true;

        var name = FileName(url);
        if (name.Length == 0)
            return false;

        return BundledName.IsMatch(name) || AppShellName.IsMatch(name);
    }

    public static IReadOnlyList<string> BuildCaveats(
        IReadOnlyList<ScriptInventoryEntry> scripts,
        int detectedLibraryCount)
    {
        if (scripts.Count == 0)
            return [];

        var bundled = scripts.Where(s => LooksBundled(s.Url, s.EncodedBodySize)).ToList();
        var fewScripts = scripts.Count <= 4;
        var anyLarge = scripts.Any(s => s.EncodedBodySize >= LargeScriptBytes);

        if (bundled.Count == 0 && !anyLarge)
            return [];

        var caveats = new List<string>();
        if (fewScripts || bundled.Count > 0 || anyLarge)
        {
            caveats.Add(
                "This page loads few large or bundled JS files. Libraries concatenated into those " +
                "files may be missed if they expose no runtime version API and have no distinctive " +
                "source banner. Treat a clean Retire.js result as incomplete; confirm with " +
                "POST /api/security/supply-chain-scan or a standalone retire.js run.");
        }

        if (detectedLibraryCount == 0)
        {
            caveats.Add(
                "No JavaScript libraries were identified despite bundled script(s). This is a strong " +
                "signal that versions are hidden inside the bundle — do not trust a clean result at face value.");
        }

        return caveats;
    }

    public static string FileName(string? url)
    {
        if (string.IsNullOrEmpty(url))
            return "";

        var path = url;
        var q = path.IndexOfAny(['?', '#']);
        if (q >= 0)
            path = path[..q];

        var slash = path.LastIndexOf('/');
        return slash >= 0 ? path[(slash + 1)..] : path;
    }
}

internal readonly record struct ScriptInventoryEntry(string Url, long EncodedBodySize);
