using Trowser.Security;
using Xunit;

namespace Trowser.Tests;

public class RetireJsExtractorOverlayTests
{
    [Fact]
    public void bootstrap_func_extractors_cover_jquery_plugins_and_namespace()
    {
        var funcs = RetireJsExtractorOverlay.ExtraFuncExtractors["bootstrap"];
        Assert.Contains("jQuery.fn.modal.Constructor.VERSION", funcs);
        Assert.Contains("jQuery.fn.tooltip.Constructor.VERSION", funcs);
        Assert.Contains("$.fn.modal.Constructor.VERSION", funcs);
        Assert.Contains("bootstrap.Modal.VERSION", funcs);
        Assert.Contains("bootstrap.Tooltip.VERSION", funcs);
    }

    [Fact]
    public void bootstrap_filecontent_extractors_target_plugin_version_tokens()
    {
        var patterns = RetireJsExtractorOverlay.ExtraFileContentExtractors["bootstrap"];
        Assert.NotEmpty(patterns);
        Assert.All(patterns, p => Assert.Contains("§§version§§", p));
        Assert.Contains(patterns, p => p.Contains("modal", StringComparison.Ordinal) && p.Contains("VERSION"));
    }

    [Theory]
    [InlineData("https://app.example/js/app.bundle.min.js", 0, true)]
    [InlineData("https://app.example/static/vendor.js", 0, true)]
    [InlineData("https://app.example/assets/chunk-3a1f.js", 0, true)]
    [InlineData("https://app.example/js/main.js", 0, true)]
    [InlineData("https://cdn.example/jquery-3.6.0.min.js", 0, false)]
    [InlineData("https://cdn.example/jquery-3.6.0.min.js", 80 * 1024, true)]
    [InlineData("https://cdn.example/bootstrap.min.js", 1200, false)]
    public void looks_bundled_uses_name_and_size(string url, long size, bool expected)
    {
        Assert.Equal(expected, RetireJsExtractorOverlay.LooksBundled(url, size));
    }

    [Fact]
    public void caveats_when_few_bundled_scripts_even_if_libraries_found()
    {
        var scripts = new[]
        {
            new ScriptInventoryEntry("https://app.test/js/app.bundle.min.js", 12_000)
        };

        var caveats = RetireJsExtractorOverlay.BuildCaveats(scripts, detectedLibraryCount: 2);
        Assert.NotEmpty(caveats);
        Assert.Contains(caveats, c => c.Contains("bundled", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(caveats, c => c.Contains("No JavaScript libraries"));
    }

    [Fact]
    public void stronger_caveat_when_bundle_and_zero_libraries()
    {
        var scripts = new[]
        {
            new ScriptInventoryEntry("https://app.test/js/app.bundle.min.js", 12_000)
        };

        var caveats = RetireJsExtractorOverlay.BuildCaveats(scripts, detectedLibraryCount: 0);
        Assert.Equal(2, caveats.Count);
        Assert.Contains(caveats, c => c.Contains("do not trust a clean result", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void no_caveat_for_standalone_cdn_scripts()
    {
        var scripts = new[]
        {
            new ScriptInventoryEntry("https://cdn.test/jquery-3.6.0.min.js", 8_000),
            new ScriptInventoryEntry("https://cdn.test/bootstrap-3.4.1.min.js", 4_000)
        };

        Assert.Empty(RetireJsExtractorOverlay.BuildCaveats(scripts, detectedLibraryCount: 2));
    }
}
