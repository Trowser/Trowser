using Trowser.Security;
using Xunit;

namespace Trowser.Tests.Security;

public class PostMessageOriginGraderTests
{
    [Fact]
    public void Strict_literal_origin_compare()
    {
        var src = "if (e.origin !== 'https://trusted.example') return;";
        var g = PostMessageOriginGrader.Analyze(src);
        Assert.Equal("strict", g.Grade);
        Assert.Equal("literal-origin-compare", g.CheckKind);
    }

    [Fact]
    public void Weak_indexOf_not_strict()
    {
        var src = "if (e.origin.indexOf('example') >= 0) { div.innerHTML = e.data; }";
        var g = PostMessageOriginGrader.Analyze(src);
        Assert.Equal("weak", g.Grade);
    }

    [Fact]
    public void Unrelated_equality_not_strict_without_origin()
    {
        var src = "if (x === 1 && y == 2) { doWork(e.data); }";
        var g = PostMessageOriginGrader.Analyze(src);
        Assert.Equal("none", g.Grade);
    }

    [Fact]
    public void Opaque_minified_zone_wrapper_is_unknown()
    {
        var src = "function(p){return H(this,p,!0)}";
        var g = PostMessageOriginGrader.Analyze(src);
        Assert.Equal("unknown", g.Grade);
        Assert.Equal("opaque-minified", g.CheckKind);
    }

    [Fact]
    public void Message_source_ref_is_strict_not_none()
    {
        var src = "({source:i,data:o})=>{i===li&&o===r&&n.length&&n.shift()()}";
        var g = PostMessageOriginGrader.Analyze(src);
        Assert.Equal("strict", g.Grade);
        Assert.Equal("message-source-ref", g.CheckKind);
    }

    [Fact]
    public void Origin_only_logged_or_forwarded_is_none_not_weak()
    {
        var src = """
                  function (event) {
                    if (!event.data || event.data.type !== "configure") return;
                    if (typeof event.data.code !== "string") return;
                    triggerCanary(undefined, event.origin);
                    try { eval(event.data.code); } catch (e) { console.error(e); }
                  }
                  """;
        var g = PostMessageOriginGrader.Analyze(src);
        Assert.Equal("none", g.Grade);
        Assert.NotEqual("weak", g.Grade);
        Assert.NotEqual("origin-mentioned-unclassified", g.CheckKind);
    }

    [Fact]
    public void Hostname_only_check_is_weak_not_strict()
    {
        var src = """
                  function isTrusted(origin) {
                    var u = new URL(origin);
                    return u.hostname === "localhost" || u.hostname === "127.0.0.1";
                  }
                  window.addEventListener("message", function(e) {
                    if (!isTrusted(e.origin)) return;
                    eval(e.data.code);
                  });
                  """;
        var g = PostMessageOriginGrader.Analyze(src);
        Assert.Equal("weak", g.Grade);
        Assert.True(g.CheckKind is "hostname-only" or "delegated-origin-fn");
    }

    [Fact]
    public void InferMessageSchema_keeps_type_literal()
    {
        var src = "if (data.type === 'resize') { el.innerHTML = data.html; }";
        var schema = PostMessagePayloadInference.InferMessageSchema(src);
        Assert.Equal("resize", schema.TypeLiteral);
        Assert.Contains("html", schema.HtmlKeys, StringComparer.OrdinalIgnoreCase);
    }
}
