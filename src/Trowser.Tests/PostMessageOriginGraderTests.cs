using Trowser.Automation;
using Trowser.Security;
using Xunit;

namespace Trowser.Tests;

public sealed class PostMessageOriginGraderTests
{
    [Fact]
    public void Opaque_zone_wrapper_grades_unknown_not_none()
    {
        var grade = PostMessageOriginGrader.Analyze("function(p){return H(this,p,!0)}");
        Assert.Equal("unknown", grade.Grade);
        Assert.Equal("opaque-minified", grade.CheckKind);
    }

    [Fact]
    public void Message_source_destructure_grades_strict()
    {
        var src = "({source,data})=>{if(source!==window)return;}";
        var grade = PostMessageOriginGrader.Analyze(src);
        Assert.Equal("strict", grade.Grade);
        Assert.Equal("message-source-ref", grade.CheckKind);
    }

    [Fact]
    public void Literal_origin_compare_grades_strict()
    {
        var src = "function(e){ if (e.origin !== 'https://trusted.example') return; }";
        var grade = PostMessageOriginGrader.Analyze(src);
        Assert.Equal("strict", grade.Grade);
        Assert.Equal("literal-origin-compare", grade.CheckKind);
    }

    [Fact]
    public void Data_type_gate_grades_data_gate_only()
    {
        var src = """
            function(e) {
              if (e.data && e.data.type === 'resize') {
                document.getElementById('out').innerHTML = e.data.html;
              }
            }
            """;
        var grade = PostMessageOriginGrader.Analyze(src);
        Assert.Equal("none", grade.Grade);
        Assert.Equal("data-gate-only", grade.CheckKind);
    }

    [Fact]
    public void No_origin_logic_grades_none()
    {
        var src = """
            function(e) {
              var node = document.getElementById('x');
              if (node) node.innerHTML = e.data;
            }
            """;
        var grade = PostMessageOriginGrader.Analyze(src);
        Assert.Equal("none", grade.Grade);
    }

    [Fact]
    public void Framing_document_ignores_later_same_origin_assets()
    {
        var page = "https://app.example/#/";
        var entries = new[]
        {
            new NetworkEntry
            {
                Url = "https://app.example/",
                ResourceType = "Document",
                ResponseHeaders = new Dictionary<string, string> { ["X-Frame-Options"] = "SAMEORIGIN" }
            },
            new NetworkEntry
            {
                Url = "https://app.example/main.js",
                ResourceType = "Script"
            }
        };

        var selected = PostMessageAuditor.SelectDocumentForFraming(entries, page);
        Assert.NotNull(selected);
        Assert.Equal("Document", selected.ResourceType);
        Assert.Equal("SAMEORIGIN", selected.ResponseHeaders["X-Frame-Options"]);
    }
}
