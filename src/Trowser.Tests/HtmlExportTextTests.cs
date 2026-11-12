using Xunit;

namespace Trowser.Tests;

public class HtmlExportTextTests
{
    [Fact]
    public void encode_strips_nul_and_html_encodes()
    {
        var encoded = HtmlExportText.Encode("before\u0000after<tag>");
        Assert.Equal(-1, encoded.IndexOf('\0'));
        Assert.Contains('\uFFFD', encoded);
        Assert.Contains("&lt;tag&gt;", encoded);
    }

    [Fact]
    public void prepare_document_removes_embedded_nul()
    {
        const string html = "<div>ok</div>\0<truncated>";
        var prepared = HtmlExportText.PrepareDocument(html);
        Assert.Equal("<div>ok</div>\uFFFD<truncated>", prepared);
    }

    [Fact]
    public void encode_preserves_newlines_for_break_replacement()
    {
        Assert.Equal("a\nb", HtmlExportText.Encode("a\nb"));
    }
}
