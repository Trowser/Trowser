using Trowser.Chat;
using Xunit;

namespace Trowser.Tests;

public class MarkdownCopyTests
{
    [Fact]
    public void segment_at_paragraph_returns_that_paragraph()
    {
        const string md = "First paragraph.\n\nSecond paragraph.";
        Assert.Equal("First paragraph.", MarkdownHelper.GetSegmentAt(md, 3));
        Assert.Equal("Second paragraph.", MarkdownHelper.GetSegmentAt(md, 20));
    }

    [Fact]
    public void segment_inside_fence_returns_inner_code()
    {
        const string md = "Intro\n\n```csharp\nConsole.WriteLine(1);\n```\n\nOutro";
        var idx = md.IndexOf("Console", StringComparison.Ordinal);
        Assert.Equal("Console.WriteLine(1);", MarkdownHelper.GetSegmentAt(md, idx));
    }

    [Fact]
    public void segment_on_fence_marker_returns_inner_code()
    {
        const string md = "```js\nconst x = 1;\n```";
        Assert.Equal("const x = 1;", MarkdownHelper.GetSegmentAt(md, 0));
        Assert.Equal("const x = 1;", MarkdownHelper.GetSegmentAt(md, md.Length));
    }

    [Fact]
    public void segment_in_unclosed_fence_returns_code_so_far()
    {
        const string md = "```python\ndef foo():\n    return 1";
        var idx = md.IndexOf("return", StringComparison.Ordinal);
        Assert.Equal("def foo():\n    return 1", MarkdownHelper.GetSegmentAt(md, idx));
    }

    [Fact]
    public void split_keeps_growing_paragraph_in_remainder()
    {
        var (complete, remainder) = MarkdownHelper.SplitCompleteAndRemainder("Hello world");
        Assert.Equal("", complete);
        Assert.Equal("Hello world", remainder);
    }

    [Fact]
    public void split_promotes_paragraph_after_blank_line()
    {
        var (complete, remainder) = MarkdownHelper.SplitCompleteAndRemainder("First.\n\nSecond");
        Assert.Equal("First.\n\n", complete);
        Assert.Equal("Second", remainder);
    }

    [Fact]
    public void split_keeps_unclosed_fence_in_remainder()
    {
        const string md = "Here:\n\n```csharp\nConsole.Write(";
        var (complete, remainder) = MarkdownHelper.SplitCompleteAndRemainder(md);
        Assert.Equal("Here:\n\n", complete);
        Assert.StartsWith("```csharp", remainder);
    }

    [Fact]
    public void split_promotes_closed_fence_immediately()
    {
        const string md = "Here:\n\n```js\nconst x = 1;\n```";
        var (complete, remainder) = MarkdownHelper.SplitCompleteAndRemainder(md);
        Assert.Equal(md, complete);
        Assert.Equal("", remainder);
    }

    [Fact]
    public void split_promotes_closed_fence_and_leaves_following_prose()
    {
        const string md = "Here:\n\n```js\nconst x = 1;\n```\nMore text";
        var (complete, remainder) = MarkdownHelper.SplitCompleteAndRemainder(md);
        Assert.Contains("```js", complete);
        Assert.Contains("const x = 1;", complete);
        Assert.Equal("More text", remainder.TrimStart('\r', '\n'));
    }

    [Fact]
    public void split_treats_tilde_fences_like_backticks()
    {
        const string md = "~~~html\n<div/>\n~~~";
        var (complete, remainder) = MarkdownHelper.SplitCompleteAndRemainder(md);
        Assert.Equal(md, complete);
        Assert.Equal("", remainder);
        Assert.Equal("<div/>", MarkdownHelper.GetSegmentAt(md, 8));
    }
}
