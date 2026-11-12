using Trowser.Automation;
using Xunit;

namespace Trowser.Tests.Automation;

public class ExecuteJsScriptPrepTests
{
    [Fact]
    public void Prepare_MultiStatementAwait_UsesAsyncIife()
    {
        var script = "const x=await Promise.resolve(7);JSON.stringify({x})";
        var prepared = ExecuteJsScriptPrep.Prepare(script);
        Assert.StartsWith("(async function(){", prepared, StringComparison.Ordinal);
        Assert.EndsWith("})()", prepared, StringComparison.Ordinal);
        Assert.Contains("await Promise.resolve(7)", prepared, StringComparison.Ordinal);
    }

    [Fact]
    public void Prepare_SingleExpressionPromise_NoWrapper()
    {
        var script = "Promise.resolve(7)";
        var prepared = ExecuteJsScriptPrep.Prepare(script);
        Assert.Equal(script, prepared);
    }

    [Fact]
    public void UsesAwait_DetectsKeywordOutsideStrings()
    {
        Assert.True(ExecuteJsScriptPrep.UsesAwait("const x = await foo();"));
        Assert.False(ExecuteJsScriptPrep.UsesAwait("'await not a keyword'"));
    }

    [Fact]
    public void Prepare_SetAttributeCallStatement_WrapsWithoutSemicolonInsideReturnParens()
    {
        var script = "document.getElementById('lnk').setAttribute('href', '/still-stale');";
        var prepared = ExecuteJsScriptPrep.Prepare(script);
        Assert.StartsWith("(function(){", prepared, StringComparison.Ordinal);
        Assert.DoesNotContain("still-stale'););", prepared, StringComparison.Ordinal);
    }
}
