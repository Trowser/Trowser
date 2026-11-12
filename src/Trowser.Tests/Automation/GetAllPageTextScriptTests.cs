using System.Reflection;
using Trowser.Automation;
using Xunit;

namespace Trowser.Tests.Automation;

public class GetAllPageTextScriptTests
{
    [Fact]
    public void GetAllPageText_walks_document_fragment_shadow_roots()
    {
        var method = typeof(AutomationContext).GetMethod(
            "GetAllPageText",
            BindingFlags.Public | BindingFlags.Instance);
        Assert.NotNull(method);

        // Source lives in AutomationContext.Interaction.cs partial; assert the JS handles shadow roots (DocumentFragment nodeType 11).
        var interactionPath = Path.Combine(
            FindRepoRoot(),
            "src", "Trowser", "Automation", "AutomationContext.Interaction.cs");
        var source = File.ReadAllText(interactionPath);
        Assert.Contains("node.nodeType === 11", source, StringComparison.Ordinal);
        Assert.Contains("if (node.shadowRoot) walk(node.shadowRoot)", source, StringComparison.Ordinal);
    }

    private static string FindRepoRoot()
    {
        var dir = AppContext.BaseDirectory;
        while (dir != null)
        {
            if (File.Exists(Path.Combine(dir, "Trowser.sln")))
                return dir;
            dir = Directory.GetParent(dir)?.FullName;
        }

        throw new InvalidOperationException("Could not locate repository root.");
    }
}
