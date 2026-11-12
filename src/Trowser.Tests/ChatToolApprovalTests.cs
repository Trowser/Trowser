using System.Text.Json;
using Trowser.Chat;
using Xunit;

namespace Trowser.Tests;

public class ChatToolApprovalTests
{
    [Fact]
    public void IsNameOnlyReason_matches_by_name_list()
    {
        var reason = ChatToolApproval.RequiresConfirmation("browser_execute_js", default)!;
        Assert.True(ChatToolApproval.IsNameOnlyReason("browser_execute_js", reason));
    }

    [Fact]
    public void IsNameOnlyReason_false_for_path_arguments()
    {
        using var doc = JsonDocument.Parse("""{"path":"C:\\\\secrets.txt"}""");
        var reason = ChatToolApproval.RequiresConfirmation("browser_journal_export", doc.RootElement)!;
        Assert.False(ChatToolApproval.IsNameOnlyReason("browser_journal_export", reason));
        Assert.Contains("local path", reason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void IsNameOnlyReason_false_for_active_safety_mode()
    {
        using var doc = JsonDocument.Parse("""{"safetyMode":"active"}""");
        var reason = ChatToolApproval.RequiresConfirmation("browser_security_scan", doc.RootElement)!;
        Assert.False(ChatToolApproval.IsNameOnlyReason("browser_security_scan", reason));
        Assert.True(ChatToolApproval.TryParseSafetyModeReason(reason, out var mode));
        Assert.Equal("active", mode);
    }

    [Fact]
    public void TryParseSafetyModeReason_rejects_other_reasons()
    {
        Assert.False(ChatToolApproval.TryParseSafetyModeReason("runs C# inside Trowser", out _));
    }

    [Fact]
    public void benign_tools_do_not_require_confirmation()
    {
        Assert.Null(ChatToolApproval.RequiresConfirmation("browser_snapshot", default));
        Assert.Null(ChatToolApproval.RequiresConfirmation("browser_click", default));
    }
}
