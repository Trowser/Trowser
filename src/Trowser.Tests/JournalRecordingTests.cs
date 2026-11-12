using Trowser.Recording;
using Trowser.SessionLog;
using Xunit;

namespace Trowser.Tests;

public class JournalRecordingTests
{
    [Fact]
    public void LogRecording_embeds_csx_when_forced()
    {
        var logger = new SessionLogger();
        logger.Settings.LogRecordings = false; // would block non-forced

        var entry = logger.LogRecording("Login flow", ["Type email", "Click Sign in"],
            url: "https://example.com/login",
            csx: "await Click(ByRole(\"button\", \"Sign in\"));\n",
            csxPath: @"C:\tmp\login.csx",
            forceJournal: true);

        Assert.NotNull(entry);
        Assert.Equal("recording", entry!.Type);
        Assert.Equal("Login flow", entry.Summary);
        Assert.Equal("https://example.com/login", entry.Url);
        Assert.NotNull(entry.Fields);
        Assert.Contains("await Click", entry.Fields!["csx"]);
        Assert.Equal(@"C:\tmp\login.csx", entry.Fields["csxPath"]);
        Assert.Contains("Type email", entry.Fields["steps"]);
    }

    [Fact]
    public void LogRecording_respects_setting_when_not_forced()
    {
        var logger = new SessionLogger();
        logger.Settings.LogRecordings = false;

        var entry = logger.LogRecording("Nope", ["step"], forceJournal: false);
        Assert.Null(entry);
    }

    [Fact]
    public void CanShowMe_true_for_csx_only_entry()
    {
        var e = new SessionLogger.JournalEntry
        {
            Type = "recording",
            Summary = "Recording",
            Fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["csx"] = "await Navigate(\"https://example.com\");"
            }
        };
        Assert.True(JournalReportGenerator.CanShowMe(e));
    }

    [Fact]
    public void CanShowMe_true_for_csxPath_only_entry()
    {
        var e = new SessionLogger.JournalEntry
        {
            Type = "recording",
            Fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["csxPath"] = @"C:\tmp\x.csx"
            }
        };
        Assert.True(JournalReportGenerator.CanShowMe(e));
    }

    [Fact]
    public void SuggestFileBaseName_slugs_description()
    {
        var name = RecordingStopResult.SuggestFileBaseName("Login to admin!", DateTime.Now);
        Assert.Equal("Login-to-admin", name);
    }
}
