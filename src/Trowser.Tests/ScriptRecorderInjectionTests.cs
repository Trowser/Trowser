using System.IO;
using System.Text.Json;
using Trowser.Recording;
using Xunit;

namespace Trowser.Tests;

/// <summary>
/// Recorded fields come from the page under test. They must never be able to end a
/// <c>//</c> comment or a string literal in the generated .csx.
/// </summary>
public class ScriptRecorderInjectionTests
{
    private static readonly string[] LineBreaks = ["\n", "\r", "\u0085", "\u2028", "\u2029"];

    [Fact]
    public void Sanitize_removes_every_csharp_line_terminator()
    {
        foreach (var br in LineBreaks)
        {
            var s = ScriptRecorder.Sanitize("a" + br + "File.Delete(x);//");
            Assert.DoesNotContain(br, s);
        }
    }

    [Fact]
    public void Escape_never_emits_raw_line_terminators()
    {
        foreach (var br in LineBreaks)
        {
            var lit = ScriptRecorder.Escape("x" + br + "\"); Evil(); (\"");
            Assert.DoesNotContain(br, lit);
            Assert.StartsWith("\"", lit);
            Assert.EndsWith("\"", lit);
        }
    }

    [Fact]
    public void Forged_radio_label_stays_inside_comment()
    {
        var path = Path.Combine(Path.GetTempPath(), $"rec-test-{Guid.NewGuid():N}.csx");
        var rec = new ScriptRecorder();
        try
        {
            rec.Start(path, "https://example.test/");
            using var doc = JsonDocument.Parse(
                "{\"type\":\"radio\",\"radioIndex\":0,\"radioValue\":\"v\\u2028Pwn();\",\"groupLabel\":\"g\\nPwn();//\"}");
            rec.RecordAction(doc.RootElement);
            var result = rec.Stop();
            Assert.NotNull(result);

            foreach (var line in result!.Script.Split('\n'))
            {
                if (line.Contains("Pwn();"))
                    Assert.StartsWith("//", line.TrimStart());
            }
            Assert.DoesNotContain("\u2028", result.Script);
            result.DeleteTempFiles();
        }
        finally
        {
            if (File.Exists(path)) File.Delete(path);
        }
    }
}
