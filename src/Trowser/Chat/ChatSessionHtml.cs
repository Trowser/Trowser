using System.Net;
using System.Text;
using Trowser.Decisions;

namespace Trowser.Chat;

internal enum ChatTranscriptKind
{
    User,
    Assistant,
    Tool,
    ToolError,
    Decision,
    Error,
    Compact
}

/// <summary>
/// One thing the tester saw in the AI Assistant. HTML export walks this list so the
/// saved page matches the panel, including tool rows and decision cards.
/// </summary>
internal sealed class ChatTranscriptItem
{
    public ChatTranscriptKind Kind { get; init; }
    public string Text { get; init; } = "";
    public DateTime Timestamp { get; init; } = DateTime.Now;
    public Decision? Decision { get; init; }
    public string? CompactSummary { get; init; }

    public static ChatTranscriptItem User(string text) =>
        new() { Kind = ChatTranscriptKind.User, Text = text };

    public static ChatTranscriptItem Assistant(string markdown) =>
        new() { Kind = ChatTranscriptKind.Assistant, Text = markdown };

    public static ChatTranscriptItem Tool(string toolName) =>
        new() { Kind = ChatTranscriptKind.Tool, Text = toolName };

    public static ChatTranscriptItem ToolError(string snippet) =>
        new() { Kind = ChatTranscriptKind.ToolError, Text = snippet };

    public static ChatTranscriptItem FromDecision(Decision decision) =>
        new() { Kind = ChatTranscriptKind.Decision, Decision = decision };

    public static ChatTranscriptItem Error(string message) =>
        new() { Kind = ChatTranscriptKind.Error, Text = message };

    public static ChatTranscriptItem Compact(string text, string? summary) =>
        new() { Kind = ChatTranscriptKind.Compact, Text = text, CompactSummary = summary };
}

/// <summary>
/// Builds the "Show as HTML" document from the visible chat transcript.
/// </summary>
internal static class ChatSessionHtml
{
    public static string Generate(IReadOnlyList<ChatTranscriptItem> items, string? model, DateTime generatedAt)
    {
        var body = new StringBuilder();
        foreach (var item in items)
            AppendItem(body, item);

        var timestamp = generatedAt.ToString("yyyy-MM-dd HH:mm:ss");
        var modelLine = string.IsNullOrEmpty(model) ? "" : $"Model: {HtmlExportText.Encode(model)}<br>";

        return "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n" +
            "<title>Trowser \u2014 AI Assistant Session</title>\n<style>\n" +
            "* { margin: 0; padding: 0; box-sizing: border-box; }\n" +
            "body { font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; background: #ffffff; color: #333; }\n" +
            ".page { max-width: 840px; margin: 0 auto; padding: 40px 32px 60px; }\n" +
            ".header { border-bottom: 3px solid #007ACC; padding-bottom: 16px; margin-bottom: 28px; }\n" +
            ".header h1 { font-size: 26px; font-weight: 600; color: #1a1a1a; margin-bottom: 6px; }\n" +
            ".header .meta { font-size: 13px; color: #666; line-height: 1.5; }\n" +
            ".message { margin-bottom: 16px; padding: 14px 18px; border-radius: 8px; }\n" +
            ".message-user { background: #e8f0fe; border-left: 4px solid #1a73e8; }\n" +
            ".message-assistant { background: #f8f9fa; border-left: 4px solid #5f6368; }\n" +
            ".message-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }\n" +
            ".message-role { font-size: 12px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; }\n" +
            ".message-user .message-role { color: #1a73e8; }\n" +
            ".message-assistant .message-role { color: #5f6368; }\n" +
            ".message-time { font-size: 11px; color: #999; }\n" +
            ".message-content { font-size: 14px; line-height: 1.65; word-wrap: break-word; overflow-wrap: break-word; }\n" +
            ".message-user .message-content { white-space: pre-wrap; }\n" +
            ".message-content h1 { font-size: 1.45em; font-weight: 650; margin: 0.7em 0 0.35em; color: #1a1a1a; }\n" +
            ".message-content h2 { font-size: 1.25em; font-weight: 650; margin: 0.65em 0 0.3em; color: #1a1a1a; }\n" +
            ".message-content h3, .message-content h4 { font-size: 1.1em; font-weight: 600; margin: 0.55em 0 0.25em; color: #222; }\n" +
            ".message-content h1:first-child, .message-content h2:first-child, .message-content h3:first-child { margin-top: 0; }\n" +
            ".message-content p { margin: 0.45em 0; }\n" +
            ".message-content ul, .message-content ol { margin: 0.45em 0; padding-left: 1.5em; }\n" +
            ".message-content li { margin: 0.2em 0; }\n" +
            ".message-content li > p { margin: 0.15em 0; }\n" +
            ".message-content blockquote { margin: 0.5em 0; padding: 0.25em 0 0.25em 12px; border-left: 3px solid #c5c5c5; color: #555; }\n" +
            ".message-content hr { border: none; border-top: 1px solid #ddd; margin: 1em 0; }\n" +
            ".message-content a { color: #1a73e8; }\n" +
            ".message-content code { font-family: 'Cascadia Code', Consolas, 'Courier New', monospace; font-size: 0.9em; background: #eceff1; padding: 0.1em 0.35em; border-radius: 3px; }\n" +
            ".message-content pre { background: #1e1e1e; color: #d4d4d4; padding: 12px 14px; border-radius: 6px; overflow-x: auto; margin: 0.6em 0; }\n" +
            ".message-content pre code { background: transparent; padding: 0; color: inherit; font-size: 12.5px; line-height: 1.5; }\n" +
            ".message-content table { border-collapse: collapse; width: 100%; margin: 0.6em 0; font-size: 13px; }\n" +
            ".message-content th, .message-content td { border: 1px solid #ddd; padding: 6px 10px; text-align: left; }\n" +
            ".message-content th { background: #eef1f4; font-weight: 600; }\n" +
            ".message-content tr:nth-child(even) td { background: #fafbfc; }\n" +
            ".tool { font-family: 'Cascadia Code', Consolas, 'Courier New', monospace; font-size: 12px; color: #666; margin: 6px 10px 2px; }\n" +
            ".tool-icon { color: #00796B; margin-right: 6px; }\n" +
            ".tool-error { font-size: 12px; color: #B71C1C; margin: 0 10px 8px 28px; }\n" +
            ".tool + .message, .tool-error + .message,\n" +
            ".tool + .decision, .tool-error + .decision,\n" +
            ".tool + .error, .tool-error + .error,\n" +
            ".tool + .compact, .tool-error + .compact { margin-top: 20px; }\n" +
            ".error { margin-bottom: 16px; padding: 12px 18px; border-radius: 8px; background: #fdecea; border-left: 4px solid #c5221f; color: #b71c1c; font-size: 13px; }\n" +
            ".compact { margin: 12px 16px; padding: 10px 14px; border-radius: 8px; background: #fff8e1; border: 1px solid #e6d48a; font-size: 12px; color: #5d4e00; }\n" +
            ".compact-summary { margin-top: 4px; color: #7a6a20; }\n" +
            ".decision { margin-bottom: 16px; padding: 14px 18px; border-radius: 2px 8px 8px 2px; background: #f8f9fa; }\n" +
            ".decision-gate { border-left: 4px solid #e65100; }\n" +
            ".decision-steer { border-left: 4px solid #1565c0; }\n" +
            ".decision-review { border-left: 4px solid #757575; }\n" +
            ".decision-lane { font-size: 11px; font-weight: 700; letter-spacing: 0.5px; margin-bottom: 8px; }\n" +
            ".decision-gate .decision-lane { color: #e65100; }\n" +
            ".decision-steer .decision-lane { color: #1565c0; }\n" +
            ".decision-review .decision-lane { color: #757575; }\n" +
            ".decision-question { font-size: 14px; line-height: 1.5; margin-bottom: 10px; color: #222; }\n" +
            ".decision-pointers { font-size: 12px; color: #666; margin-bottom: 10px; }\n" +
            ".decision-option { background: #fff; border: 1px solid #e0e0e0; border-radius: 6px; padding: 8px 12px; margin: 4px 0; font-size: 13px; }\n" +
            ".decision-option .key { font-weight: 700; color: #1565c0; margin-right: 8px; }\n" +
            ".decision-option.recommended .key { color: #00796B; }\n" +
            ".decision-option .rec { font-size: 11px; color: #888; margin-left: 8px; }\n" +
            ".decision-option .detail { font-size: 12px; color: #666; margin-top: 2px; }\n" +
            ".decision-footer { font-size: 12px; color: #666; margin-top: 10px; }\n" +
            ".decision-footer.answered { color: #00796B; }\n" +
            ".decision-footer.defaulted { color: #7B6800; }\n" +
            "@media print { .page { padding: 20px 0; } .message-content pre { white-space: pre-wrap; } }\n" +
            "</style>\n</head>\n<body>\n<div class=\"page\">\n" +
            "<div class=\"header\">\n<h1>Trowser \u2014 AI Assistant Session</h1>\n" +
            $"<div class=\"meta\">{modelLine}Generated: {timestamp}</div>\n</div>\n" +
            body +
            "</div>\n</body>\n</html>";
    }

    private static void AppendItem(StringBuilder body, ChatTranscriptItem item)
    {
        switch (item.Kind)
        {
            case ChatTranscriptKind.User:
                AppendMessage(body, "user", "You", item.Timestamp, EncodedBreaks(item.Text));
                break;
            case ChatTranscriptKind.Assistant:
                AppendMessage(body, "assistant", "AI Assistant", item.Timestamp, MarkdownHelper.ToHtml(item.Text));
                break;
            case ChatTranscriptKind.Tool:
                body.Append("<div class=\"tool\"><span class=\"tool-icon\">\u2699</span>")
                    .Append(HtmlExportText.Encode(FormatToolName(item.Text)))
                    .Append("</div>\n");
                break;
            case ChatTranscriptKind.ToolError:
                body.Append("<div class=\"tool-error\">")
                    .Append(HtmlExportText.Encode(item.Text))
                    .Append("</div>\n");
                break;
            case ChatTranscriptKind.Error:
                body.Append("<div class=\"error\">\u26A0 ")
                    .Append(HtmlExportText.Encode(item.Text))
                    .Append("</div>\n");
                break;
            case ChatTranscriptKind.Compact:
                body.Append("<div class=\"compact\"><div>")
                    .Append(HtmlExportText.Encode(item.Text))
                    .Append("</div>");
                if (!string.IsNullOrWhiteSpace(item.CompactSummary))
                {
                    body.Append("<div class=\"compact-summary\">")
                        .Append(HtmlExportText.Encode(item.CompactSummary))
                        .Append("</div>");
                }
                body.Append("</div>\n");
                break;
            case ChatTranscriptKind.Decision when item.Decision != null:
                AppendDecision(body, item.Decision);
                break;
        }
    }

    private static void AppendMessage(StringBuilder body, string roleClass, string roleLabel, DateTime time, string content)
    {
        body.Append("<div class=\"message message-").Append(roleClass).Append("\">")
            .Append("<div class=\"message-header\">")
            .Append("<span class=\"message-role\">").Append(roleLabel).Append("</span>")
            .Append("<span class=\"message-time\">").Append(time.ToString("HH:mm:ss")).Append("</span>")
            .Append("</div>")
            .Append("<div class=\"message-content\">").Append(content).Append("</div>")
            .Append("</div>\n");
    }

    private static void AppendDecision(StringBuilder body, Decision decision)
    {
        var laneClass = DecisionCardCopy.LaneCssClass(decision.Lane);
        body.Append("<div class=\"decision decision-").Append(laneClass).Append("\">")
            .Append("<div class=\"decision-lane\">")
            .Append(HtmlExportText.Encode(DecisionCardCopy.LaneHeader(decision)))
            .Append("</div>")
            .Append("<div class=\"decision-question\">")
            .Append(HtmlExportText.Encode(decision.Question).Replace("\n", "<br>"))
            .Append("</div>");

        var pointers = DecisionCardCopy.PointerLine(decision);
        if (!string.IsNullOrEmpty(pointers))
        {
            body.Append("<div class=\"decision-pointers\">")
                .Append(HtmlExportText.Encode(pointers))
                .Append("</div>");
        }

        foreach (var option in decision.Options)
        {
            var recommended = string.Equals(option.Key, decision.Recommendation, StringComparison.OrdinalIgnoreCase);
            body.Append("<div class=\"decision-option");
            if (recommended) body.Append(" recommended");
            body.Append("\"><span class=\"key\">")
                .Append(HtmlExportText.Encode(option.Key))
                .Append("</span>")
                .Append(HtmlExportText.Encode(option.Label));
            if (recommended)
                body.Append("<span class=\"rec\">recommended</span>");
            if (!string.IsNullOrWhiteSpace(option.Detail))
            {
                body.Append("<div class=\"detail\">")
                    .Append(HtmlExportText.Encode(option.Detail))
                    .Append("</div>");
            }
            body.Append("</div>");
        }

        if (decision.AllowOther)
        {
            var otherKey = decision.OtherKey ?? DecisionOption.KeyAt(decision.Options.Count);
            body.Append("<div class=\"decision-option\"><span class=\"key\">")
                .Append(HtmlExportText.Encode(otherKey))
                .Append("</span>Other\u2026</div>");
        }

        var footerKind = DecisionCardCopy.FooterKind(decision);
        body.Append("<div class=\"decision-footer ").Append(footerKind).Append("\">")
            .Append(HtmlExportText.Encode(DecisionCardCopy.Footer(decision)))
            .Append("</div></div>\n");
    }

    internal static string FormatToolName(string toolName) =>
        toolName.Replace("browser_", "").Replace("_", " ");

    private static string EncodedBreaks(string text) =>
        HtmlExportText.Encode(text).Replace("\n", "<br>");
}
