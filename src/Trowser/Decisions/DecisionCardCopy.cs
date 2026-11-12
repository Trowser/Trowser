using System.Text;

namespace Trowser.Decisions;

/// <summary>
/// Shared labels for the decision card in the AI Assistant and in "Show as HTML",
/// so the saved page cannot drift from what the tester saw.
/// </summary>
internal static class DecisionCardCopy
{
    public static string LaneLabel(string lane) => lane switch
    {
        DecisionLanes.Gate => "Waiting on you",
        DecisionLanes.Review => "For the record",
        _ => "Steering — answer if you disagree"
    };

    public static string LaneHeader(Decision decision)
    {
        var header = LaneLabel(decision.Lane);
        if (decision.Urgency == DecisionUrgencies.High)
            header += "  \u2022  urgent";
        return header.ToUpperInvariant();
    }

    public static string LaneCssClass(string lane) => DecisionLanes.Normalize(lane) switch
    {
        DecisionLanes.Gate => "gate",
        DecisionLanes.Review => "review",
        _ => "steer"
    };

    public static string PointerLine(Decision decision) =>
        decision.PointerIds is { Count: > 0 }
            ? $"\U0001F4CD About {string.Join(", ", decision.PointerIds)} — Ctrl+Shift+P to see the pointers"
            : "";

    /// <summary>Plain text for clipboard copy — kept in sync with the decision card UI and HTML export.</summary>
    public static string PlainText(Decision decision)
    {
        var sb = new StringBuilder();
        sb.AppendLine(LaneHeader(decision));
        sb.AppendLine(decision.Question);

        var pointers = PointerLine(decision);
        if (!string.IsNullOrEmpty(pointers))
            sb.AppendLine(pointers);

        sb.AppendLine();

        foreach (var option in decision.Options)
        {
            var recommended = string.Equals(option.Key, decision.Recommendation, StringComparison.OrdinalIgnoreCase);
            sb.Append(option.Key).Append("  ").Append(option.Label);
            if (recommended)
                sb.Append("   recommended");
            sb.AppendLine();
            if (!string.IsNullOrWhiteSpace(option.Detail))
                sb.AppendLine(option.Detail);
        }

        if (decision.AllowOther)
        {
            var otherKey = decision.OtherKey ?? DecisionOption.KeyAt(decision.Options.Count);
            sb.Append(otherKey).Append("  Other…").AppendLine();
        }

        sb.AppendLine();
        sb.Append(Footer(decision));
        return sb.ToString().TrimEnd();
    }

    public static string Footer(Decision decision)
    {
        if (decision.Status == DecisionStatuses.Pending)
            return PendingFooter(decision);

        var (icon, text) = Verdict(decision);
        if (decision.IsOtherAnswer || string.IsNullOrWhiteSpace(decision.AnswerNote) ||
            decision.AnswerNote == decision.AnswerLabel)
            return $"{icon} {text}";
        return $"{icon} {text}  \u2014  \"{decision.AnswerNote}\"";
    }

    public static string FooterKind(Decision decision) => decision.Status switch
    {
        DecisionStatuses.Pending => "pending",
        DecisionStatuses.Answered => "answered",
        DecisionStatuses.Defaulted or DecisionStatuses.Expired => "defaulted",
        _ => "muted"
    };

    public static (string Icon, string Text) Verdict(Decision decision)
    {
        string? answerText;
        if (decision.IsOtherAnswer)
            answerText = $"{decision.OtherKey}) Other: {decision.AnswerLabel}";
        else
        {
            var answer = decision.FindOption(decision.AnswerKey);
            answerText = answer == null ? null : $"{answer.Key}) {answer.Label}";
        }

        return decision.Status switch
        {
            DecisionStatuses.Answered when decision.AnsweredBy == DecisionAnswerers.Human =>
                ("\u2713", $"You chose {answerText}."),
            DecisionStatuses.Answered =>
                ("\u2713", $"Answered {answerText} by {decision.AnsweredBy}."),
            DecisionStatuses.Defaulted =>
                ("\u23F1", $"No answer — defaulted to {answerText}. The agent made this call, not you."),
            DecisionStatuses.Expired =>
                ("\u23F1", "No answer and no default — the agent carried on using its own judgement."),
            DecisionStatuses.Cancelled =>
                ("\u2014", "The agent withdrew this question."),
            _ => ("\u2014", decision.Status)
        };
    }

    private static string PendingFooter(Decision decision)
    {
        if (decision.Lane == DecisionLanes.Review)
            return "No answer needed — this is on the record either way.";

        var clock = DecisionCountdown.Format(DecisionCountdown.MilestoneFor(decision.SecondsRemaining));
        var fallback = decision.FindOption(decision.DefaultKey);
        return fallback == null
            ? $"{clock} — after that the agent carries on without an answer."
            : $"{clock} — then it defaults to {fallback.Key}) {fallback.Label}.";
    }
}
