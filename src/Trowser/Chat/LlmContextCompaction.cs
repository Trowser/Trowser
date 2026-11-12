using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Trowser.SessionLog;

namespace Trowser.Chat;

public sealed class SessionMetadata
{
    public string? Url { get; set; }
    public string? Title { get; set; }
    public int TabCount { get; set; }
    public string? SessionName { get; set; }
    public string? SafetyMode { get; set; }
}

public sealed class CompactAppliedInfo
{
    public int MessagesBefore { get; set; }
    public int MessagesAfter { get; set; }
    public int TokensBefore { get; set; }
    public int TokensAfter { get; set; }
    public string Summary { get; set; } = "";
    public bool Deterministic { get; set; }
}

/// <summary>
/// Rebuilds built-in chat history from journal + session memory instead of resending full tool dumps.
/// </summary>
public sealed class LlmContextCompaction
{
    private static readonly Regex PromptToolResultRegex = new(
        @"^\s*<tool_result\s+name=""[^""]+"">",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    private readonly SessionLogger? _sessionLogger;
    private readonly SessionMemory? _sessionMemory;
    private readonly Func<Task<SessionMetadata>>? _getSessionMetadata;
    private bool _warnNudgeSent;

    public event Action<CompactAppliedInfo>? CompactApplied;

    public LlmContextCompaction(
        SessionLogger? sessionLogger,
        SessionMemory? sessionMemory,
        Func<Task<SessionMetadata>>? getSessionMetadata)
    {
        _sessionLogger = sessionLogger;
        _sessionMemory = sessionMemory;
        _getSessionMetadata = getSessionMetadata;
    }

    public int EstimateConversationTokens(List<ChatMessage> conversation)
    {
        long chars = 0;
        foreach (var msg in conversation)
        {
            if (!string.IsNullOrEmpty(msg.Content))
                chars += msg.Content.Length;
            if (msg.ToolCalls != null)
            {
                foreach (var tc in msg.ToolCalls)
                {
                    chars += tc.Name.Length + tc.ArgumentsJson.Length + tc.Id.Length;
                }
            }
            if (!string.IsNullOrEmpty(msg.ToolName))
                chars += msg.ToolName.Length;
        }
        return (int)(chars / 4);
    }

    public void ResetWarnNudge() => _warnNudgeSent = false;

    public bool TryInjectWarnNudge(List<ChatMessage> conversation, LlmSettings settings)
    {
        if (!settings.AutoCompactEnabled || _warnNudgeSent) return false;
        var budget = settings.ContextBudgetTokens;
        if (budget <= 0) return false;
        var tokens = EstimateConversationTokens(conversation);
        var pct = tokens * 100 / budget;
        if (pct < settings.CompactWarnPercent) return false;

        _warnNudgeSent = true;
        conversation.Add(ChatMessage.System(
            $"Context is at {pct}% of budget (~{tokens:N0} / {budget:N0} tokens). " +
            "Finish the current test, journal findings with explicit evidence, then call browser_compact."));
        return true;
    }

    public async Task<bool> RequestDeterministicCompact(List<ChatMessage> conversation, LlmSettings settings, string reason)
    {
        if (_sessionMemory == null || _sessionLogger == null) return false;

        var summary = BuildDeterministicSummary(_sessionLogger);
        if (!string.IsNullOrWhiteSpace(reason))
            summary = reason + "\n" + summary;

        _sessionMemory.QueueCompact(new PendingCompactRequest
        {
            Summary = summary,
            OpenThreads = new List<string>(),
            NextSteps = _sessionMemory.Tasks
                .Where(t => t.Status is SessionTaskStatus.Open or SessionTaskStatus.Doing)
                .Select(t => t.Text)
                .Take(5)
                .ToList(),
            KeepLastTurns = settings.CompactKeepLastTurns,
            Deterministic = true
        });

        _sessionLogger.LogSystemNote(
            "Context compacted",
            reason,
            tags: new List<string> { "compact", "manual" });

        return await ApplyPendingCompact(conversation, settings).ConfigureAwait(false);
    }

    public async Task<bool> TryForceCompact(List<ChatMessage> conversation, LlmSettings settings)
    {
        if (!settings.AutoCompactEnabled || _sessionMemory == null || _sessionLogger == null)
            return false;

        var budget = settings.ContextBudgetTokens;
        if (budget <= 0) return false;
        var tokens = EstimateConversationTokens(conversation);
        var pct = tokens * 100 / budget;
        if (pct < settings.CompactForcePercent) return false;

        var summary = BuildDeterministicSummary(_sessionLogger);
        _sessionMemory.QueueCompact(new PendingCompactRequest
        {
            Summary = summary,
            OpenThreads = new List<string>(),
            NextSteps = _sessionMemory.Tasks
                .Where(t => t.Status is SessionTaskStatus.Open or SessionTaskStatus.Doing)
                .Select(t => t.Text)
                .Take(5)
                .ToList(),
            KeepLastTurns = settings.CompactKeepLastTurns,
            Deterministic = true
        });

        _sessionLogger.LogSystemNote(
            "Context auto-compacted",
            $"Deterministic compact at {pct}% of budget (~{tokens:N0} tokens).",
            tags: new List<string> { "compact", "auto" });

        return await ApplyPendingCompact(conversation, settings).ConfigureAwait(false);
    }

    public async Task<bool> ApplyPendingCompact(List<ChatMessage> conversation, LlmSettings settings)
    {
        if (_sessionMemory == null || _sessionLogger == null) return false;
        var pending = _sessionMemory.TakePendingCompact();
        if (pending == null) return false;

        var tokensBefore = EstimateConversationTokens(conversation);
        var messagesBefore = conversation.Count;

        var inline = pending.JournalIndexes != null && pending.JournalIndexes.Count > 0
            ? _sessionLogger.GetEntriesByIndexes(pending.JournalIndexes)
            : null;

        var digest = _sessionMemory.BuildDigestBlock(_sessionLogger, inline);
        // Must await — GetResult() deadlocks the Compact button: the click handler
        // blocks the dispatcher while GetCurrentUrl queues work on that same dispatcher.
        var metadataBlock = await BuildMetadataBlockAsync().ConfigureAwait(false);
        var digestMessage = ChatMessage.FromUser($"{metadataBlock}\n\n{digest}");

        var system = conversation.FirstOrDefault(m => m.Role == ChatRole.System);
        var rebuilt = new List<ChatMessage>();
        if (system != null)
            rebuilt.Add(system);
        else
            rebuilt.Add(ChatMessage.System(""));

        rebuilt.Add(digestMessage);

        var keepTurns = pending.KeepLastTurns > 0 ? pending.KeepLastTurns : settings.CompactKeepLastTurns;
        var cutIndex = FindSafeCutIndex(conversation, keepTurns);
        if (cutIndex >= 0 && cutIndex < conversation.Count)
            rebuilt.AddRange(conversation.Skip(cutIndex));

        conversation.Clear();
        conversation.AddRange(rebuilt);

        var tokensAfter = EstimateConversationTokens(conversation);
        var messagesAfter = conversation.Count;
        _sessionMemory.ApplyHandoff(pending, messagesBefore, messagesAfter, tokensBefore, tokensAfter);

        CompactApplied?.Invoke(new CompactAppliedInfo
        {
            MessagesBefore = messagesBefore,
            MessagesAfter = messagesAfter,
            TokensBefore = tokensBefore,
            TokensAfter = tokensAfter,
            Summary = pending.Summary,
            Deterministic = pending.Deterministic
        });

        return true;
    }

    internal static int FindSafeCutIndex(List<ChatMessage> conversation, int desiredTurns)
    {
        if (conversation.Count == 0 || desiredTurns <= 0) return conversation.Count;

        int turns = 0;
        for (int i = conversation.Count - 1; i >= 0; i--)
        {
            var msg = conversation[i];
            if (IsSafeCutPoint(msg))
            {
                turns++;
                if (turns >= desiredTurns)
                    return i;
            }
        }

        // No safe cut within desired window — drop tail entirely.
        return conversation.Count;
    }

    internal static bool IsSafeCutPoint(ChatMessage msg)
    {
        if (msg.Role == ChatRole.Assistant)
            return msg.ToolCalls == null || msg.ToolCalls.Count == 0;

        if (msg.Role == ChatRole.User)
        {
            if (string.IsNullOrEmpty(msg.Content)) return true;
            return !PromptToolResultRegex.IsMatch(msg.Content);
        }

        return false;
    }

    private async Task<string> BuildMetadataBlockAsync()
    {
        var meta = _getSessionMetadata != null
            ? await _getSessionMetadata().ConfigureAwait(false)
            : new SessionMetadata();

        var sb = new StringBuilder();
        sb.AppendLine("## Session metadata");
        if (!string.IsNullOrEmpty(meta.SessionName))
            sb.AppendLine($"Session: {meta.SessionName}");
        if (!string.IsNullOrEmpty(meta.Url))
            sb.AppendLine($"URL: {meta.Url}");
        if (!string.IsNullOrEmpty(meta.Title))
            sb.AppendLine($"Title: {meta.Title}");
        if (meta.TabCount > 0)
            sb.AppendLine($"Tabs: {meta.TabCount}");
        if (!string.IsNullOrEmpty(meta.SafetyMode))
            sb.AppendLine($"Safety: {meta.SafetyMode}");
        return sb.ToString().TrimEnd();
    }

    private static string BuildDeterministicSummary(SessionLogger logger)
    {
        var entries = logger.GetJournal(last: 20);
        if (entries.Count == 0)
            return "Session compacted automatically — no journal entries yet.";

        var sb = new StringBuilder("Auto-compact digest:");
        foreach (var e in entries.Take(12))
            sb.AppendLine().Append("- ").Append(JournalProjection.FormatIndexLine(e));
        return sb.ToString();
    }
}
