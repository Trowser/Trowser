using System.Net;
using System.Text.Json;
using Trowser.Decisions;

namespace Trowser.Api;

/// <summary>
/// REST + shared builders for decisions (P3): the agent asks the human to make a call, the human
/// answers with a button, and every resolution — including a default that fired because nobody
/// answered — is journalled. Follows the same symmetry pattern as the pointer primitive: one
/// <c>Build*Async</c> per capability, consumed by a REST route and an MCP tool via
/// <c>RenderHostSafe</c>. All of it is in-memory, so nothing here goes through the safety gate.
/// </summary>
public partial class TrowserApiServer
{
    private DecisionStore RequireDecisionStore() =>
        DecisionStore ?? throw new ApiCommandException(503, "Decision store is not available.");

    // ----- Ask -----

    /// <summary>
    /// Create a decision and, in the <c>gate</c> lane, wait for it to resolve. Backs
    /// <c>POST /api/decision</c> and MCP <c>browser_decide</c>.
    /// </summary>
    internal async Task<object> BuildDecisionAskAsync(JsonBody body)
    {
        var store = RequireDecisionStore();

        var question = NullIfEmpty(body.GetString("question")) ?? NullIfEmpty(body.GetString("text"))
            ?? throw new ApiCommandException(400, "Missing required field: question");

        var options = ParseDecisionOptions(body.GetJsonElement("options"));
        var allowOther = body.GetBool("allowOther") || body.GetBool("other");
        var maxListed = allowOther ? DecisionDefaults.MaxOptionsWithOther : DecisionDefaults.MaxOptions;
        if (options.Count < DecisionDefaults.MinOptions || options.Count > maxListed)
            throw new ApiCommandException(400,
                allowOther
                    ? $"With allowOther, list at most {DecisionDefaults.MaxOptionsWithOther} options (Other takes the next letter). Got {options.Count}."
                    : $"A decision needs between {DecisionDefaults.MinOptions} and {DecisionDefaults.MaxOptions} options; got {options.Count}. " +
                      "Supply them as an array of strings, or of objects with label and optional detail.");

        var lane = DecisionLanes.Normalize(body.GetString("lane"));
        var urgency = DecisionUrgencies.Normalize(body.GetString("urgency"));

        var graceMs = 0;
        if (body.HasProperty("graceMs"))
        {
            graceMs = Math.Clamp(body.GetInt("graceMs", 0), 0, DecisionDefaults.MaxGraceMs);
            if (graceMs > 0 && lane != DecisionLanes.Steer)
                throw new ApiCommandException(400, "graceMs is only valid for lane='steer'.");
        }

        var recommendation = MatchOptionKey(options, body.GetString("recommendation"));

        // Steer proceeds without the human, so it always needs something to proceed with: the
        // agent's own recommendation, or failing that the first option it listed.
        var defaultKey = MatchOptionKey(options, body.GetString("default") ?? body.GetString("defaultOption"));
        if (defaultKey == null && lane == DecisionLanes.Steer)
            defaultKey = recommendation ?? options[0].Key;

        var timeoutMs = Math.Clamp(
            body.GetInt("timeout", DecisionDefaults.TimeoutMs),
            DecisionDefaults.MinTimeoutMs, DecisionDefaults.MaxTimeoutMs);

        var pointerIds = body.GetStringList("pointerIds") ?? body.GetStringList("pointers");
        var otherKey = allowOther ? DecisionOption.KeyAt(options.Count) : null;

        var url = NullIfEmpty(body.GetString("url"));
        if (url == null)
        {
            try { url = await _context.GetCurrentUrl(); } catch { /* best effort */ }
        }

        var decision = new Decision
        {
            Question = question,
            Options = options,
            Lane = lane,
            Urgency = urgency,
            Recommendation = recommendation,
            DefaultKey = defaultKey,
            TimeoutMs = timeoutMs,
            PointerIds = pointerIds,
            AllowOther = allowOther,
            OtherKey = otherKey,
            GraceMs = graceMs,
            Url = url,
            CheckpointId = NullIfEmpty(body.GetString("checkpointId")) ?? PointerStore?.LatestCheckpoint?.Id
        };

        store.Add(decision);

        if (_sessionLogger != null)
        {
            try
            {
                var entry = _sessionLogger.LogDecisionAsked(
                    question, lane, DescribeOptions(options, allowOther, otherKey), recommendation, decision.Id, url);
                decision.JournalIndex = entry.Index;
            }
            catch (Exception ex) { TrowserLog.Warn($"Decision journal log failed: {ex.Message}"); }
        }

        // Only the gate lane blocks. Everything else returns now so an agent that asked politely is
        // never stuck behind a question it said it could proceed without.
        if (lane == DecisionLanes.Gate && body.GetBool("wait", true))
        {
            try { await store.WaitForResolutionAsync(decision.Id); }
            catch (Exception ex) { TrowserLog.Warn($"Decision wait failed: {ex.Message}"); }
        }
        else if (lane == DecisionLanes.Steer && graceMs > 0)
        {
            try { await store.WaitForSteerGraceAsync(decision.Id, graceMs); }
            catch (Exception ex) { TrowserLog.Warn($"Decision steer grace failed: {ex.Message}"); }
        }

        return ProjectDecision(store, store.Get(decision.Id) ?? decision);
    }

    // ----- Read / answer / cancel -----

    internal object DoListDecisions(JsonBody body) =>
        DoListDecisions(NullIfEmpty(body.GetString("status")), NullIfEmpty(body.GetString("lane")));

    internal object DoListDecisions(string? status, string? lane)
    {
        var store = RequireDecisionStore();
        if (status != null && !DecisionStatuses.IsKnown(status))
            throw new ApiCommandException(400,
                $"Unknown status '{status}'. Use one of: {string.Join(", ", DecisionStatuses.All)}.");
        if (lane != null && !DecisionLanes.IsKnown(lane))
            throw new ApiCommandException(400,
                $"Unknown lane '{lane}'. Use one of: {string.Join(", ", DecisionLanes.All)}.");

        var list = store.GetAll(status, lane);
        return new
        {
            decisions = list,
            count = list.Count,
            pending = list.Count(d => d.Status == DecisionStatuses.Pending),
            revision = store.Revision
        };
    }

    internal object DoGetDecision(string id)
    {
        var store = RequireDecisionStore();
        var decision = store.Get(id) ?? throw new ApiCommandException(404, $"Unknown decision: {id}");
        return ProjectDecision(store, decision);
    }

    /// <summary>
    /// Record an answer. Backs <c>POST /api/decision/{id}/answer</c> and the GUI buttons (which call
    /// the store directly). Refuses to overwrite an already-resolved decision so the accountability
    /// record cannot be rewritten after the fact.
    /// </summary>
    internal object DoAnswerDecision(string id, JsonBody body)
    {
        var store = RequireDecisionStore();
        var decision = store.Get(id) ?? throw new ApiCommandException(404, $"Unknown decision: {id}");

        if (decision.Status != DecisionStatuses.Pending)
            throw new ApiCommandException(409,
                $"Decision {id} is already {decision.Status}" +
                (decision.AnswerKey == null ? "." : $" (answer: {decision.AnswerKey})."));

        var key = NullIfEmpty(body.GetString("option")) ?? NullIfEmpty(body.GetString("answer"))
            ?? throw new ApiCommandException(400, "Missing required field: option");

        var note = NullIfEmpty(body.GetString("note")) ?? NullIfEmpty(body.GetString("text"));

        if (decision.MatchesOtherKey(key))
        {
            if (string.IsNullOrWhiteSpace(note))
                throw new ApiCommandException(400, $"Missing required field: note (the custom answer for {decision.OtherKey}).");
            store.Answer(id, decision.OtherKey!, NullIfEmpty(body.GetString("by")) ?? DecisionAnswerers.Human, note);
        }
        else
        {
            var matched = MatchOptionKey(decision.Options, key)
                ?? throw new ApiCommandException(400,
                    $"Unknown option '{key}'. Valid options: {DescribeOptions(decision.Options, decision.AllowOther, decision.OtherKey)}.");
            store.Answer(id, matched, NullIfEmpty(body.GetString("by")) ?? DecisionAnswerers.Human, note);
        }

        return ProjectDecision(store, store.Get(id) ?? decision);
    }

    /// <summary>Withdraw a pending question. Backs <c>DELETE /api/decision/{id}</c>.</summary>
    internal object DoCancelDecision(string id, string? reason)
    {
        var store = RequireDecisionStore();
        var decision = store.Get(id) ?? throw new ApiCommandException(404, $"Unknown decision: {id}");

        if (decision.Status != DecisionStatuses.Pending)
            throw new ApiCommandException(409, $"Decision {id} is already {decision.Status}.");

        store.Cancel(id, reason);
        return ProjectDecision(store, store.Get(id) ?? decision);
    }

    /// <summary>
    /// MCP read/steer facade for <c>browser_decisions</c>: lists decisions, fetches one when
    /// <c>id</c> is given, or withdraws one with <c>action:"cancel"</c>.
    /// </summary>
    internal Task<object> BuildDecisionsAsync(JsonBody body)
    {
        var id = NullIfEmpty(body.GetString("id"));
        var action = body.GetString("action");

        if (string.Equals(action, "cancel", StringComparison.OrdinalIgnoreCase))
        {
            if (id == null)
                throw new ApiCommandException(400, "action='cancel' needs the id of the decision to withdraw.");
            return Task.FromResult(DoCancelDecision(id, body.GetString("reason")));
        }

        if (id != null)
            return Task.FromResult(DoGetDecision(id));

        return Task.FromResult(DoListDecisions(body));
    }

    // ----- REST plumbing -----

    /// <summary>
    /// <c>GET /api/decisions</c>. Filters come from the query string here — a GET has no body, and
    /// <c>ReadJsonBody</c> would silently drop them.
    /// </summary>
    private async Task HandleGetDecisions(HttpListenerRequest request, HttpListenerResponse response)
    {
        try
        {
            var query = ApiQuery(request);
            await WriteSuccess(response, DoListDecisions(
                NullIfEmpty(query["status"]), NullIfEmpty(query["lane"])));
        }
        catch (ApiCommandException ex) { await WriteError(response, ex.StatusCode, ex.Message); }
    }

    /// <summary>Path-parameter routes for <c>/api/decision/{id}</c> and <c>/api/decision/{id}/answer</c>.</summary>
    private async Task<bool> TryRouteDecisionAsync(string path, string method, HttpListenerRequest request, HttpListenerResponse response)
    {
        const string prefix = "/api/decision/";
        if (!path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) return false;

        var tail = path[prefix.Length..].Trim('/');
        if (tail.Length == 0) return false;

        // /api/decision/{id}/answer
        if (tail.EndsWith("/answer", StringComparison.OrdinalIgnoreCase) && method == "POST")
        {
            var answerId = Uri.UnescapeDataString(tail[..^"/answer".Length]);
            try
            {
                var body = await ReadJsonBody(request);
                await WriteSuccess(response, DoAnswerDecision(answerId, body));
            }
            catch (ApiCommandException ex) { await WriteError(response, ex.StatusCode, ex.Message); }
            return true;
        }

        if (tail.Contains('/')) return false; // no other nested routes

        var id = Uri.UnescapeDataString(tail);
        switch (method)
        {
            case "GET":
                try { await WriteSuccess(response, DoGetDecision(id)); }
                catch (ApiCommandException ex) { await WriteError(response, ex.StatusCode, ex.Message); }
                return true;
            case "DELETE":
                try
                {
                    // Many clients cannot send a DELETE body, so take the reason from either.
                    var body = await ReadJsonBody(request);
                    var reason = NullIfEmpty(body.GetString("reason")) ?? NullIfEmpty(ApiQuery(request)["reason"]);
                    await WriteSuccess(response, DoCancelDecision(id, reason));
                }
                catch (ApiCommandException ex) { await WriteError(response, ex.StatusCode, ex.Message); }
                return true;
            default:
                return false;
        }
    }

    // ----- Helpers -----

    /// <summary>
    /// Wrap a decision with what the agent actually needs to act: whether it can proceed, on which
    /// option, and guidance. <c>provisional</c> marks a steer-lane answer the human can still override.
    /// </summary>
    private static object ProjectDecision(DecisionStore store, Decision decision)
    {
        var resolved = decision.Status != DecisionStatuses.Pending;

        object? answerPayload = null;
        var provisional = false;

        if (resolved && decision.Status != DecisionStatuses.Expired)
        {
            answerPayload = BuildAnswerPayload(decision, decision.AnsweredBy);
        }
        else if (!resolved && decision.Lane == DecisionLanes.Steer)
        {
            var defaultOption = decision.FindOption(decision.DefaultKey);
            if (defaultOption != null)
            {
                answerPayload = new { key = defaultOption.Key, label = defaultOption.Label, detail = defaultOption.Detail, by = DecisionAnswerers.Default, note = (string?)null };
                provisional = true;
            }
        }

        return new
        {
            decision,
            resolved,
            provisional,
            answer = answerPayload,
            guidance = BuildDecisionGuidance(decision, provisional)
        };
    }

    private static object? BuildAnswerPayload(Decision decision, string? by)
    {
        if (decision.IsOtherAnswer)
            return new { key = decision.OtherKey, label = decision.AnswerLabel, detail = (string?)null, by, note = decision.AnswerNote };
        var option = decision.FindOption(decision.AnswerKey);
        return option == null ? null : new { key = option.Key, label = option.Label, detail = option.Detail, by, note = decision.AnswerNote };
    }

    private static string BuildDecisionGuidance(Decision decision, bool provisional)
    {
        var window = FormatTimeout(decision.TimeoutMs);
        var choice = FormatChoice(decision);

        if (provisional)
        {
            var defaultOption = decision.FindOption(decision.DefaultKey);
            var defaultChoice = defaultOption == null ? null : $"{defaultOption.Key} ({defaultOption.Label})";
            var graceNote = decision.GraceMs > 0
                ? $"Waited {FormatGrace(decision.GraceMs)} for your answer — none came. "
                : "";
            return graceNote +
                   $"Proceeding on the default {defaultChoice}. The question stays open for ~{window} — " +
                   $"re-check with browser_decisions id={decision.Id} before anything irreversible.";
        }

        return decision.Status switch
        {
            DecisionStatuses.Answered when decision.AnsweredBy == DecisionAnswerers.Human =>
                $"The tester chose {choice}. Do that.",
            DecisionStatuses.Answered =>
                $"Answered {choice} by {decision.AnsweredBy}. Do that.",
            DecisionStatuses.Defaulted =>
                $"Nobody answered within {window}, so the default {choice} applied. " +
                "Say so in your next journal entry — this was your call, not the tester's.",
            DecisionStatuses.Expired =>
                $"Nobody answered within {window} and there was no default. Use your judgement and " +
                "journal the assumption you made.",
            DecisionStatuses.Cancelled =>
                "This question was withdrawn.",
            _ when decision.Lane == DecisionLanes.Review =>
                "Recorded for the tester; no answer needed. Carry on.",
            _ =>
                $"Question is open. Poll browser_decisions id={decision.Id} when you need the answer " +
                $"(the default fires after ~{window})."
        };
    }

    private static string? FormatChoice(Decision decision)
    {
        if (decision.IsOtherAnswer)
            return $"Other ({decision.AnswerLabel})";
        var option = decision.FindOption(decision.AnswerKey);
        return option == null ? null : $"{option.Key} ({option.Label})";
    }

    private static string FormatGrace(int graceMs) =>
        graceMs < 1000 ? $"{graceMs} ms" : graceMs < 60_000 ? $"{graceMs / 1000} s" : $"{graceMs / 60_000} min";

    private static string FormatTimeout(int timeoutMs) =>
        timeoutMs < 60_000 ? $"{timeoutMs / 1000} s" : $"{timeoutMs / 60_000} min";

    /// <summary>
    /// Accept options as plain strings (<c>["Retry", "Skip"]</c>) or objects
    /// (<c>[{"label":"Retry","detail":"…"}]</c>), assigning keys A, B, C … in order.
    /// </summary>
    private static List<DecisionOption> ParseDecisionOptions(JsonElement? element)
    {
        var options = new List<DecisionOption>();
        if (element is not { ValueKind: JsonValueKind.Array } array) return options;

        foreach (var item in array.EnumerateArray())
        {
            string? label = null;
            string? detail = null;

            if (item.ValueKind == JsonValueKind.String)
            {
                label = item.GetString();
            }
            else if (item.ValueKind == JsonValueKind.Object)
            {
                label = ReadStringProp(item, "label") ?? ReadStringProp(item, "text") ?? ReadStringProp(item, "option");
                detail = ReadStringProp(item, "detail") ?? ReadStringProp(item, "description");
            }

            if (string.IsNullOrWhiteSpace(label)) continue;
            options.Add(new DecisionOption
            {
                Key = DecisionOption.KeyAt(options.Count),
                Label = label.Trim(),
                Detail = string.IsNullOrWhiteSpace(detail) ? null : detail.Trim()
            });

            if (options.Count > DecisionDefaults.MaxOptions) break;
        }

        return options;
    }

    /// <summary>Resolve a caller-supplied option reference — a key like "B", or the option's label.</summary>
    private static string? MatchOptionKey(List<DecisionOption> options, string? reference)
    {
        if (string.IsNullOrWhiteSpace(reference)) return null;
        var value = reference.Trim();

        var byKey = options.FirstOrDefault(o => o.Key.Equals(value, StringComparison.OrdinalIgnoreCase));
        if (byKey != null) return byKey.Key;

        var byLabel = options.FirstOrDefault(o => o.Label.Equals(value, StringComparison.OrdinalIgnoreCase));
        return byLabel?.Key;
    }

    private static string DescribeOptions(List<DecisionOption> options, bool allowOther = false, string? otherKey = null)
    {
        var text = string.Join(", ", options.Select(o => $"{o.Key}) {o.Label}"));
        if (allowOther && otherKey != null)
            return text + $", {otherKey}) Other (custom text; REST alias option=\"other\")";
        return text;
    }

    private static string? ReadStringProp(JsonElement element, string name) =>
        element.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
}
