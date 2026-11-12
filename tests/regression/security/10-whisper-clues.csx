// Security: Red Team Whisper clues — DOM hypotheses, no Shadow overlap, session dedup, per-domain cache.

await ResetBrowserState();
RedTeamWhisper.ResetSession();
RedTeamWhisper.Configure(true, notifyGui: false);

Assert.Section("GET password form + hidden inputs → clues; javascript: / CSP omitted");
var html = MinimalHtml("Whisper Page",
    @"<form method=""get"" action=""/login"">
        <input type=""password"" name=""p"">
        <input type=""hidden"" name=""h1"" value=""1"">
        <input type=""hidden"" name=""h2"" value=""2"">
        <input type=""hidden"" name=""h3"" value=""3"">
        <input type=""hidden"" name=""h4"" value=""4"">
        <input type=""hidden"" name=""h5"" value=""5"">
        <input type=""hidden"" name=""h6"" value=""6"">
        <button type=""submit"">Go</button>
      </form>
      <a href=""javascript:alert(1)"">js link</a>
      <p onclick=""void(0)"">inline</p>");
SetupPage(FixtureUrl("/whisper-form"), html, VulnerableHeaders());
await Navigate(FixtureUrl("/whisper-form"));
await WaitForIdle();
await Task.Delay(900);

var kinds = RedTeamWhisper.LastClues.Select(c => c.Kind).ToList();
Log($"First nav clues ({RedTeamWhisper.LastClues.Count}): " + string.Join(", ", kinds));
foreach (var c in RedTeamWhisper.LastClues)
    Log($"  [{c.Kind}] {c.Title}");

Assert.True(kinds.Contains("get-password-form"), "GET password form is a clue");
Assert.True(kinds.Contains("hidden-inputs"), "Many hidden inputs is a clue");
Assert.False(kinds.Contains("csp") || kinds.Contains("missing-csp"), "CSP is Shadow's job — not a Whisper clue");
Assert.False(kinds.Contains("javascript-url") || kinds.Contains("javascript-links"),
    "javascript: links are Shadow XSS — not a Whisper clue");
Assert.False(kinds.Contains("inline-handlers"), "Inline handlers are Shadow XSS — not a Whisper clue");
Assert.True(RedTeamWhisper.LastNewClues.Count > 0, "First visit produces new clues");

Assert.Section("Same host again → no repeat toasts (newClues empty for those kinds)");
ClearMocks();
SetupPage(FixtureUrl("/whisper-form-2"), html, VulnerableHeaders());
await Navigate(FixtureUrl("/whisper-form-2"));
await WaitForIdle();
await Task.Delay(900);

var newKinds = RedTeamWhisper.LastNewClues.Select(c => c.Kind).ToList();
Log($"Second nav newClues ({newKinds.Count}): " + string.Join(", ", newKinds));
Assert.False(newKinds.Contains("get-password-form"), "Same GET-password clue is not toasted again");
Assert.False(newKinds.Contains("hidden-inputs"), "Same hidden-inputs clue is not toasted again");
Assert.True(RedTeamWhisper.LastClues.Any(c => c.Kind == "get-password-form"),
    "Current-page lastClues still lists the GET password form");

Assert.Section("Reset session + cache HIT → cache clue once per domain");
RedTeamWhisper.ResetSession();
ClearMocks();
SetupPage(FixtureUrl("/whisper-cache"), MinimalHtml("Cached", "<h1>Hit</h1>"), HtmlHeaders(new Dictionary<string, string>
{
    ["CF-Cache-Status"] = "HIT",
    ["Age"] = "42",
    ["Cache-Control"] = "public, max-age=60",
    ["Server"] = "cloudflare"
}));
await Navigate(FixtureUrl("/whisper-cache"));
await WaitForIdle();
await Task.Delay(1200);

var cacheKinds = RedTeamWhisper.LastClues.Select(c => c.Kind).ToList();
Log($"Cache nav clues: " + string.Join(", ", cacheKinds));
foreach (var c in RedTeamWhisper.LastClues)
    Log($"  [{c.Kind}] {c.Title}");
Assert.True(cacheKinds.Contains("cache") || cacheKinds.Contains("tech-stack"),
    "New domain emits a cache and/or tech-stack clue");

var copy = WhisperClue.FormatCopy("Whisper: test", RedTeamWhisper.LastClues.ToList());
Assert.True(copy.Contains("Clue:", StringComparison.Ordinal), "Copy bundle includes Clue: details");
Assert.True(copy.Contains("Whisper: test", StringComparison.Ordinal), "Copy bundle starts with the toast text");

Assert.Section("Internal comment textarea is not a chat-ui clue (even in a *chat* container)");
RedTeamWhisper.ResetSession();
ClearMocks();
var commentHtml = MinimalHtml("Case comments",
    @"<div class=""chat-thread conversation"">
        <form method=""post"" action=""/cases/1/comments"">
          <label for=""save-internal-comment-input"">Comment not shown</label>
          <textarea id=""save-internal-comment-input""
                    label=""Provide comment not shown""
                    placeholder=""Provide comment""></textarea>
          <button type=""submit"">Save</button>
        </form>
      </div>
      <input type=""text"" placeholder=""Ask a question"">");
SetupPage(FixtureUrl("/whisper-internal-comment"), commentHtml, VulnerableHeaders());
await Navigate(FixtureUrl("/whisper-internal-comment"));
await WaitForIdle();
await Task.Delay(900);

var commentKinds = RedTeamWhisper.LastClues.Select(c => c.Kind).ToList();
Log("Comment-page clues: " + string.Join(", ", commentKinds));
foreach (var c in RedTeamWhisper.LastClues)
    Log($"  [{c.Kind}] {c.Title}");
Assert.False(commentKinds.Contains("chat-ui") || commentKinds.Contains("chat-ui-hint"),
    "Internal comment / FAQ 'Ask a question' must not toast as chat UI without corroboration");

Assert.Section("Known chat widget global (Intercom) → chat-ui clue");
RedTeamWhisper.ResetSession();
ClearMocks();
var intercomHtml = MinimalHtml("Support",
    @"<script>window.Intercom = function(){};</script>
      <p>No textarea.</p>");
SetupPage(FixtureUrl("/whisper-intercom"), intercomHtml, VulnerableHeaders());
await Navigate(FixtureUrl("/whisper-intercom"));
await WaitForIdle();
await Task.Delay(900);

var intercomKinds = RedTeamWhisper.LastClues.Select(c => c.Kind).ToList();
Log("Intercom-page clues: " + string.Join(", ", intercomKinds));
foreach (var c in RedTeamWhisper.LastClues)
    Log($"  [{c.Kind}] {c.Title}");
Assert.True(intercomKinds.Contains("chat-ui"), "Intercom global corroborates a chat-ui clue");
Assert.True(RedTeamWhisper.LastClues.Any(c => c.Title.Contains("Intercom", StringComparison.OrdinalIgnoreCase)),
    "Chat-ui clue names the widget global");
