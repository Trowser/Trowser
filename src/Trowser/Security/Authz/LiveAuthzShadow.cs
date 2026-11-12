using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using Trowser.Api;
using Trowser.Automation;
using Trowser.Decisions;
using Trowser.Peers;

namespace Trowser.Security.Authz;

/// <summary>
/// Configuration for <see cref="LiveAuthzShadow"/>. Off by default — enabling it is an explicit,
/// safetyMode-gated opt-in.
/// </summary>
public class LiveAuthzShadowConfig
{
    public bool Enabled { get; set; }

    /// <summary>passive | safe | active | aggressive. GET/HEAD/OPTIONS/QUERY always allowed once
    /// enabled; state-changing methods (POST/PUT/PATCH/DELETE) require active or aggressive.</summary>
    public string SafetyMode { get; set; } = "safe";

    /// <summary>
    /// Peer names to replay against. Empty means alive session peers marked "Use for tests",
    /// plus any peers registered outside the session manager. An explicit list replaces that.
    /// </summary>
    public List<string> Peers { get; set; } = [];

    public int MaxConcurrent { get; set; } = 2;
    public int MaxResults { get; set; } = 500;
}

/// <summary>One recorded owner-vs-peer replay outcome.</summary>
public sealed class LiveAuthzShadowResult
{
    private static int _nextId;

    public int Id { get; init; } = Interlocked.Increment(ref _nextId);

    internal static void AdvanceIdPast(int id)
    {
        int current;
        do
        {
            current = _nextId;
            if (current >= id) return;
        }
        while (Interlocked.CompareExchange(ref _nextId, id, current) != current);
    }
    public DateTime Timestamp { get; init; } = DateTime.UtcNow;
    public required string Host { get; init; }
    public required string Method { get; init; }
    public required string Url { get; init; }
    public required string UrlTemplate { get; init; }
    public required string Peer { get; init; }

    [JsonConverter(typeof(JsonStringEnumConverter))]
    public required AuthzVerdictKind Verdict { get; init; }
    public required string Confidence { get; init; }
    public required string Reason { get; init; }

    /// <summary>The access model's declared expectation for this resource, if classified.</summary>
    public string? ExpectedOutcome { get; set; }

    /// <summary>True when this resource has no human or AI classification in the access model.
    /// A heuristic seed still needs a person to confirm it.</summary>
    public bool NeedsClassification { get; set; }

    /// <summary>Owner response status captured from the browser. 0 when unknown.</summary>
    public int OwnerStatus { get; init; }

    /// <summary>Peer replay status. 0 when the replay failed before a response.</summary>
    public int PeerStatus { get; init; }

    public int OwnerBodyLength { get; init; }

    public int PeerBodyLength { get; init; }

    /// <summary>Peer URL after redirects, when it differs from <see cref="Url"/>.</summary>
    public string? PeerFinalUrl { get; init; }

    /// <summary>Set when the peer replay itself failed (timeout, dead peer, undecoded body is a verdict instead).</summary>
    public string? PeerError { get; init; }

    /// <summary>How many owner-identifying tokens were available for this comparison. Zero means a leak cannot be confirmed by token.</summary>
    public int OwnerTokenCount { get; init; }

    /// <summary><c>cookie</c>, <c>bearer</c>, <c>both</c>, or <c>none</c>. A denial with <c>none</c> is inconclusive.</summary>
    public string? PeerAuthApplied { get; init; }

    /// <summary>True when the owner body was not captured and a single retry still had nothing to compare.</summary>
    public bool OwnerBodyMissing { get; init; }

    /// <summary>True when the owner body is an HTML document (SPA shell).</summary>
    public bool HtmlShell { get; init; }

    /// <summary>True when another route already returned this same HTML document.</summary>
    public bool DuplicateHtmlShell { get; init; }

    /// <summary>True when a state-changing replay received a 2xx as the peer. The peer account may contain a new row.</summary>
    public bool PeerMutated { get; init; }
}

/// <summary>Why <see cref="LiveAuthzShadow.Classify"/> declined to replay a captured request.</summary>
public enum AuthzShadowSkipReason
{
    None = 0,
    Disabled,
    SyntheticOrCache,
    ResourceType,
    SafetyMode,
    NotSuccess,
    ThirdParty,
    BadUrl,
    /// <summary>An open WebSocket was seen. Frames are not HTTP-replayed.</summary>
    WebSocket
}

/// <summary>A captured request the shadow declined to replay, keyed for the coverage gap list.</summary>
public sealed class AuthzShadowSkip
{
    public required string Host { get; init; }
    public required string Method { get; init; }
    public required string UrlTemplate { get; init; }

    /// <summary><c>safety</c>, <c>resourceType</c>, <c>nonSuccess</c>, or <c>thirdParty</c>.</summary>
    public required string Kind { get; init; }
}

/// <summary>Portable snapshot of shadow results plus the access models they depend on.</summary>
public sealed class AuthzShadowBundle
{
    public const int CurrentVersion = 1;

    public static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter() },
        WriteIndented = true
    };

    public int Version { get; set; } = CurrentVersion;
    public DateTime ExportedAt { get; set; } = DateTime.UtcNow;
    public string SafetyMode { get; set; } = "safe";
    public List<string> Peers { get; set; } = [];
    public List<LiveAuthzShadowResult> Results { get; set; } = [];
    public List<AccessModel> Models { get; set; } = [];
}

/// <summary>
/// Live, intent-aware Broken Access Control shadow: watches network traffic ambient to normal
/// browsing (fed from <c>OnNetworkEntry</c>, alongside <see cref="SecurityShadowManager"/>) and
/// replays authz-relevant requests read-only through registered peers to surface cross-identity
/// access issues without a dedicated scan. Off by default; enabling requires an explicit safetyMode.
/// </summary>
public class LiveAuthzShadow
{
    private readonly AutomationContext _context;
    private readonly AccessModelStore _modelStore;
    private readonly object _lock = new();
    private readonly List<LiveAuthzShadowResult> _results = [];
    private readonly HashSet<string> _tested = new(StringComparer.OrdinalIgnoreCase);
    private readonly SemaphoreSlim _concurrency;
    private int _generation;
    private readonly Dictionary<string, (string Host, AccessModelResource Resource)> _sessionClassifications = new(StringComparer.OrdinalIgnoreCase);
    private int _endpointsTested;
    private int _endpointsSkipped;
    private int _skippedBySafety;
    private int _skippedResourceType;
    private int _skippedNonSuccess;
    private int _skippedThirdParty;
    private int _skippedWebSocket;
    private int _replayFailures;
    private int _lastPolledResultId;
    private readonly Dictionary<string, AuthzShadowSkip> _skips = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, string> _htmlShells = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, (DateTime Expires, Dictionary<string, string> Headers)> _peerAuthCache = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<int, PeerFirstWriteBatch> _peerFirstWrites = new();
    private int _nextPeerFirstSlot;
    private DecisionStore? _decisionStore;

    /// <summary>Captured write the shadow will replay to peers before the owner request proceeds.</summary>
    public sealed class OutgoingAuthzRequest
    {
        public required string Method { get; init; }
        public required string Url { get; init; }
        public required string ResourceType { get; init; }
        public required Dictionary<string, string> RequestHeaders { get; init; }
        public string? RequestBody { get; init; }
        public required string PageUrl { get; init; }
        public bool IsTrowserGenerated { get; init; }
    }

    private sealed class PeerFirstWriteBatch
    {
        public required OutgoingAuthzRequest Request { get; init; }
        public required int Generation { get; init; }
        public required HashSet<string> ExpectedPeers { get; init; }
        public Dictionary<string, DirectFetchHelper.DirectFetchResult> PeerResults { get; } =
            new(StringComparer.OrdinalIgnoreCase);
    }

    public LiveAuthzShadowConfig Config { get; } = new();

    /// <summary>Access model store backing this shadow — exposed so the GUI can read/apply bulk classifications directly.</summary>
    public AccessModelStore ModelStore => _modelStore;

    /// <summary>
    /// Correlation prefix stashed in <see cref="Decision.CheckpointId"/> so <see cref="OnDecisionResolved"/>
    /// can recognize its own review-lane questions among any other decisions in the store.
    /// </summary>
    internal const string ClassificationCheckpointPrefix = "authz-model:";

    /// <summary>
    /// Optional decision store. Classification uses the Live Authz Shadow dialog; legacy review answers still update the access model.
    /// </summary>
    public DecisionStore? DecisionStore
    {
        get => _decisionStore;
        set
        {
            if (ReferenceEquals(_decisionStore, value)) return;
            if (_decisionStore != null) _decisionStore.Resolved -= OnDecisionResolved;
            _decisionStore = value;
            if (_decisionStore != null) _decisionStore.Resolved += OnDecisionResolved;
        }
    }

    public LiveAuthzShadow(AutomationContext context, AccessModelStore? modelStore = null)
    {
        _context = context;
        _modelStore = modelStore ?? new AccessModelStore();
        _concurrency = new SemaphoreSlim(Config.MaxConcurrent);
        ForgetDialogClassificationsOnDisk();
    }

    /// <summary>Test seam. Does not touch the browser.</summary>
    internal LiveAuthzShadow(AccessModelStore modelStore) : this(null!, modelStore) { }

    public bool Enabled => Config.Enabled;

    public void Configure(bool enabled, string? safetyMode = null, List<string>? peers = null)
    {
        Config.Enabled = enabled;
        if (safetyMode != null) Config.SafetyMode = safetyMode;
        if (peers != null) Config.Peers = peers;
        if (enabled)
            NoteOpenSockets();
    }

    /// <summary>Record an open socket as a coverage gap. Live Authz Shadow does not replay frames.</summary>
    public void NoteWebSocket(string url)
    {
        if (!Config.Enabled || string.IsNullOrWhiteSpace(url)) return;
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri)) return;
        if (uri.Scheme is not ("ws" or "wss" or "http" or "https")) return;

        var normalized = Trowser.Security.WebSocket.WebSocketAuditor.NormalizeConnectionUrl(
            uri.Scheme is "http" or "https"
                ? "wss://" + uri.Authority + uri.PathAndQuery
                : url);
        if (!Uri.TryCreate(normalized, UriKind.Absolute, out var socketUri)) return;

        var host = AuthzHostKey.Canonical(normalized);
        var template = AttackSurfaceMapper.TemplatizePath(socketUri.AbsolutePath);
        RememberSkip(host, "WS", string.IsNullOrEmpty(template) ? "/" : template, "websocket", AuthzShadowSkipReason.WebSocket);
    }

    /// <summary>Store an on-demand socket authz result in the same verdict list as HTTP replays.</summary>
    public void RecordSocketResult(LiveAuthzShadowResult result)
    {
        int generation;
        lock (_lock) generation = _generation;
        StoreResult(result, result.PeerError != null, generation);
    }

    private void NoteOpenSockets()
    {
        try
        {
            var sockets = _context?.ActiveTab?.WebSocket?.GetConnections();
            if (sockets == null) return;
            foreach (var conn in sockets)
            {
                if (conn.State is "open" or "connecting")
                    NoteWebSocket(conn.Url);
            }
        }
        catch
        {
            // No active tab yet.
        }
    }

    public void ClearResults()
    {
        List<(string Host, AccessModelResource Resource)> cleared;
        lock (_lock)
        {
            _generation++;
            _results.Clear();
            _tested.Clear();
            _skips.Clear();
            _htmlShells.Clear();
            _peerAuthCache.Clear();
            _peerFirstWrites.Clear();
            _endpointsTested = 0;
            _endpointsSkipped = 0;
            _skippedBySafety = 0;
            _skippedResourceType = 0;
            _skippedNonSuccess = 0;
            _skippedThirdParty = 0;
            _skippedWebSocket = 0;
            _replayFailures = 0;
            _lastPolledResultId = 0;
            cleared = _sessionClassifications.Values.ToList();
            _sessionClassifications.Clear();
        }

        RemovePersistedClassifications(cleared);
        WithdrawClassificationCards(null);
    }

    /// <summary>Classifications made in this run. Export/Import is how they leave the process.</summary>
    public AccessModelResource? FindSessionClassification(string host, string method, string urlTemplate)
    {
        lock (_lock)
        {
            return _sessionClassifications.TryGetValue(SessionKey(host, method, urlTemplate), out var found)
                ? found.Resource
                : null;
        }
    }

    public List<(string Host, AccessModelResource Resource)> ListSessionClassifications()
    {
        lock (_lock)
            return _sessionClassifications.Values
                .OrderBy(v => v.Host, StringComparer.OrdinalIgnoreCase)
                .ThenBy(v => v.Resource.Key, StringComparer.OrdinalIgnoreCase)
                .ToList();
    }

    /// <summary>Copy this run's classifications onto <paramref name="model"/> without writing them to disk.</summary>
    public void ApplySessionClassifications(AccessModel model)
    {
        var host = AuthzHostKey.Canonical(model.Host);
        lock (_lock)
        {
            foreach (var (classifiedHost, resource) in _sessionClassifications.Values)
            {
                if (!AuthzHostKey.Canonical(classifiedHost).Equals(host, StringComparison.OrdinalIgnoreCase))
                    continue;
                model.Resources[resource.Key] = resource;
            }
        }
    }

    /// <summary>
    /// A human or AI answer with a real sensitivity and ownership. Heuristic seeds stay open
    /// so the Live Authz Shadow dialog can still ask.
    /// </summary>
    public static bool HasCommittedClassification(AccessModelResource? resource) =>
        resource != null
        && resource.Source is AccessSource.Human or AccessSource.Ai
        && !resource.IsUnclassified;

    /// <summary>Verdicts the Live Authz Shadow dialog asks a person to classify.</summary>
    public static bool IsClassificationVerdict(AuthzVerdictKind verdict) =>
        verdict is AuthzVerdictKind.ConfirmedLeak
            or AuthzVerdictKind.BolaSuspected
            or AuthzVerdictKind.SameShapeDifferentData
            or AuthzVerdictKind.ReplayedWrite;

    /// <summary>
    /// Record a classification from the Live Authz Shadow dialog and drop matching results
    /// out of the needs-classification set.
    /// </summary>
    public void ClassifyResource(
        string host, string method, string urlTemplate,
        AccessSensitivity sensitivity, AccessOwnership ownership,
        AccessSource source = AccessSource.Human)
    {
        var resource = new AccessModelResource
        {
            Method = method.Trim(),
            UrlTemplate = urlTemplate.Trim(),
            Sensitivity = sensitivity,
            Ownership = ownership,
            Source = source,
            Confidence = 1.0,
            Notes = "Classified in the Live Authz Shadow dialog."
        };
        RememberSession(host, resource);
        MarkResultsClassified(host, method, urlTemplate, resource.ExpectedCrossIdentityOutcome);
    }

    private void RememberSession(string host, AccessModelResource resource)
    {
        lock (_lock)
            _sessionClassifications[SessionKey(host, resource.Method, resource.UrlTemplate)] = (host, resource);
    }

    private void MarkResultsClassified(string host, string method, string urlTemplate, string expected)
    {
        lock (_lock)
        {
            foreach (var result in _results)
            {
                if (!result.Host.Equals(host, StringComparison.OrdinalIgnoreCase)) continue;
                if (!result.Method.Equals(method, StringComparison.OrdinalIgnoreCase)) continue;
                if (!result.UrlTemplate.Equals(urlTemplate, StringComparison.OrdinalIgnoreCase)) continue;
                result.NeedsClassification = false;
                result.ExpectedOutcome = expected;
            }
        }
    }

    private static string SessionKey(string host, string method, string urlTemplate) =>
        $"{AuthzHostKey.Canonical(host)}|{method.Trim().ToUpperInvariant()}|{urlTemplate.Trim()}";

    /// <summary>
    /// Dialog classifications used to be written into the access-model files. Drop those so a
    /// restart does not bring them back. Export/Import is the copy that survives.
    /// </summary>
    private void ForgetDialogClassificationsOnDisk()
    {
        try
        {
            foreach (var host in _modelStore.ListHosts())
            {
                var model = _modelStore.Load(host);
                if (model == null) continue;
                var stale = model.Resources
                    .Where(kv => kv.Value.Source is AccessSource.Human or AccessSource.Ai
                        && kv.Value.Notes != null
                        && kv.Value.Notes.Contains("Live Authz Shadow", StringComparison.OrdinalIgnoreCase))
                    .Select(kv => kv.Key)
                    .ToList();
                if (stale.Count == 0) continue;
                foreach (var key in stale)
                    model.Resources.Remove(key);
                _modelStore.Save(model);
            }
        }
        catch
        {
            // A locked model file must not stop the shadow from starting.
        }
    }

    private void RemovePersistedClassifications(List<(string Host, AccessModelResource Resource)> cleared)
    {
        foreach (var group in cleared.GroupBy(c => AuthzHostKey.Canonical(c.Host), StringComparer.OrdinalIgnoreCase))
        {
            if (!AccessModelStore.IsValidHost(group.Key)) continue;
            try
            {
                var model = _modelStore.Load(group.Key);
                if (model == null) continue;
                var changed = false;
                foreach (var (_, resource) in group)
                {
                    var key = resource.Key;
                    if (model.Resources.TryGetValue(key, out var existing)
                        && existing.Source is AccessSource.Human or AccessSource.Ai)
                    {
                        model.Resources.Remove(key);
                        changed = true;
                    }
                }
                if (changed) _modelStore.Save(model);
            }
            catch
            {
                // Clearing the in-memory session still succeeded.
            }
        }
    }

    /// <summary>Drop any Live Authz Shadow review cards still waiting in the AI Assistant.</summary>
    public void DismissClassificationPrompts() => WithdrawClassificationCards(null);

    public object GetStatus()
    {
        lock (_lock)
        {
            return new
            {
                enabled = Config.Enabled,
                safetyMode = Config.SafetyMode,
                peers = Config.Peers,
                endpointsTested = _endpointsTested,
                endpointsSkipped = _endpointsSkipped,
                skippedBySafetyMode = _skippedBySafety,
                skippedResourceType = _skippedResourceType,
                skippedNonSuccess = _skippedNonSuccess,
                skippedThirdParty = _skippedThirdParty,
                skippedWebSocket = _skippedWebSocket,
                replayFailures = _replayFailures,
                peerMutatedCount = _results.Count(r => r.PeerMutated),
                resultCount = _results.Count,
                verdictCounts = _results
                    .GroupBy(r => r.Verdict.ToString())
                    .ToDictionary(g => g.Key, g => g.Count()),
                needsClassificationCount = _results.Count(r => r.NeedsClassification)
            };
        }
    }

    public List<LiveAuthzShadowResult> GetResults(int? sinceId = null, AuthzVerdictKind? verdict = null, string? host = null)
    {
        lock (_lock)
        {
            IEnumerable<LiveAuthzShadowResult> q = _results;
            if (sinceId.HasValue) q = q.Where(r => r.Id > sinceId.Value);
            if (verdict.HasValue) q = q.Where(r => r.Verdict == verdict.Value);
            if (!string.IsNullOrWhiteSpace(host))
            {
                var key = AuthzHostKey.Canonical(host);
                q = q.Where(r => AuthzHostKey.Canonical(r.Host).Equals(key, StringComparison.OrdinalIgnoreCase));
            }
            return q.ToList();
        }
    }

    public List<AuthzShadowSkip> GetSkips()
    {
        lock (_lock)
            return _skips.Values.ToList();
    }

    public void MarkPolled()
    {
        lock (_lock)
        {
            if (_results.Count > 0)
                _lastPolledResultId = _results[^1].Id;
        }
    }

    /// <summary>Chromium resource types that are always worth authz-testing. API calls labeled Other are handled by <see cref="ShouldReplayResource"/>.</summary>
    public static bool IsAuthzRelevantResourceType(string resourceType) =>
        resourceType is "XHR" or "Fetch" or "Document";

    /// <summary>
    /// Resource type <c>Other</c> is not a reason to skip an API call. Chromium uses it for
    /// <c>/contacts</c> when the content-type header was missing. Stylesheets, scripts, fonts,
    /// and decorative images stay out.
    /// </summary>
    public static bool ShouldReplayResource(NetworkEntry entry)
    {
        if (entry.IsEventStream)
            return false;

        var type = entry.ResourceType ?? "";
        if (type is "Script" or "Stylesheet" or "Font" or "Media") return false;

        var ct = entry.ContentType ?? "";
        if (ct.Contains("javascript", StringComparison.OrdinalIgnoreCase)
            || ct.Contains("text/css", StringComparison.OrdinalIgnoreCase)
            || ct.Contains("font/", StringComparison.OrdinalIgnoreCase)
            || ct.Contains("woff", StringComparison.OrdinalIgnoreCase))
            return false;

        var path = entry.Path ?? "";
        var apiOrAuth = path.Contains("/api/", StringComparison.OrdinalIgnoreCase)
            || PeerAuthMaterial.RequestHasAuthHeader(entry.RequestHeaders);
        if (type == "Image" || ct.Contains("image/", StringComparison.OrdinalIgnoreCase))
            return apiOrAuth;

        if (!apiOrAuth && (HasStaticExtension(path) || HasStaticExtension(entry.Url)))
            return false;

        return true;
    }

    private static bool HasStaticExtension(string? pathOrUrl)
    {
        if (string.IsNullOrEmpty(pathOrUrl)) return false;
        var path = pathOrUrl;
        var q = path.IndexOf('?');
        if (q >= 0) path = path[..q];
        var slash = path.LastIndexOf('/');
        var file = slash >= 0 ? path[(slash + 1)..] : path;
        var dot = file.LastIndexOf('.');
        if (dot < 0) return false;
        var ext = file[dot..];
        return ext is ".js" or ".css" or ".map" or ".png" or ".jpg" or ".jpeg" or ".gif" or ".svg"
            or ".webp" or ".ico" or ".woff" or ".woff2" or ".ttf" or ".eot" or ".mp4" or ".mp3" or ".webm";
    }

    public static bool IsStateChanging(string? method)
    {
        var m = (method ?? "").ToUpperInvariant();
        return m is "POST" or "PUT" or "PATCH" or "DELETE";
    }

    /// <summary>
    /// Writes are not read diffs. A 2xx against a named object is a cross-identity save.
    /// A collection create whose body also changes the owner stays <see cref="AuthzVerdictKind.ReplayedWrite"/>.
    /// No peer credential is <see cref="AuthzVerdictKind.PeerUnauthenticated"/>.
    /// </summary>
    public static AuthzVerdict ClassifyWriteReplay(
        AuthzVerdict readVerdict,
        string? peerAuthApplied,
        bool peerSucceeded,
        string? urlTemplate = null,
        string? ownerBody = null,
        string? peerBody = null,
        bool ownerSucceeded = true)
    {
        if (string.Equals(peerAuthApplied, "none", StringComparison.OrdinalIgnoreCase))
        {
            return new AuthzVerdict
            {
                Kind = AuthzVerdictKind.PeerUnauthenticated,
                Confidence = "low",
                Reason = "The write was replayed without a peer credential (peerAuthApplied: none)."
            };
        }

        if (readVerdict.Kind == AuthzVerdictKind.ConfirmedLeak)
            return readVerdict;

        if (!peerSucceeded)
            return readVerdict;

        if (!ownerSucceeded && TemplateHasIdentity(urlTemplate))
        {
            return new AuthzVerdict
            {
                Kind = AuthzVerdictKind.BolaSuspected,
                Confidence = "high",
                Reason = "The peer completed this write against a specific object (2xx) before the owner session finished; the owner then did not succeed — likely cross-identity access or state consumed by the peer replay."
            };
        }

        var sameExceptId = readVerdict.Kind == AuthzVerdictKind.BolaSuspected
            || AuthzBodyMatcher.BodiesMatchIgnoringIdentityFields(ownerBody, peerBody);
        var targetsObject = TemplateHasIdentity(urlTemplate);

        if (targetsObject)
        {
            return new AuthzVerdict
            {
                Kind = AuthzVerdictKind.BolaSuspected,
                Confidence = sameExceptId ? "high" : "medium",
                Reason = sameExceptId
                    ? "The peer completed this write against a specific object and got a success (peerMutated). The response matches the owner's except for an id."
                    : "The peer completed this write against a specific object and got a success (peerMutated). A 2xx on a named object is a cross-identity save, not an isolated create."
            };
        }

        if (sameExceptId && readVerdict.Kind != AuthzVerdictKind.BolaSuspected)
        {
            return new AuthzVerdict
            {
                Kind = AuthzVerdictKind.ReplayedWrite,
                Confidence = "medium",
                Reason = "Both identities got a success and the bodies match except an id. The peer account was mutated (peerMutated). If this saved an existing object, that id is the only difference."
            };
        }

        var identical = readVerdict.Kind == AuthzVerdictKind.BolaSuspected;
        return new AuthzVerdict
        {
            Kind = AuthzVerdictKind.ReplayedWrite,
            Confidence = "low",
            Reason = identical
                ? "Both identities got a success and the bodies match. The peer account was mutated (peerMutated). Confirm the peer did not receive the owner's new resource."
                : "Both identities got their own success. The peer account was mutated (peerMutated). Different ids are an isolated write, not a leak."
        };
    }

    /// <summary>
    /// The owner was logged in, the peer had no session, and the peer still received the same 200 body.
    /// That is missing authentication. An HTML document stays a public shell. A request the owner
    /// made with no credential is left alone so a public API can still recommend public.
    /// </summary>
    public static AuthzVerdict PromoteMissingAuth(
        AuthzVerdict verdict,
        string? peerAuthApplied,
        bool ownerHadCredential,
        bool peerSucceeded,
        bool htmlDocument)
    {
        if (htmlDocument || !ownerHadCredential || !peerSucceeded) return verdict;
        if (!string.Equals(peerAuthApplied, "none", StringComparison.OrdinalIgnoreCase)) return verdict;
        if (verdict.Kind != AuthzVerdictKind.BolaSuspected) return verdict;

        return new AuthzVerdict
        {
            Kind = AuthzVerdictKind.ConfirmedLeak,
            Confidence = "high",
            Reason = "Peer had no session and received the owner's 200 body."
        };
    }

    /// <summary>True when a 2xx body that should exist was not captured (null or empty, and not Content-Length 0).</summary>
    public static bool IsOwnerBodyMissing(NetworkEntry entry)
    {
        if (entry.StatusCode is 204 or 205 or 304) return false;
        if (string.Equals(entry.Method, "HEAD", StringComparison.OrdinalIgnoreCase)) return false;
        if (entry.StatusCode is < 200 or >= 300) return false;
        if (entry.ContentLengthBytes == 0) return false;
        return string.IsNullOrEmpty(entry.ResponseBody);
    }

    public static bool IsHtmlDocument(string? contentType, string? body)
    {
        if (!string.IsNullOrEmpty(contentType) &&
            contentType.Contains("html", StringComparison.OrdinalIgnoreCase))
            return true;
        if (string.IsNullOrWhiteSpace(body)) return false;
        var trimmed = body.AsSpan().TrimStart();
        return trimmed.StartsWith("<!DOCTYPE", StringComparison.OrdinalIgnoreCase)
               || trimmed.StartsWith("<html", StringComparison.OrdinalIgnoreCase);
    }

    public static bool TemplateHasIdentity(string? urlTemplate)
    {
        if (string.IsNullOrEmpty(urlTemplate)) return false;
        return urlTemplate.Contains("{id}", StringComparison.OrdinalIgnoreCase)
               || urlTemplate.Contains("{email}", StringComparison.OrdinalIgnoreCase)
               || urlTemplate.Contains("{token}", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Recommendation comes from the response, not the verdict name.
    /// An identical public document is public. An authenticated write, a confirmed leak, or a list
    /// whose bodies already differ by user is per-user.
    /// </summary>
    public static string RecommendClassification(
        AuthzVerdictKind verdict, string urlTemplate, bool identicalPublicDocument = false, string method = "GET")
    {
        if (verdict is AuthzVerdictKind.ConfirmedLeak or AuthzVerdictKind.ReplayedWrite) return "B";
        if (IsStateChanging(method)) return "B";
        if (verdict is AuthzVerdictKind.SameShapeDifferentData or AuthzVerdictKind.FilteredResponse) return "B";
        if (identicalPublicDocument || !TemplateHasIdentity(urlTemplate)) return "A";
        return "B";
    }

    /// <summary>Another registrable domain (maps, youtube, analytics) is not this application's authz surface.</summary>
    public static bool IsOtherRegistrableDomain(string? requestHost, string? pageUrl)
    {
        if (string.IsNullOrWhiteSpace(requestHost) || string.IsNullOrWhiteSpace(pageUrl))
            return false;
        if (!Uri.TryCreate(pageUrl, UriKind.Absolute, out var page))
            return false;
        if (SecurityHostScope.Matches(requestHost, page.Host))
            return false;
        return !RegistrableDomain(requestHost).Equals(RegistrableDomain(page.Host), StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>State-changing methods only get replayed once the user has explicitly raised safetyMode.</summary>
    public static bool IsMethodAllowed(string method, string safetyMode)
    {
        var m = method.ToUpperInvariant();
        if (m is "GET" or "HEAD" or "OPTIONS" or "QUERY") return true;
        return safetyMode is "active" or "aggressive";
    }

    /// <summary>
    /// Pure selection predicate (no I/O) so the "should this network entry be authz-tested" policy
    /// is unit-testable independent of peers/context.
    /// </summary>
    public bool ShouldTest(NetworkEntry entry) => Classify(entry) == AuthzShadowSkipReason.None;

    /// <summary>Pure selection predicate (no I/O), including why a request was skipped.</summary>
    public AuthzShadowSkipReason Classify(NetworkEntry entry, string? pageUrl = null)
    {
        if (!Config.Enabled) return AuthzShadowSkipReason.Disabled;
        if (entry.IsTrowserGenerated || entry.ServedFromCache) return AuthzShadowSkipReason.SyntheticOrCache;
        if (string.IsNullOrEmpty(entry.Url) || !Uri.TryCreate(entry.Url, UriKind.Absolute, out var uri)) return AuthzShadowSkipReason.BadUrl;
        if (IsWebSocketTraffic(entry)) return AuthzShadowSkipReason.WebSocket;
        if (uri.Scheme is not ("http" or "https")) return AuthzShadowSkipReason.BadUrl;
        if (IsOtherRegistrableDomain(entry.Host, pageUrl)) return AuthzShadowSkipReason.ThirdParty;
        if (!ShouldReplayResource(entry)) return AuthzShadowSkipReason.ResourceType;
        if (!entry.IsSuccess) return AuthzShadowSkipReason.NotSuccess;
        if (!IsMethodAllowed(entry.Method, Config.SafetyMode)) return AuthzShadowSkipReason.SafetyMode;
        return AuthzShadowSkipReason.None;
    }

    /// <summary>
    /// Whether an in-flight browser write should be held until peer replays finish.
    /// Does not require a response status — used from <c>WebResourceRequested</c>.
    /// </summary>
    public AuthzShadowSkipReason ClassifyOutgoing(OutgoingAuthzRequest request)
    {
        if (!Config.Enabled) return AuthzShadowSkipReason.Disabled;
        if (request.IsTrowserGenerated) return AuthzShadowSkipReason.SyntheticOrCache;
        if (string.IsNullOrEmpty(request.Url) || !Uri.TryCreate(request.Url, UriKind.Absolute, out var uri))
            return AuthzShadowSkipReason.BadUrl;
        if (uri.Scheme is not ("http" or "https")) return AuthzShadowSkipReason.BadUrl;
        if (IsOtherRegistrableDomain(uri.Host, request.PageUrl)) return AuthzShadowSkipReason.ThirdParty;

        var stub = new NetworkEntry
        {
            Method = request.Method,
            Url = request.Url,
            ResourceType = request.ResourceType,
            RequestHeaders = request.RequestHeaders,
            StatusCode = 200
        };
        if (!IsStateChanging(request.Method)) return AuthzShadowSkipReason.Disabled;
        if (!ShouldReplayResource(stub)) return AuthzShadowSkipReason.ResourceType;
        if (!IsMethodAllowed(request.Method, Config.SafetyMode)) return AuthzShadowSkipReason.SafetyMode;
        return AuthzShadowSkipReason.None;
    }

    /// <summary>
    /// Peers a replay should hit. An explicit <see cref="LiveAuthzShadowConfig.Peers"/> list wins.
    /// Otherwise session peers are included only when alive and marked "Use for tests".
    /// </summary>
    public List<string> ResolveReplayPeers()
    {
        if (Config.Peers.Count > 0)
            return Config.Peers.ToList();

        var registry = _context?.PeerRegistry;
        if (registry == null)
            return [];

        return PeerSessionManager.SelectPeersForReplay(
            registry.GetAll().Select(p => p.Name),
            _context?.PeerSessionManager?.Sessions).ToList();
    }

    /// <summary>
    /// Reserve a peer-first slot for a state-changing request. Returns null when replay should not run
    /// (disabled, safe mode, static asset, no peers, etc.).
    /// </summary>
    public int? TryBeginPeerFirstWrite(OutgoingAuthzRequest request)
    {
        if (_context?.PeerRegistry == null || _context.PeerRegistry.Count == 0)
            return null;
        if (ClassifyOutgoing(request) != AuthzShadowSkipReason.None)
            return null;

        var peerNames = ResolveReplayPeers();
        if (peerNames.Count == 0) return null;

        var slotId = Interlocked.Increment(ref _nextPeerFirstSlot);
        lock (_lock)
        {
            _peerFirstWrites[slotId] = new PeerFirstWriteBatch
            {
                Request = request,
                Generation = _generation,
                ExpectedPeers = new HashSet<string>(peerNames, StringComparer.OrdinalIgnoreCase)
            };
        }

        return slotId;
    }

    /// <summary>
    /// Replay the reserved write to every configured peer before the owner browser request continues.
    /// </summary>
    public async Task RunPeerFirstReplaysAsync(int slotId)
    {
        PeerFirstWriteBatch? batch;
        lock (_lock)
        {
            if (!_peerFirstWrites.TryGetValue(slotId, out batch))
                return;
        }

        var registry = _context?.PeerRegistry;
        if (registry == null) return;

        var req = batch.Request;
        var host = AuthzHostKey.Canonical(req.Url);
        var ownerHadAuth = PeerAuthMaterial.RequestHasAuthHeader(req.RequestHeaders);

        foreach (var peerName in batch.ExpectedPeers.OrderBy(p => p, StringComparer.OrdinalIgnoreCase))
        {
            if (!IsCurrentRun(batch.Generation))
                return;

            try
            {
                IReadOnlyDictionary<string, string>? peerAuth = null;
                if (ownerHadAuth)
                    peerAuth = await GetPeerAuthHeadersAsync(registry, peerName, host);

                var replayHeaders = PeerAuthMaterial.MergeReplayHeaders(
                    AuthzComparisonService.SanitizeReplayHeaders(req.RequestHeaders),
                    req.RequestHeaders,
                    peerAuth,
                    out _);

                var peer = await AuthzRequestEvaluator.FetchViaPeerAsync(
                    registry, peerName, req.Url, req.Method, replayHeaders, req.RequestBody, 20000);

                lock (_lock)
                {
                    if (_peerFirstWrites.TryGetValue(slotId, out var live))
                        live.PeerResults[peerName] = peer;
                }
            }
            catch (Exception ex)
            {
                lock (_lock)
                {
                    if (_peerFirstWrites.TryGetValue(slotId, out var live))
                    {
                        live.PeerResults[peerName] = new DirectFetchHelper.DirectFetchResult
                        {
                            Error = Trim(ex.Message, 300)
                        };
                    }
                }
            }
        }
    }

    private DirectFetchHelper.DirectFetchResult? TryTakePeerFirstResult(int slotId, string peerName, int generation)
    {
        lock (_lock)
        {
            if (!_peerFirstWrites.TryGetValue(slotId, out var batch) || batch.Generation != generation)
                return null;
            if (!batch.PeerResults.TryGetValue(peerName, out var peer))
                return null;

            batch.ExpectedPeers.Remove(peerName);
            if (batch.ExpectedPeers.Count == 0)
                _peerFirstWrites.Remove(slotId);
            return peer;
        }
    }

    /// <summary>Called for each captured network entry, alongside <see cref="SecurityShadowManager.OnNetworkEntry"/>.</summary>
    public void OnNetworkEntry(NetworkEntry entry, string pageUrl)
    {
        if (Config.Enabled)
            HarvestOwnerTokens(entry);

        var skip = Classify(entry, pageUrl);
        if (entry.AuthzPeerFirstSlotId.HasValue && IsStateChanging(entry.Method)
            && skip == AuthzShadowSkipReason.NotSuccess)
        {
            // Peers ran before the owner; a non-2xx owner may mean the peer already consumed the object.
            skip = AuthzShadowSkipReason.None;
        }

        if (skip is AuthzShadowSkipReason.SafetyMode
            or AuthzShadowSkipReason.ResourceType
            or AuthzShadowSkipReason.NotSuccess
            or AuthzShadowSkipReason.ThirdParty
            or AuthzShadowSkipReason.WebSocket)
        {
            NoteSkip(skip, entry);
            return;
        }
        if (skip != AuthzShadowSkipReason.None) return;

        var peerNames = ResolveReplayPeers();
        if (peerNames.Count == 0)
        {
            lock (_lock) _endpointsSkipped++;
            return;
        }

        var urlTemplate = AttackSurfaceMapper.TemplatizePath(entry.Path);

        foreach (var peerName in peerNames)
        {
            var key = $"{peerName}|{entry.Method.ToUpperInvariant()}|{urlTemplate}";
            int generation;
            lock (_lock)
            {
                generation = _generation;
                if (!_tested.Add(key))
                    continue;
            }

            var slotId = entry.AuthzPeerFirstSlotId;
            _ = Task.Run(() => TestAgainstPeerAsync(entry, peerName, urlTemplate, generation, slotId));
        }
    }

    private bool IsCurrentRun(int generation)
    {
        lock (_lock) return generation == _generation;
    }

    private async Task TestAgainstPeerAsync(
        NetworkEntry entry, string peerName, string urlTemplate, int generation, int? peerFirstSlotId = null)
    {
        var registry = _context.PeerRegistry;
        if (registry == null) return;

        await _concurrency.WaitAsync();
        var host = AuthzHostKey.Canonical(entry.Url);
        try
        {
            if (!IsCurrentRun(generation)) return;
            var ownerBody = entry.ResponseBody ?? "";
            var ownerStatus = entry.StatusCode;
            var ownerMissing = IsOwnerBodyMissing(entry);
            if (ownerMissing)
            {
                var testedKeyEarly = $"{peerName}|{entry.Method.ToUpperInvariant()}|{urlTemplate}";
                var alreadyNoted = false;
                lock (_lock)
                {
                    alreadyNoted = _results.Any(r =>
                        r.Peer == peerName && r.UrlTemplate == urlTemplate && r.OwnerBodyMissing);
                }

                if (!IsCurrentRun(generation)) return;

                if (!alreadyNoted)
                {
                    var retryHeaders = AuthzComparisonService.SanitizeReplayHeaders(entry.RequestHeaders, keepAuthorization: true);
                    var retry = await DirectFetchHelper.FetchAsync(
                        _context, entry.Url, entry.Method, retryHeaders, entry.RequestBody, 20000);
                    if (retry.Error == null && retry.Status is >= 200 and < 300 && !string.IsNullOrEmpty(retry.Body))
                    {
                        ownerBody = retry.Body;
                        ownerStatus = retry.Status;
                        ownerMissing = false;
                    }
                }
                else
                {
                    lock (_lock)
                    {
                        if (generation != _generation) return;
                        _tested.Remove(testedKeyEarly);
                    }
                    return;
                }
            }

            if (ownerMissing)
            {
                if (!IsCurrentRun(generation)) return;
                var testedKey = $"{peerName}|{entry.Method.ToUpperInvariant()}|{urlTemplate}";
                var alreadyNoted = false;
                lock (_lock)
                {
                    if (generation != _generation) return;
                    // The capture raced. A later navigation that does have a body must still be compared.
                    _tested.Remove(testedKey);
                    alreadyNoted = _results.Any(r =>
                        r.Peer == peerName &&
                        r.UrlTemplate == urlTemplate &&
                        r.OwnerBodyMissing);
                }

                if (!alreadyNoted)
                {
                    StoreResult(new LiveAuthzShadowResult
                    {
                        Host = host,
                        Method = entry.Method,
                        Url = entry.Url,
                        UrlTemplate = urlTemplate,
                        Peer = peerName,
                        Verdict = AuthzVerdictKind.Inconclusive,
                        Confidence = "low",
                        Reason = "Owner response body was not captured, so it was not compared to the peer.",
                        OwnerStatus = entry.StatusCode,
                        OwnerBodyLength = 0,
                        OwnerBodyMissing = true,
                        NeedsClassification = false
                    }, false, generation);
                }
                return;
            }

            var owner = new DirectFetchHelper.DirectFetchResult
            {
                Ok = ownerStatus is >= 200 and < 300,
                Status = ownerStatus,
                Body = ownerBody,
                Redirected = false,
                FinalUrl = entry.Url
            };

            var ownerHadAuth = PeerAuthMaterial.RequestHasAuthHeader(entry.RequestHeaders);
            IReadOnlyDictionary<string, string>? peerAuth = null;
            if (ownerHadAuth)
                peerAuth = await GetPeerAuthHeadersAsync(registry, peerName, host);

            var replayHeaders = PeerAuthMaterial.MergeReplayHeaders(
                AuthzComparisonService.SanitizeReplayHeaders(entry.RequestHeaders),
                entry.RequestHeaders,
                peerAuth,
                out var peerHeaderApplied);

            DirectFetchHelper.DirectFetchResult peer;
            if (peerFirstSlotId is int slot)
            {
                var prefetched = TryTakePeerFirstResult(slot, peerName, generation);
                peer = prefetched ?? await AuthzRequestEvaluator.FetchViaPeerAsync(
                    registry, peerName, entry.Url, entry.Method, replayHeaders, entry.RequestBody, 20000);
            }
            else
            {
                peer = await AuthzRequestEvaluator.FetchViaPeerAsync(
                    registry, peerName, entry.Url, entry.Method, replayHeaders, entry.RequestBody, 20000);
            }

            var peerAuthApplied = PeerAuthMaterial.ClassifyApplied(
                ownerHadAuth, peerHeaderApplied, peer.CookiesSent.Count > 0);

            AccessModel model;
            try
            {
                model = _modelStore.GetOrCreate(host);
            }
            catch
            {
                model = new AccessModel { Host = host };
            }

            var resource = model.FindResource(entry.Method, urlTemplate);
            var ownerTokens = CollectOwnerTokens(model);
            var verdict = PeerAuthMaterial.DemoteUnauthenticatedDeny(
                AuthzVerdictEvaluator.Evaluate(owner, peer, ownerTokens, entry.Url),
                peerAuthApplied);
            var peerMutated = false;
            if (IsStateChanging(entry.Method))
            {
                var peerSucceeded = peer.Status is >= 200 and < 300 && peer.Error == null;
                var ownerSucceeded = ownerStatus is >= 200 and < 300;
                verdict = ClassifyWriteReplay(
                    verdict, peerAuthApplied, peerSucceeded, urlTemplate, owner.Body, peer.Body, ownerSucceeded);
                peerMutated = peerSucceeded;
            }

            var isHtml = IsHtmlDocument(entry.ContentType, owner.Body);
            if (!IsStateChanging(entry.Method))
            {
                var ownerHadCredential = ownerHadAuth
                    || entry.RequestHeaders.Keys.Any(k => k.Equals("Cookie", StringComparison.OrdinalIgnoreCase));
                var peerReadSucceeded = peer.Status is >= 200 and < 300 && peer.Error == null;
                verdict = PromoteMissingAuth(verdict, peerAuthApplied, ownerHadCredential, peerReadSucceeded, isHtml);
            }
            var duplicateShell = false;
            if (isHtml && owner.Body.Length > 0)
            {
                var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(owner.Body)));
                var shellKey = host + "|" + hash;
                lock (_lock)
                {
                    if (_htmlShells.TryGetValue(shellKey, out var first)
                        && !first.Equals(urlTemplate, StringComparison.OrdinalIgnoreCase))
                        duplicateShell = true;
                    else
                        _htmlShells.TryAdd(shellKey, urlTemplate);
                }
            }

            if (verdict.Kind == AuthzVerdictKind.BolaSuspected && !TemplateHasIdentity(urlTemplate))
            {
                var suffix = duplicateShell
                    ? " Identical HTML shells are one document, not a per-user resource."
                    : isHtml
                        ? " Identical public document."
                        : " No id in the path; identical content is not by itself per-user data.";
                verdict = new AuthzVerdict
                {
                    Kind = verdict.Kind,
                    Confidence = "low",
                    Reason = verdict.Reason + suffix
                };
            }

            var needsClassification = !duplicateShell && FindSessionClassification(host, entry.Method, urlTemplate) == null;
            var result = BuildResult(
                entry, host, peerName, urlTemplate, verdict, resource, owner, peer,
                ownerTokens.Count, needsClassification, peerAuthApplied, duplicateShell, duplicateShell, peerMutated);
            if (StoreResult(result, peer.Error != null, generation))
            {
                var quietIdentical = result.Verdict == AuthzVerdictKind.BolaSuspected && !TemplateHasIdentity(urlTemplate);
                if (!duplicateShell && !quietIdentical)
                    EmitFindingIfSignal(result);
            }
        }
        catch (Exception ex)
        {
            var result = new LiveAuthzShadowResult
            {
                Host = host,
                Method = entry.Method,
                Url = entry.Url,
                UrlTemplate = urlTemplate,
                Peer = peerName,
                Verdict = AuthzVerdictKind.Inconclusive,
                Confidence = "low",
                Reason = "Replay failed: " + Trim(ex.Message, 300),
                PeerError = Trim(ex.Message, 300),
                OwnerStatus = entry.StatusCode,
                OwnerBodyLength = entry.ResponseBody?.Length ?? 0,
                NeedsClassification = false
            };
            StoreResult(result, true, generation);
        }
        finally
        {
            _concurrency.Release();
        }
    }

    private async Task<Dictionary<string, string>> GetPeerAuthHeadersAsync(PeerRegistry registry, string peerName, string host)
    {
        var cacheKey = peerName + "|" + host;
        lock (_lock)
        {
            if (_peerAuthCache.TryGetValue(cacheKey, out var cached) && cached.Expires > DateTime.UtcNow)
                return new Dictionary<string, string>(cached.Headers, StringComparer.OrdinalIgnoreCase);
        }

        var loaded = await PeerAuthMaterial.LoadFromPeerAsync(registry, peerName, host);
        // An empty result is usually "the peer has not logged in yet". Do not pin that for long.
        var ttl = loaded.Count == 0 ? TimeSpan.FromSeconds(2) : TimeSpan.FromSeconds(15);
        lock (_lock)
            _peerAuthCache[cacheKey] = (DateTime.UtcNow + ttl, loaded);
        return loaded;
    }

    private void NoteSkip(AuthzShadowSkipReason reason, NetworkEntry entry)
    {
        var kind = reason switch
        {
            AuthzShadowSkipReason.SafetyMode => "safety",
            AuthzShadowSkipReason.ResourceType => "resourceType",
            AuthzShadowSkipReason.NotSuccess => "nonSuccess",
            AuthzShadowSkipReason.ThirdParty => "thirdParty",
            AuthzShadowSkipReason.WebSocket => "websocket",
            _ => ""
        };
        if (kind.Length == 0) return;

        var method = reason == AuthzShadowSkipReason.WebSocket ? "WS" : entry.Method;
        var template = AttackSurfaceMapper.TemplatizePath(entry.Path ?? "");
        var host = AuthzHostKey.Canonical(entry.Url);
        RememberSkip(host, method, template, kind, reason);
    }

    private void RememberSkip(string host, string method, string template, string kind, AuthzShadowSkipReason reason)
    {
        var key = $"{host}|{method.ToUpperInvariant()}|{template}|{kind}";
        lock (_lock)
        {
            if (!_skips.TryAdd(key, new AuthzShadowSkip
            {
                Host = host,
                Method = method,
                UrlTemplate = template,
                Kind = kind
            }))
                return;

            switch (reason)
            {
                case AuthzShadowSkipReason.SafetyMode: _skippedBySafety++; break;
                case AuthzShadowSkipReason.ResourceType: _skippedResourceType++; break;
                case AuthzShadowSkipReason.NotSuccess: _skippedNonSuccess++; break;
                case AuthzShadowSkipReason.ThirdParty: _skippedThirdParty++; break;
                case AuthzShadowSkipReason.WebSocket: _skippedWebSocket++; break;
            }
        }

        PersistSkip(host, method, template, kind);
    }

    private static bool IsWebSocketTraffic(NetworkEntry entry)
    {
        if (string.Equals(entry.ResourceType, "WebSocket", StringComparison.OrdinalIgnoreCase))
            return true;
        return entry.Url.StartsWith("ws://", StringComparison.OrdinalIgnoreCase)
            || entry.Url.StartsWith("wss://", StringComparison.OrdinalIgnoreCase);
    }

    public int WebSocketGapCount
    {
        get { lock (_lock) return _skippedWebSocket; }
    }

    private void PersistSkip(string host, string method, string template, string kind)
    {
        try
        {
            var model = _modelStore.GetOrCreate(host);
            if (model.SkippedRequests.Any(s =>
                    s.Method.Equals(method, StringComparison.OrdinalIgnoreCase)
                    && s.UrlTemplate.Equals(template, StringComparison.OrdinalIgnoreCase)
                    && s.Kind.Equals(kind, StringComparison.OrdinalIgnoreCase)))
                return;
            model.SkippedRequests.Add(new AccessModelSkip
            {
                Method = method.ToUpperInvariant(),
                UrlTemplate = template,
                Kind = kind
            });
            _modelStore.Save(model);
        }
        catch
        {
            // The in-memory counter still explains the current session.
        }
    }

    private static LiveAuthzShadowResult BuildResult(
        NetworkEntry entry,
        string host,
        string peerName,
        string urlTemplate,
        AuthzVerdict verdict,
        AccessModelResource? resource,
        DirectFetchHelper.DirectFetchResult owner,
        DirectFetchHelper.DirectFetchResult peer,
        int ownerTokenCount,
        bool needsClassification,
        string peerAuthApplied,
        bool htmlShell,
        bool duplicateHtmlShell,
        bool peerMutated) => new()
    {
        Host = host,
        Method = entry.Method,
        Url = entry.Url,
        UrlTemplate = urlTemplate,
        Peer = peerName,
        Verdict = verdict.Kind,
        Confidence = verdict.Confidence,
        Reason = verdict.Reason,
        ExpectedOutcome = resource?.ExpectedCrossIdentityOutcome,
        NeedsClassification = needsClassification,
        OwnerStatus = owner.Status,
        PeerStatus = peer.Status,
        OwnerBodyLength = owner.Body?.Length ?? 0,
        PeerBodyLength = peer.Body?.Length ?? 0,
        PeerFinalUrl = peer.Redirected ? peer.FinalUrl : null,
        PeerError = peer.Error,
        OwnerTokenCount = ownerTokenCount,
        PeerAuthApplied = peerAuthApplied,
        HtmlShell = htmlShell,
        DuplicateHtmlShell = duplicateHtmlShell,
        PeerMutated = peerMutated
    };

    private bool StoreResult(LiveAuthzShadowResult result, bool replayFailed, int generation)
    {
        lock (_lock)
        {
            if (generation != _generation) return false;
            _results.Add(result);
            _endpointsTested++;
            if (replayFailed) _replayFailures++;
            if (_results.Count > Config.MaxResults)
                _results.RemoveAt(0);
            return true;
        }
    }

    private static string Trim(string? text, int max)
    {
        if (string.IsNullOrEmpty(text) || text.Length <= max) return text ?? "";
        return text[..max];
    }

    /// <summary>Snapshot results and the access models for the hosts those results mention.</summary>
    public AuthzShadowBundle ExportBundle()
    {
        var results = GetResults();
        var models = new List<AccessModel>();
        foreach (var host in results.Select(r => r.Host).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            if (!AccessModelStore.IsValidHost(host)) continue;
            try
            {
                var model = _modelStore.GetOrCreate(host);
                ApplySessionClassifications(model);
                models.Add(model);
            }
            catch { /* skip a host the store refuses */ }
        }

        return new AuthzShadowBundle
        {
            Version = AuthzShadowBundle.CurrentVersion,
            ExportedAt = DateTime.UtcNow,
            SafetyMode = Config.SafetyMode,
            Peers = Config.Peers.ToList(),
            Results = results,
            Models = models
        };
    }

    /// <summary>
    /// Restore a bundle. Human/AI resource classifications already on disk are kept when the
    /// bundle only has a heuristic. <paramref name="replaceResults"/> drops the in-memory log first.
    /// </summary>
    public object ImportBundle(AuthzShadowBundle bundle, bool replaceResults)
    {
        if (bundle.Version > AuthzShadowBundle.CurrentVersion)
            throw new ArgumentException($"Unsupported authz shadow bundle version {bundle.Version}.");

        var modelsMerged = 0;
        var resourcesMerged = 0;
        foreach (var incoming in bundle.Models ?? [])
        {
            if (incoming == null || !AccessModelStore.IsValidHost(incoming.Host)) continue;
            var model = _modelStore.GetOrCreate(incoming.Host);
            foreach (var identity in incoming.Identities ?? [])
            {
                if (string.IsNullOrWhiteSpace(identity.Name)) continue;
                var existing = model.FindIdentity(identity.Name);
                if (existing == null)
                {
                    model.Identities.Add(identity);
                    continue;
                }
                foreach (var tag in identity.OwnerTags ?? [])
                {
                    if (!string.IsNullOrWhiteSpace(tag) &&
                        !existing.OwnerTags.Contains(tag, StringComparer.OrdinalIgnoreCase))
                        existing.OwnerTags.Add(tag);
                }
                if (string.IsNullOrWhiteSpace(existing.Role) && !string.IsNullOrWhiteSpace(identity.Role))
                    existing.Role = identity.Role;
                if (identity.Tier > existing.Tier)
                    existing.Tier = identity.Tier;
            }

            foreach (var resource in incoming.Resources?.Values ?? Enumerable.Empty<AccessModelResource>())
            {
                if (string.IsNullOrWhiteSpace(resource.Method) || string.IsNullOrWhiteSpace(resource.UrlTemplate))
                    continue;
                var key = AccessModelResource.KeyOf(resource.Method, resource.UrlTemplate);
                if (resource.Source is AccessSource.Human or AccessSource.Ai && !resource.IsUnclassified)
                {
                    // Classifications belong to this run. The bundle brings them back; the model file does not.
                    RememberSession(incoming.Host, resource);
                    MarkResultsClassified(incoming.Host, resource.Method, resource.UrlTemplate, resource.ExpectedCrossIdentityOutcome);
                    continue;
                }
                if (model.Resources.TryGetValue(key, out var existing) &&
                    existing.Source is AccessSource.Human or AccessSource.Ai &&
                    resource.Source is not (AccessSource.Human or AccessSource.Ai))
                    continue;
                resource.Method = resource.Method.Trim();
                resource.UrlTemplate = resource.UrlTemplate.Trim();
                model.Resources[key] = resource;
                resourcesMerged++;
            }

            _modelStore.Save(model);
            modelsMerged++;
        }

        var imported = 0;
        var skipped = 0;
        lock (_lock)
        {
            if (replaceResults)
            {
                _generation++;
                _results.Clear();
                _tested.Clear();
                _endpointsTested = 0;
                _replayFailures = 0;
                _lastPolledResultId = 0;
            }

            foreach (var result in bundle.Results ?? [])
            {
                if (result == null || string.IsNullOrWhiteSpace(result.Peer) || string.IsNullOrWhiteSpace(result.UrlTemplate))
                {
                    skipped++;
                    continue;
                }
                var key = $"{result.Peer}|{result.Method.ToUpperInvariant()}|{result.UrlTemplate}";
                if (!_tested.Add(key))
                {
                    skipped++;
                    continue;
                }
                _results.Add(result);
                _endpointsTested++;
                if (result.PeerError != null) _replayFailures++;
                imported++;
            }

            if (_results.Count > 0)
                LiveAuthzShadowResult.AdvanceIdPast(_results.Max(r => r.Id));
        }

        return new
        {
            modelsMerged,
            resourcesMerged,
            resultsImported = imported,
            resultsSkipped = skipped,
            reviewQuestionsRaised = 0,
            status = GetStatus()
        };
    }

    private static List<string> CollectOwnerTokens(AccessModel model) =>
        model.Identities
            .SelectMany(i => i.OwnerTags ?? [])
            .Where(t => !string.IsNullOrWhiteSpace(t))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

    private void EmitFindingIfSignal(LiveAuthzShadowResult result)
    {
        var shadow = _context.SecurityShadow;
        if (shadow == null) return;

        string title;
        var severity = Severity.Info;
        switch (result.Verdict)
        {
            case AuthzVerdictKind.ConfirmedLeak:
                severity = Severity.Critical;
                title = $"Confirmed cross-identity data leak: {result.Method} {result.UrlTemplate}";
                break;
            case AuthzVerdictKind.BolaSuspected:
                severity = Severity.High;
                title = $"BOLA/IDOR suspected: {result.Method} {result.UrlTemplate}";
                break;
            case AuthzVerdictKind.SameShapeDifferentData when result.NeedsClassification:
                severity = Severity.Medium;
                title = $"Unclassified resource returns same-shaped data to another identity: {result.Method} {result.UrlTemplate}";
                break;
            default:
                return; // ProperlyDenied / FilteredResponse / NeedsReview / Inconclusive are not findings
        }

        shadow.AddCustomFinding(
            severity,
            title,
            $"Peer \"{result.Peer}\" replay of {result.Method} {result.Url}: {result.Reason}" +
                (result.NeedsClassification
                    ? " This resource is not yet classified in the access model — classify it via PUT /api/authz/model to confirm intent."
                    : $" Access model expects: {result.ExpectedOutcome}."),
            recommendation: "Confirm ownership boundaries for this endpoint, then classify it via PUT /api/authz/model. " +
                "If this is a genuine leak, restrict server-side authorization checks to the resource owner/tenant.",
            audit: "authz",
            url: result.Url);
    }

    // ----- Classification answers from an older review card, if one is still open -----

    /// <summary>
    /// Cancel pending review cards this shadow raised. <paramref name="checkpointId"/> null cancels every
    /// authz card (used by clear). A specific id cancels older cards for that template before a new one is added.
    /// </summary>
    private void WithdrawClassificationCards(string? checkpointId)
    {
        if (DecisionStore == null) return;
        List<Decision> pending;
        try
        {
            pending = DecisionStore.GetAll(DecisionStatuses.Pending, DecisionLanes.Review);
        }
        catch
        {
            return;
        }

        foreach (var decision in pending)
        {
            if (decision.CheckpointId == null
                || !decision.CheckpointId.StartsWith(ClassificationCheckpointPrefix, StringComparison.Ordinal))
                continue;
            if (checkpointId != null && !decision.CheckpointId.Equals(checkpointId, StringComparison.OrdinalIgnoreCase))
                continue;
            try
            {
                DecisionStore.Cancel(decision.Id, checkpointId == null
                    ? "Live Authz Shadow results were cleared."
                    : "Superseded by a newer Live Authz Shadow result for the same template.");
            }
            catch
            {
                // A card that cannot be withdrawn must not block the replay.
            }
        }
    }

    /// <summary>
    /// Persist a human/AI answer to one of our review questions back into the access model.
    /// Ignores decisions this shadow did not raise, and any resolution that is not a real answer
    /// (defaulted/expired/cancelled) — silence should never be read as a classification.
    /// </summary>
    private void OnDecisionResolved(Decision decision)
    {
        try
        {
            if (decision.CheckpointId == null || !decision.CheckpointId.StartsWith(ClassificationCheckpointPrefix, StringComparison.Ordinal))
                return;
            if (decision.Status != DecisionStatuses.Answered || decision.AnswerKey == null)
                return;
            if (decision.IsOtherAnswer)
                return; // free-text "not sure" — nothing structured to persist

            var key = decision.CheckpointId[ClassificationCheckpointPrefix.Length..];
            var parts = key.Split('|', 3);
            if (parts.Length != 3) return;
            var (host, method, urlTemplate) = (parts[0], parts[1], parts[2]);

            var (sensitivity, ownership) = MapAnswerToClassification(decision.AnswerKey);
            if (sensitivity == AccessSensitivity.Unknown) return;

            var source = string.Equals(decision.AnsweredBy, DecisionAnswerers.Human, StringComparison.OrdinalIgnoreCase)
                ? AccessSource.Human
                : AccessSource.Ai;

            ClassifyResource(host, method, urlTemplate, sensitivity, ownership, source);
        }
        catch
        {
            // best effort — a persistence failure here must not crash the decision store's event fan-out
        }
    }

    internal static (AccessSensitivity Sensitivity, AccessOwnership Ownership) MapAnswerToClassification(string answerKey) =>
        answerKey.Trim().ToUpperInvariant() switch
        {
            "A" => (AccessSensitivity.Public, AccessOwnership.Shared),
            "B" => (AccessSensitivity.Sensitive, AccessOwnership.PerUser),
            "C" => (AccessSensitivity.Sensitive, AccessOwnership.PerTenant),
            "D" => (AccessSensitivity.Internal, AccessOwnership.RoleGated),
            _ => (AccessSensitivity.Unknown, AccessOwnership.Unknown)
        };

    /// <summary>Paths that reliably return "my own" identity data — safe to harvest as owner tokens.</summary>
    private static readonly Regex SelfEndpointPattern = new(
        @"(^|/)(me|profile|whoami|self|session|current-?user|my-account|my-profile|account)(/|$|\?)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    internal static bool IsSelfEndpoint(string? path) =>
        !string.IsNullOrEmpty(path) && SelfEndpointPattern.IsMatch(path);

    private static readonly Regex EmailPattern = new(
        @"[\w.+-]+@[\w-]+\.[\w.-]+", RegexOptions.Compiled);

    /// <summary>
    /// Harvest email and user-id fields as owner tokens on the model's "self" identity.
    /// A generic <c>id</c> is a record id, not the victim. Emails are read at any depth so a
    /// list of the owner's own objects can confirm a later partial copy.
    /// </summary>
    private void HarvestOwnerTokens(NetworkEntry entry)
    {
        if (!entry.IsSuccess) return;
        var authenticated = PeerAuthMaterial.RequestHasAuthHeader(entry.RequestHeaders)
            || entry.RequestHeaders.Keys.Any(k => k.Equals("Cookie", StringComparison.OrdinalIgnoreCase));
        var selfEndpoint = IsSelfEndpoint(entry.Path);
        if (!authenticated && !selfEndpoint) return;

        var tokens = new List<string>();
        if (authenticated)
        {
            foreach (var email in EmailsInPath(entry.Path))
                tokens.Add(email);
        }

        if (!string.IsNullOrEmpty(entry.ResponseBody) && (selfEndpoint || authenticated))
            tokens.AddRange(ExtractIdentityTokens(entry.ResponseBody));

        if (tokens.Count == 0) return;

        try
        {
            var model = _modelStore.GetOrCreate(AuthzHostKey.Canonical(entry.Url));
            var self = model.FindIdentity("self");
            if (self == null)
            {
                self = new AccessModelIdentity { Name = "self", Role = "owner", Tier = 1 };
                model.Identities.Add(self);
            }

            var before = self.OwnerTags.Count;
            foreach (var token in tokens)
            {
                if (!self.OwnerTags.Contains(token, StringComparer.OrdinalIgnoreCase))
                    self.OwnerTags.Add(token);
            }

            if (self.OwnerTags.Count != before)
                _modelStore.Save(model);
        }
        catch
        {
            // best effort — ambient enrichment, never surfaces as an error
        }
    }

    internal static List<string> ExtractIdentityTokens(string body, bool topLevelOnly = false)
    {
        _ = topLevelOnly;
        var tokens = new List<string>();
        if (string.IsNullOrWhiteSpace(body) || body.Length > 256_000) return tokens;

        try
        {
            using var doc = JsonDocument.Parse(body);
            WalkIdentity(doc.RootElement, null, tokens);
        }
        catch (JsonException)
        {
            foreach (Match m in EmailPattern.Matches(body))
                AddToken(tokens, m.Value);
        }

        return tokens;
    }

    private static void WalkIdentity(JsonElement element, string? propertyName, List<string> tokens)
    {
        if (tokens.Count >= 40) return;
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                foreach (var prop in element.EnumerateObject())
                    WalkIdentity(prop.Value, prop.Name, tokens);
                break;
            case JsonValueKind.Array:
                foreach (var item in element.EnumerateArray())
                    WalkIdentity(item, null, tokens);
                break;
            case JsonValueKind.String:
                var text = element.GetString() ?? "";
                if (EmailPattern.IsMatch(text) || (propertyName != null && IsIdentityField(propertyName)))
                    AddToken(tokens, text);
                break;
            case JsonValueKind.Number when propertyName != null && IsIdentityField(propertyName):
                var raw = element.GetRawText();
                if (raw.Length >= 3)
                    AddToken(tokens, raw);
                break;
        }
    }

    private static bool IsIdentityField(string name) =>
        name.Equals("userId", StringComparison.OrdinalIgnoreCase)
        || name.Equals("user_id", StringComparison.OrdinalIgnoreCase)
        || name.Equals("username", StringComparison.OrdinalIgnoreCase)
        || name.Equals("userName", StringComparison.OrdinalIgnoreCase)
        || name.Equals("email", StringComparison.OrdinalIgnoreCase)
        || name.Equals("accountId", StringComparison.OrdinalIgnoreCase)
        || name.Equals("account_id", StringComparison.OrdinalIgnoreCase)
        || name.Equals("sub", StringComparison.OrdinalIgnoreCase)
        || name.Equals("uid", StringComparison.OrdinalIgnoreCase);

    private static void AddToken(List<string> tokens, string? value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length < 3) return;
        if (value.Length > 80) return;
        if (ObjectIdHarvester.LooksLikeInjectionOrFuzzPayload(value)) return;
        if (!tokens.Contains(value, StringComparer.OrdinalIgnoreCase))
            tokens.Add(value);
    }

    private static IEnumerable<string> EmailsInPath(string? path)
    {
        if (string.IsNullOrEmpty(path)) yield break;
        var q = path.IndexOf('?');
        var bare = q >= 0 ? path[..q] : path;
        string decoded;
        try { decoded = Uri.UnescapeDataString(bare); }
        catch (UriFormatException) { decoded = bare; }
        foreach (Match m in EmailPattern.Matches(decoded))
            yield return m.Value;
    }

    private static readonly string[] MultiPartSuffixes =
    [
        "co.uk", "org.uk", "ac.uk", "com.au", "net.au", "co.jp", "com.br", "co.nz",
        "co.za", "com.mx", "co.in", "com.tr", "com.sg", "co.kr", "com.tw", "com.hk", "com.ar", "co.il"
    ];

    private static string RegistrableDomain(string host)
    {
        var parts = host.Trim().TrimEnd('.').Split('.', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length <= 2) return string.Join('.', parts);
        var lastTwo = parts[^2] + "." + parts[^1];
        if (MultiPartSuffixes.Contains(lastTwo, StringComparer.OrdinalIgnoreCase) && parts.Length >= 3)
            return parts[^3] + "." + lastTwo;
        return lastTwo;
    }
}
