using System.Collections.Specialized;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using System.Windows.Threading;
using System.Xml.Linq;
using Trowser;
using Trowser.Accessibility;
using Trowser.Automation;
using Trowser.Compatibility;
using Trowser.Robustness;
using Trowser.Scripting;
using Trowser.Security;
using Trowser.Security.ChainEngine;
using Trowser.Security.LlmRedTeam;
using Trowser.Security.Vpx;
using Trowser.Security.Orchestration;
using Trowser.Security.Orchestration.Rendering;
using Trowser.Security.Workflow;
using Trowser.Security.Sse;
using Trowser.Security.WebSocket;
using Trowser.Security.XsLeaks;
using Trowser.Seo;
using Trowser.SessionLog;

namespace Trowser.Api;

public partial class TrowserApiServer
{
    #region Attack Chain Engine Handlers

    private List<ChainableFinding> CollectChainableFindingsForSession() =>
        ChainAnalysisService.CollectFindings(_context, SessionLogger);

    private ChainPattern? ResolveChainPattern(string patternId) =>
        _chainCatalog.GetAll().FirstOrDefault(p =>
            p.Id.Equals(patternId, StringComparison.OrdinalIgnoreCase));

    private static List<string>? MergeExplicitTargets(List<string>? primary, List<string>? secondary)
    {
        if (primary is not { Count: > 0 } && secondary is not { Count: > 0 })
            return null;
        var merged = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        void AddRange(IEnumerable<string>? items)
        {
            if (items == null) return;
            foreach (var item in items)
            {
                if (string.IsNullOrWhiteSpace(item)) continue;
                if (seen.Add(item.Trim()))
                    merged.Add(item.Trim());
            }
        }
        AddRange(primary);
        AddRange(secondary);
        return merged;
    }

    private static List<IReadOnlyDictionary<string, string>>? ParseHeaderSets(JsonBody body)
    {
        if (!body.TryGetRoot(out var root) || !root.TryGetProperty("headerSets", out var sets)
            || sets.ValueKind != JsonValueKind.Array)
            return null;

        var result = new List<IReadOnlyDictionary<string, string>>();
        foreach (var set in sets.EnumerateArray())
        {
            if (set.ValueKind != JsonValueKind.Object) continue;
            var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var prop in set.EnumerateObject())
            {
                if (prop.Value.ValueKind == JsonValueKind.String)
                    dict[prop.Name] = prop.Value.GetString() ?? "";
            }
            if (dict.Count > 0)
                result.Add(dict);
        }

        return result.Count > 0 ? result : null;
    }

    private static Dictionary<string, string>? BuildChainProveSubstitutionOverrides(JsonBody body) =>
        ChainProveSubstitutionHelper.FromJsonBody(body);

    private async Task<ChainAnalysisService.AnalyzeOptions> BuildChainAnalyzeOptionsAsync(JsonBody body)
    {
        var thirdParty = await _context.CheckThirdParty();
        return await BuildChainAnalyzeOptionsWithThirdPartyAsync(body, thirdParty);
    }

    private async Task<ChainAnalysisService.AnalyzeOptions> BuildChainAnalyzeOptionsWithThirdPartyAsync(
        JsonBody body, ThirdParty.ThirdPartyResult thirdParty)
    {
        var externalWithoutSri = thirdParty.Resources
            .Where(r => !r.HasSri && r.Type is "script" or "stylesheet")
            .ToList();
        var missingSriUrls = externalWithoutSri
            .Select(r => r.Url)
            .Where(u => !string.IsNullOrWhiteSpace(u))
            .ToList();

        return new ChainAnalysisService.AnalyzeOptions(
            body.GetString("minChainedSeverity")?.Trim().ToLowerInvariant() is var s and ("critical" or "high" or "medium" or "low") ? s : null,
            body.GetBool("includePartial", true),
            _identityStore,
            await _context.GetCurrentUrl(),
            thirdParty.TotalCount,
            externalWithoutSri.Count,
            missingSriUrls);
    }

    private async Task HandlePostSecurityChainAnalyze(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        var chainableFindings = CollectChainableFindingsForSession();

        if (chainableFindings.Count == 0)
        {
            await WriteSuccess(response, ChainAnalysisService.BuildAnalyzePayload(
                new ChainAnalysisResult(),
                "No security findings available. Enable shadow, run auto-scan/parser-probe/cmd-canary, add journal bugs with security tags, or POST /api/security/chain-findings."));
            return;
        }

        var result = ChainAnalysisService.Analyze(_chainCatalog, chainableFindings, await BuildChainAnalyzeOptionsAsync(body));

        await WriteSuccess(response, ChainAnalysisService.BuildAnalyzePayload(result));
    }

    private async Task HandleGetSecurityChainFindings(HttpListenerRequest request, HttpListenerResponse response)
    {
        var findings = CollectChainableFindingsForSession();

        var category = ApiQuery(request)["category"];
        if (!string.IsNullOrEmpty(category))
            findings = findings.Where(f => f.Category.Contains(category, StringComparison.OrdinalIgnoreCase)).ToList();

        await WriteSuccess(response, new
        {
            findings = findings.Select(f => new
            {
                f.Id,
                f.Source,
                f.Category,
                f.Severity,
                f.Title,
                f.Endpoint,
                f.Method,
                f.Evidence
            }),
            count = findings.Count,
            knownCategories = FindingNormalizer.KnownCategories.OrderBy(c => c, StringComparer.OrdinalIgnoreCase).ToList()
        });
    }

    private async Task HandleGetSecurityFindings(HttpListenerRequest request, HttpListenerResponse response)
    {
        var query = ApiQuery(request);
        var host = query["host"];
        if (string.IsNullOrWhiteSpace(host) && query["allHosts"] != "true")
        {
            var pageUrl = await _context.GetCurrentUrl();
            host = SecurityHostScope.ResolveScopeHost(null, pageUrl);
        }

        var export = SecurityFindingsExport.BuildExport(
            _context,
            SessionLogger,
            new SecurityFindingsExport.ExportOptions
            {
                Host = host,
                Category = query["category"],
                MinSeverity = query["severity"] ?? query["minSeverity"],
                MinConfidence = query["minConfidence"] ?? SecurityConfidence.Likely,
                IncludeHygiene = query["includeHygiene"] == "true",
                IncludeShadow = query["includeShadow"] != "false",
                IncludeChain = query["includeChain"] != "false"
            });

        await WriteSuccess(response, export);
    }

    private async Task HandlePostSecurityChainFindings(HttpListenerRequest request, HttpListenerResponse response,
        bool implicitAddPayload = false)
    {
        var body = await ReadJsonBody(request);
        var action = implicitAddPayload ? "add" : (body.GetString("action") ?? "add");

        if (action == "clear")
        {
            _context.ClearManualChainFindings();
            await WriteSuccess(response, new { cleared = true, manualCount = 0 });
            return;
        }

        if (action == "remove")
        {
            var id = body.GetString("id");
            if (string.IsNullOrEmpty(id))
            {
                await WriteError(response, 400, "remove requires non-empty 'id'.");
                return;
            }

            var removed = _context.RemoveManualChainFinding(id);
            await WriteSuccess(response, new { removed, id });
            return;
        }

        if (action != "add")
        {
            await WriteError(response, 400, "Unknown action. Use add, remove, or clear.");
            return;
        }

        var category = body.GetString("category")?.Trim().ToLowerInvariant();
        var title = body.GetString("title")?.Trim();
        if (string.IsNullOrEmpty(category) || string.IsNullOrEmpty(title))
        {
            await WriteError(response, 400, "add requires 'category' and 'title'.");
            return;
        }

        if (!FindingNormalizer.IsKnownCategory(category))
        {
            await WriteError(response, 400,
                $"Unknown category '{category}'. Use GET /api/security/chain-findings to list knownCategories.");
            return;
        }

        var severity = (body.GetString("severity") ?? "medium").Trim().ToLowerInvariant();
        if (severity is not ("critical" or "high" or "medium" or "low" or "info"))
            severity = "medium";

        var rawId = body.GetString("id")?.Trim();
        string idOut;
        if (string.IsNullOrEmpty(rawId))
            idOut = $"manual-{Guid.NewGuid():N}";
        else if (_context.GetManualChainFindingsSnapshot().Exists(f => f.Id == rawId))
        {
            await WriteError(response, 400, $"Manual finding id '{rawId}' already exists. Omit 'id' to auto-assign or choose a unique id.");
            return;
        }
        else
            idOut = rawId;

        var endpoint = body.GetString("endpoint");
        var method = body.GetString("method");
        var parameter = body.GetString("parameter");
        var detail = body.GetString("detail");
        var evidence = body.GetString("evidence");
        var tags = body.GetStringArray("tags");

        var finding = new ChainableFinding
        {
            Id = idOut,
            Source = "manual",
            Category = category,
            Severity = severity,
            Title = title,
            Endpoint = string.IsNullOrWhiteSpace(endpoint) ? null : endpoint.Trim(),
            Method = string.IsNullOrWhiteSpace(method) ? null : method.Trim().ToUpperInvariant(),
            Parameter = string.IsNullOrWhiteSpace(parameter) ? null : parameter.Trim(),
            Detail = string.IsNullOrWhiteSpace(detail) ? null : detail.Trim(),
            Evidence = string.IsNullOrWhiteSpace(evidence) ? null : evidence.Trim(),
            Tags = tags?.Count > 0 ? [.. tags] : ["manual"]
        };

        _context.AddManualChainFinding(finding);
        await WriteSuccess(response, new
        {
            added = finding.Id,
            manualCount = _context.GetManualChainFindingsSnapshot().Count
        });
    }

    private async Task HandleGetSecurityChainPatterns(HttpListenerRequest request, HttpListenerResponse response)
    {
        await WriteSuccess(response, ChainAnalysisService.BuildPatternsPayload(_chainCatalog.GetAll()));
    }

    private async Task HandlePostSecurityChainPatterns(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);

        var action = body.GetString("action") ?? "list";

        if (action is "add" or "remove" && SafeMode)
        {
            await WriteError(response, 403,
                $"Blocked by safe mode: POST /api/security/chain-patterns action={action}. Safe mode allows list/read only.");
            return;
        }

        if (action == "add")
        {
            if (!body.TryGetRoot(out var root))
            {
                await WriteError(response, 400, "Invalid JSON body.");
                return;
            }

            var pattern = ChainPatternParser.TryBuildFromAddPayload(root, out var parseError);
            if (pattern == null)
            {
                await WriteError(response, 400, parseError ?? "Invalid pattern payload.");
                return;
            }

            if (!_chainCatalog.Add(pattern))
            {
                await WriteError(response, 409, $"Pattern id '{pattern.Id}' already exists.");
                return;
            }

            await WriteSuccess(response, new { added = pattern.Id, totalPatterns = _chainCatalog.GetAll().Count });
        }
        else if (action == "remove")
        {
            var id = body.GetString("id");
            if (string.IsNullOrEmpty(id)) { await WriteError(response, 400, "Required: id"); return; }
            var removed = _chainCatalog.Remove(id);
            await WriteSuccess(response, new { removed, id });
        }
        else
        {
            await HandleGetSecurityChainPatterns(request, response);
        }
    }

    #endregion

    #region WebSocket Security Handlers

    private async Task HandleGetWebSocketConnections(HttpListenerRequest request, HttpListenerResponse response)
    {
        var wsManager = _context.ActiveTab.WebSocket;
        var urlFilter = ApiQuery(request)["url"];
        var connections = wsManager.GetConnections(urlFilter: urlFilter);

        await WriteSuccess(response, new
        {
            connections = connections.Select(c => new
            {
                c.ConnectionId,
                c.CdpRequestId,
                c.Url,
                c.State,
                c.Protocol,
                c.FramesSent,
                c.FramesReceived,
                c.BytesSent,
                c.BytesReceived,
                c.CreatedAt,
                c.ClosedAt,
                hasHandshake = c.HandshakeStatus > 0
            }),
            count = connections.Count
        });
    }

    private async Task HandleGetSseConnections(HttpListenerRequest request, HttpListenerResponse response)
    {
        await _context.RefreshOpenSseCaptureFromCdpAsync();
        var mgr = _context.ActiveTab.Sse;
        var urlFilter = ApiQuery(request)["url"];
        var state = ApiQuery(request)["state"];
        var connections = mgr.GetConnections(stateFilter: state, urlFilter: urlFilter);

        await WriteSuccess(response, new
        {
            connections = connections.Select(c => new
            {
                c.ConnectionId,
                c.CdpRequestId,
                c.Url,
                c.Method,
                c.State,
                c.MessagesReceived,
                c.BytesReceived,
                c.CreatedAt,
                c.ClosedAt,
                c.LastEventIdSent,
                c.NetworkEntryId,
                wireBytes = _context.ActiveTab.Sse.GetWireBytes(c.CdpRequestId),
                captureMode = _context.ActiveTab.Sse.DescribeCaptureMode(c.CdpRequestId)
            }),
            count = connections.Count
        });
    }

    private async Task HandleGetSseMessages(HttpListenerRequest request, HttpListenerResponse response)
    {
        await _context.RefreshOpenSseCaptureFromCdpAsync();
        var mgr = _context.ActiveTab.Sse;
        var query = ApiQuery(request);
        int.TryParse(query["connectionId"], out var connId);
        var eventFilter = query["event"];
        int.TryParse(query["limit"], out var limit);
        if (limit <= 0) limit = 100;

        List<SseMessage> messages;
        if (connId > 0)
            messages = mgr.GetMessages(connId, eventNameFilter: eventFilter, last: limit);
        else
        {
            messages = mgr.GetConnections()
                .SelectMany(c => mgr.GetMessages(c.ConnectionId, eventNameFilter: eventFilter, last: limit))
                .OrderByDescending(m => m.Timestamp)
                .Take(limit)
                .ToList();
        }

        await WriteSuccess(response, new
        {
            messages = messages.Select(m => new
            {
                m.MessageId,
                m.ConnectionId,
                m.EventName,
                m.EventId,
                data = m.Data.Length > 2000 ? m.Data[..2000] + "..." : m.Data,
                m.Timestamp
            }),
            count = messages.Count
        });
    }

    private async Task HandlePostSecuritySseAudit(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        var checks = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var s in body?.GetStringArray("checks") ?? [])
            checks.Add(s);
        if (checks.Count == 0)
            checks.Add("all");

        var connId = body?.GetInt("connectionId", 0) ?? 0;
        var options = new SseAuditor.AuditOptions
        {
            ConnectionId = connId > 0 ? connId : null,
            Checks = checks,
            MaxEventsProbe = body?.GetInt("maxEvents", 50) ?? 50,
            MaxMsProbe = body?.GetInt("maxMs", 5000) ?? 5000,
            SafetyMode = SafetyModeExtensions.Parse(body?.GetString("safetyMode")),
            UseCapturedShapeHeaders = body?.GetBool("useCapturedShapeHeaders", true) ?? true
        };

        var result = await _context.RunSseAuditAsync(options, Peers);
        await WriteSuccess(response, result);
    }

    private async Task HandleGetWebSocketMessages(HttpListenerRequest request, HttpListenerResponse response)
    {
        var wsManager = _context.ActiveTab.WebSocket;
        var query = ApiQuery(request);

        int.TryParse(query["connectionId"], out var connId);
        var direction = query["direction"];
        var search = query["search"];
        int.TryParse(query["limit"], out var limit);
        if (limit <= 0) limit = 100;

        List<WebSocketFrame> frames;
        if (connId > 0)
        {
            frames = wsManager.GetFrames(connId, directionFilter: direction, searchText: search, last: limit);
        }
        else
        {
            frames = wsManager.GetConnections()
                .SelectMany(c => wsManager.GetFrames(c.ConnectionId, directionFilter: direction, searchText: search, last: limit))
                .OrderByDescending(f => f.Timestamp)
                .Take(limit)
                .ToList();
        }

        await WriteSuccess(response, new
        {
            frames = frames.Select(f => new
            {
                f.ConnectionId,
                f.Direction,
                f.DataType,
                data = f.Data.Length > 2000 ? f.Data[..2000] + "..." : f.Data,
                f.DataLength,
                f.IsJson,
                f.JsonType,
                f.Timestamp
            }),
            count = frames.Count
        });
    }

    private async Task HandlePostWebSocketSend(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        var connectionId = body.GetInt("connectionId", 0);
        var message = body.GetString("message");
        if (connectionId <= 0 || string.IsNullOrEmpty(message))
        {
            await WriteError(response, 400, "Required: connectionId (int), message (string).");
            return;
        }

        var result = await WebSocketJsBridge.SendAsync(_context, connectionId, message);
        if (!result.Ok)
        {
            await WriteError(response, 502, result.Error ?? "WebSocket send failed.");
            return;
        }

        await WriteSuccess(response, new { ok = true, hookId = result.HookId, url = result.Url });
    }

    private async Task HandlePostWebSocketClose(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        var connectionId = body.GetInt("connectionId", 0);
        if (connectionId <= 0)
        {
            await WriteError(response, 400, "Required: connectionId (int).");
            return;
        }

        var code = body.HasProperty("code") ? body.GetInt("code") : (int?)null;
        var reason = body.GetString("reason");
        var result = await WebSocketJsBridge.CloseAsync(_context, connectionId, code, reason);
        if (!result.Ok)
        {
            await WriteError(response, 502, result.Error ?? "WebSocket close failed.");
            return;
        }

        await WriteSuccess(response, new { ok = true, hookId = result.HookId });
    }

    private async Task HandlePostSecurityWebSocketAuthz(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        var peers = new List<string>();
        var peer = body.GetString("peer");
        if (!string.IsNullOrWhiteSpace(peer)) peers.Add(peer);

        var connectionId = body.GetInt("connectionId", 0);
        int? frameId = body.HasProperty("frameId") ? body.GetInt("frameId") : null;
        if (frameId <= 0) frameId = null;

        var report = await new WebSocketAuthzTester(_context, Peers).RunAsync(new WebSocketAuthzRequest
        {
            ConnectionId = connectionId,
            FrameId = frameId,
            Message = body.GetString("message"),
            Peers = peers.Count > 0 ? peers : null,
            ResponseWaitMs = body.GetInt("responseWaitMs", 800),
            SafetyMode = SafetyGate.Resolve(body)
        });

        if (!report.Ok)
        {
            await WriteError(response, 400, report.Error ?? "WebSocket authz check failed.");
            return;
        }

        WebSocketAuthzRecorder.Record(_context, report);
        await WriteSuccess(response, report);
    }

    private async Task HandlePostSecurityWebSocketAudit(HttpListenerRequest request, HttpListenerResponse response)
    {
        var wsManager = _context.ActiveTab.WebSocket;
        var connections = wsManager.GetConnections();

        if (connections.Count == 0)
        {
            await WriteSuccess(response, new
            {
                findings = Array.Empty<object>(),
                message = "No WebSocket connections found. Navigate to a page that uses WebSockets first."
            });
            return;
        }

        var body = await ReadJsonBody(request);
        int.TryParse(body?.GetString("connectionId"), out var targetConnId);
        var includeActiveMessageProbes = body?.GetBool("includeActiveMessageProbes") == true;

        var allResults = new List<WebSocketAuditor.AuditResult>();
        var targetConnections = targetConnId > 0
            ? connections.Where(c => c.ConnectionId == targetConnId).ToList()
            : connections;

        var pageHandlerFindings = await WebSocketPageHandlerAnalyzer.AnalyzeAsync(_context);
        var activeProbeNotes = new List<string>();

        foreach (var conn in targetConnections)
        {
            var result = WebSocketAuditor.Audit(conn, wsManager);
            if (pageHandlerFindings.Count > 0)
                result.Findings.AddRange(pageHandlerFindings);
            allResults.Add(result);
        }

        if (includeActiveMessageProbes)
        {
            string? gateMessage = body == null
                ? "Request body required for active WebSocket message probes (include safetyMode: active)."
                : SafetyGate.RequireActive(body, "WebSocket message probes send injection payloads on open connections")?.Message;
            if (gateMessage != null)
            {
                activeProbeNotes.Add(gateMessage);
            }
            else
            {
                var fuzzer = new WebSocketFuzzer(_context, (_, _) => { });
                var fuzz = await fuzzer.RunAsync(new WebSocketFuzzOptions
                {
                    ConnectionId = targetConnId > 0 ? targetConnId : null,
                    MaxConnections = 2,
                    MaxPayloadsPerSet = 3,
                    PayloadSets = ["ws-code-exec-oracle"],
                    IncludeMessageTypeMatrix = true,
                    MaxMessageTypes = 6,
                    ResponseWaitMs = 600
                });
                if (fuzz.Findings.Count > 0)
                {
                    foreach (var conn in targetConnections)
                    {
                        var result = allResults.First(r => r.ConnectionId == conn.ConnectionId);
                        foreach (var ff in fuzz.Findings.Where(f => f.ConnectionId == conn.ConnectionId))
                        {
                            result.Findings.Add(new WebSocketAuditFinding
                            {
                                Check = "active-message-probe",
                                Severity = ff.Severity,
                                Title = ff.Indicator switch
                                {
                                    "ws-code-execution-confirmed" => "WebSocket inbound message executed attacker JavaScript",
                                    _ => "WebSocket active message probe finding"
                                },
                                Detail = ff.Detail,
                                Evidence = ff.ReceivedSnippet ?? ff.MessageSent,
                                Remediation = "Remove eval/Function on WebSocket payloads; enforce server-side authz on message types and fields."
                            });
                        }
                    }
                }

                activeProbeNotes.Add(fuzz.Message);
            }
        }

        var findingItems = allResults
            .SelectMany(r => r.Findings.Select(f => (Finding: f, ConnectionUrl: r.Url, ConnectionId: r.ConnectionId)))
            .ToList();
        var aggregatedFindings = WebSocketAuditor.AggregateFindings(findingItems);
        var rawFindingCount = findingItems.Count;

        // Push deduplicated findings to shadow mode if enabled
        var shadow = _context.SecurityShadow;
        if (shadow != null)
        {
            foreach (var finding in aggregatedFindings)
            {
                var detail = finding.Occurrences > 1
                    ? $"{finding.Detail} (seen on {finding.Occurrences} connection(s))"
                    : finding.Detail;

                shadow.AddCustomFinding(
                    finding.Severity switch
                    {
                        "critical" => Severity.Critical,
                        "high" => Severity.High,
                        "medium" => Severity.Medium,
                        _ => Severity.Low
                    },
                    finding.Title,
                    detail,
                    finding.Remediation,
                    "websocket-audit",
                    finding.NormalizedUrl
                );
            }
        }

        await WriteSuccess(response, new
        {
            connectionsAudited = targetConnections.Count,
            findings = aggregatedFindings.Select(f => new
            {
                f.Check,
                f.Severity,
                f.Title,
                f.Detail,
                f.Evidence,
                f.Remediation,
                f.Occurrences,
                normalizedUrl = f.NormalizedUrl,
                seenConnectionUrls = f.SeenConnectionUrls.Count > 0 ? f.SeenConnectionUrls : null,
                connectionIds = f.ConnectionIds.Count > 0 ? f.ConnectionIds : null
            }),
            results = allResults.Select(r => new
            {
                r.ConnectionId,
                r.Url,
                normalizedUrl = WebSocketAuditor.NormalizeConnectionUrl(r.Url),
                findings = r.Findings.Select(f => new
                {
                    f.Check,
                    f.Severity,
                    f.Title,
                    f.Detail,
                    f.Evidence,
                    f.Remediation
                }),
                r.MessageTypeDiscovery,
                r.ElapsedMs
            }),
            totalFindings = aggregatedFindings.Count,
            rawFindingCount,
            bySeverity = aggregatedFindings.GroupBy(f => f.Severity)
                .ToDictionary(g => g.Key, g => g.Count()),
            activeProbeNotes = activeProbeNotes.Count > 0 ? activeProbeNotes : null
        });
    }

    private async Task HandlePostSecurityWebSocketFuzz(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);

        var gateError = SafetyGate.RequireActive(body, "WebSocket fuzz sends injection payloads on active connections");
        if (gateError != null)
        {
            await WriteError(response, 400, gateError);
            return;
        }

        int? connectionId = body.HasProperty("connectionId") ? body.GetInt("connectionId") : null;
        if (connectionId <= 0) connectionId = null;

        var options = new WebSocketFuzzOptions
        {
            ConnectionId = connectionId,
            PayloadSets = body.GetStringList("payloadSets") ?? body.GetStringArray("payloadSets")?.ToList(),
            MaxConnections = body.GetInt("maxConnections", 3),
            MaxPayloadsPerSet = body.GetInt("maxPayloadsPerSet", 8),
            MaxMessageTypes = body.GetInt("maxMessageTypes", 6),
            ResponseWaitMs = body.GetInt("responseWaitMs", 500),
            WrapJsonPayloads = body.GetBool("wrapJsonPayloads", true),
            IncludeMessageTypeMatrix = body.GetBool("includeMessageTypeMatrix", true),
        };

        try
        {
            var result = await _context.RunWebSocketFuzz(options);
            await WriteSuccess(response, new
            {
                message = result.Message,
                skippedReason = result.SkippedReason,
                connectionsFuzzed = result.ConnectionsFuzzed,
                payloadsSent = result.PayloadsSent,
                elapsedMs = result.ElapsedMs,
                findings = result.Findings
            });
        }
        catch (InvalidOperationException ex)
        {
            await WriteError(response, 400, ex.Message);
        }
    }

    private async Task HandlePostSecurityCswshTest(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);

        var targetUrl = body.GetString("url") ?? body.GetString("targetUrl");
        if (string.IsNullOrEmpty(targetUrl))
        {
            // Auto-detect from active WebSocket connections
            var wsManager = _context.ActiveTab.WebSocket;
            var activeConn = wsManager.GetConnections().FirstOrDefault(c => c.State == "open");
            if (activeConn != null)
                targetUrl = activeConn.Url;
        }

        if (string.IsNullOrEmpty(targetUrl))
        {
            await WriteError(response, 400,
                "Required: url (WebSocket URL to test, e.g. wss://example.com/ws). " +
                "Or navigate to a page with active WebSocket connections for auto-detection.");
            return;
        }

        // Convert http(s) to ws(s) if needed
        if (targetUrl.StartsWith("http://")) targetUrl = "ws://" + targetUrl[7..];
        else if (targetUrl.StartsWith("https://")) targetUrl = "wss://" + targetUrl[8..];

        var browserProof = body.GetBool("browserProof", true);
        var attackerOrigin = body.GetString("origin") ?? body.GetString("attackerOrigin")
            ?? PostMessageProbeBuilder.AttackerOrigin;

        var preset = body.GetString("preset");
        string? sendAfterConnect = body.GetString("sendAfterConnect");
        if (sendAfterConnect == null && preset?.Equals("graphql-ws", StringComparison.OrdinalIgnoreCase) == true)
            sendAfterConnect = WebSocketJsBridge.GraphqlWsConnectionInit(body.GetString("graphqlPayload"));

        // Get cookies from current page if not explicitly provided
        Dictionary<string, string>? cookies = null;
        var cookieBody = body.GetString("cookies");
        if (cookieBody != null)
        {
            try
            {
                cookies = JsonSerializer.Deserialize<Dictionary<string, string>>(cookieBody);
            }
            catch { /* ignore parse errors */ }
        }

        var options = new CswshTester.CswshOptions
        {
            TargetUrl = targetUrl,
            AttackerOrigin = attackerOrigin,
            Cookies = cookies,
            Protocol = body.GetString("protocol"),
            SendAfterConnect = sendAfterConnect,
            MonitorMs = body.GetInt("monitorMs", 5000),
            TimeoutMs = body.GetInt("timeoutMs", 10000)
        };

        var screening = await CswshTester.TestAsync(options);

        CswshBrowserProver.BrowserProofResult? browser = null;
        if (browserProof)
        {
            browser = await CswshBrowserProver.TestAsync(_context, new CswshBrowserProver.BrowserProofOptions
            {
                TargetUrl = targetUrl,
                AttackerOrigin = attackerOrigin,
                Protocol = options.Protocol,
                SendAfterConnect = sendAfterConnect,
                MonitorMs = options.MonitorMs
            });
        }

        var vulnerable = browser?.Vulnerable == true
            || (browser == null && screening.Vulnerable);
        var severity = browser?.Vulnerable == true
            ? browser.Severity
            : screening.Severity;
        var detail = browser?.Vulnerable == true
            ? browser.Detail
            : browser != null && screening.Vulnerable && !browser.Vulnerable
                ? $"Raw TCP screening suggested CSWSH (HTTP {screening.HandshakeStatus}) but browser cross-site WebSocket did not open — prefer browser verdict. {browser.Detail}"
                : screening.Detail;

        // Push to shadow mode if vulnerable (browser-first when available)
        if (vulnerable && _context.SecurityShadow != null)
        {
            _context.SecurityShadow.AddCustomFinding(
                severity == "critical" ? Severity.Critical : Severity.High,
                "Cross-Site WebSocket Hijacking (CSWSH)",
                detail,
                "Validate the Origin header on WebSocket upgrade requests. Reject connections from untrusted origins.",
                browser?.Vulnerable == true ? "cswsh-browser" : "cswsh-test"
            );
        }

        await WriteSuccess(response, new
        {
            targetUrl = screening.TargetUrl,
            testedOrigin = screening.TestedOrigin,
            vulnerable,
            severity,
            detail,
            handshakeStatus = screening.HandshakeStatus,
            receivedMessages = browser?.ReceivedMessages.Count > 0 ? browser.ReceivedMessages : screening.ReceivedMessages,
            evidence = screening.Evidence,
            elapsedMs = screening.ElapsedMs + (browser?.ElapsedMs ?? 0),
            proofMode = browser?.Vulnerable == true ? "browser" : browser != null ? "browser+screening" : "screening",
            screening = new
            {
                screening.Vulnerable,
                screening.HandshakeStatus,
                screening.TestedOrigin,
                screening.Detail,
                note = "Raw TCP + manual Cookie header — may differ from WebView2 cross-site cookie rules."
            },
            browser = browser == null ? null : new
            {
                browser.AttackerOrigin,
                browser.HandshakeAttempted,
                browser.ConnectionOpened,
                browser.Vulnerable,
                browser.Severity,
                browser.Detail,
                browser.ReceivedMessages,
                browser.ElapsedMs
            },
            browserModel = XsLeakBrowserModel.ForRun(attackerOrigin, "cross-site").ToApiObject()
        });
    }

    private async Task HandlePostSecuritySubdomainTakeover(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        var result = await Security.SubdomainTakeoverChecker.RunAsync(_context,
            new Security.SubdomainTakeoverChecker.SubdomainTakeoverOptions
            {
                MaxHostnames = body.GetInt("maxHostnames", 20),
                TimeoutMs = body.GetInt("timeoutMs", 15000),
                RegisterChainFindings = body.GetBool("registerChainFindings", true)
            });
        await WriteSuccess(response, result);
    }

    #endregion

    #region Orchestration API

    private async Task<bool> TryRouteOrchestrateAsync(
        string path, string method, HttpListenerRequest request, HttpListenerResponse response)
    {
        if (path == "/api/orchestrate/playbooks" && method == "GET")
        {
            await WriteSuccess(response, _playbookRegistry.GetCatalog());
            return true;
        }

        if (path == "/api/vpx/render" && method == "POST")
        {
            await HandlePostVpxRender(request, response);
            return true;
        }

        if (!path.StartsWith("/api/orchestrate/")) return false;

        var tail = path["/api/orchestrate/".Length..];

        if (tail.StartsWith("dry-run/") && method == "POST")
        {
            var playbookId = tail["dry-run/".Length..];
            await HandlePostOrchestrateDryRun(playbookId, request, response);
            return true;
        }

        if (tail.StartsWith("runs/", StringComparison.OrdinalIgnoreCase))
        {
            var runId = tail["runs/".Length..].Trim('/');
            if (string.IsNullOrEmpty(runId))
            {
                await WriteError(response, 400, "Missing run id. Poll GET /api/orchestrate/runs/{runId}.");
                return true;
            }

            if (method == "GET")
            {
                await HandleGetOrchestrateRun(response, runId);
                return true;
            }

            await WriteError(response, 405, "Use GET /api/orchestrate/runs/{runId} to poll an async playbook run.");
            return true;
        }

        if (method == "POST")
        {
            await HandlePostOrchestrate(tail, request, response);
            return true;
        }

        return false;
    }

    private async Task HandlePostOrchestrate(string playbookId, HttpListenerRequest request, HttpListenerResponse response)
    {
        var playbook = _playbookRegistry.Get(playbookId);
        if (playbook == null)
        {
            await WriteError(response, 404,
                $"Unknown playbook: '{playbookId}'. Use GET /api/orchestrate/playbooks for the catalog.");
            return;
        }

        var body = await ReadJsonBody(request);
        var playbookRequest = ParsePlaybookRequest(body);

        if (body.GetBool("async", false))
        {
            var started = TryStartAsyncOrchestrateRun(playbook, playbookRequest, out var poll);
            await WriteJsonResponse(response, 202, new Dictionary<string, object?>
            {
                ["success"] = true,
                ["activeTab"] = _context.GetActiveTabContext(),
                ["data"] = poll
            });
            return;
        }

        var runner = new PlaybookRunner(_context, _identityStore, _chainCatalog, SessionLogger, Peers,
            scannerInvoker: CreateScannerInvoker());
        try
        {
            var result = await runner.RunAsync(playbook, playbookRequest, _context.OperationCancellation);
            await WriteSuccess(response, SerializePlaybookResponse(result));
        }
        catch (OperationCanceledException)
        {
            await WriteError(response, 499, "Playbook execution was cancelled.");
        }
    }

    private async Task HandleGetOrchestrateRun(HttpListenerResponse response, string runId)
    {
        if (!_playbookRunStore.TryGet(runId, out var entry) || entry == null)
        {
            await WriteError(response, 404, $"Unknown orchestrate run '{runId}'.");
            return;
        }

        await WriteSuccess(response, entry.ToPollResponse());
    }

    private bool TryStartAsyncOrchestrateRun(IPlaybook playbook, PlaybookRequest playbookRequest, out object poll)
    {
        var runId = Guid.NewGuid().ToString("N")[..12];
        var entry = _playbookRunStore.Create(runId, playbook.Id);
        poll = entry.ToPollResponse();
        _ = Task.Run(() => RunOrchestrateRunInBackgroundAsync(entry, playbook, playbookRequest));
        return true;
    }

    private async Task RunOrchestrateRunInBackgroundAsync(
        PlaybookRunStore.Entry entry,
        IPlaybook playbook,
        PlaybookRequest playbookRequest)
    {
        SemaphoreSlim gateLease;
        lock (_gateLock)
            gateLease = _gate;

        if (!await gateLease.WaitAsync(TimeSpan.FromHours(2)))
        {
            entry.Fail("Timed out waiting for the browser gate (another operation held it too long).");
            return;
        }

        lock (_gateLock)
            _activeGateLease = gateLease;

        var runCts = entry.CreateLinkedCancellation(_cts.Token);
        _operationCts = runCts;
        _currentOperation = $"PLAYBOOK {entry.PlaybookId} (run {entry.RunId})";
        _context.OperationCancellation = runCts.Token;
        if (_sessionLogger != null) _sessionLogger.SuppressGuiActions = true;
        MirrorController?.BeginApiSuppress();
        _context.IsAgentAutomation = true;

        try
        {
            entry.MarkRunning();
            var progress = new PlaybookRunStore.ProgressReporter(_playbookRunStore, entry.RunId);
            var runner = new PlaybookRunner(_context, _identityStore, _chainCatalog, SessionLogger, Peers,
                scannerInvoker: CreateScannerInvoker());
            var result = await runner.RunAsync(
                playbook, playbookRequest, runCts.Token, entry.RunId, progress);
            entry.Complete(SerializePlaybookResponse(result));
        }
        catch (OperationCanceledException)
        {
            if (entry.Status is "queued" or "running")
                entry.Fail("Playbook execution was cancelled.");
        }
        catch (Exception ex)
        {
            entry.Fail(ex.Message);
        }
        finally
        {
            _context.IsAgentAutomation = false;
            if (_sessionLogger != null) _sessionLogger.SuppressGuiActions = false;
            MirrorController?.EndApiSuppress();
            _currentOperation = null;
            _operationCts = null;
            _context.OperationCancellation = CancellationToken.None;
            runCts.Dispose();
            gateLease.Release();
            lock (_gateLock)
            {
                if (_activeGateLease == gateLease)
                    _activeGateLease = null;
            }
        }
    }

    private async Task HandlePostOrchestrateDryRun(string playbookId, HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        await WriteSuccess(response, await BuildOrchestrateDryRunAsync(playbookId, body));
    }

    internal Task<object> BuildOrchestratePlaybooksAsync() =>
        Task.FromResult<object>(_playbookRegistry.GetCatalog());

    internal Task<object> BuildOrchestratePlaybooksForMcpAsync(JsonBody _) =>
        BuildOrchestratePlaybooksAsync();

    internal async Task<object> BuildOrchestrateDryRunAsync(string playbookId, JsonBody body)
    {
        var playbook = _playbookRegistry.Get(playbookId);
        if (playbook == null)
            throw new ApiCommandException(404,
                $"Unknown playbook: '{playbookId}'. Use GET /api/orchestrate/playbooks for the catalog.");

        var playbookRequest = ParsePlaybookRequest(body);
        var runner = new PlaybookRunner(_context, _identityStore, _chainCatalog, SessionLogger, Peers);
        return await runner.DryRunAsync(playbook, playbookRequest);
    }

    internal async Task<object> BuildOrchestrateRunAsync(JsonBody body)
    {
        var playbookId = body.GetString("playbookId") ?? body.GetString("playbook");
        if (string.IsNullOrWhiteSpace(playbookId))
            throw new ApiCommandException(400, "playbookId is required.");

        var playbook = _playbookRegistry.Get(playbookId);
        if (playbook == null)
            throw new ApiCommandException(404,
                $"Unknown playbook: '{playbookId}'. Use GET /api/orchestrate/playbooks for the catalog.");

        var playbookRequest = ParsePlaybookRequest(body);
        if (body.GetBool("async", false))
        {
            TryStartAsyncOrchestrateRun(playbook, playbookRequest, out var poll);
            return poll;
        }

        var runner = new PlaybookRunner(_context, _identityStore, _chainCatalog, SessionLogger, Peers,
            scannerInvoker: CreateScannerInvoker());
        try
        {
            var result = await runner.RunAsync(playbook, playbookRequest, _context.OperationCancellation);
            return SerializePlaybookResponse(result);
        }
        catch (OperationCanceledException)
        {
            throw new ApiCommandException(499, "Playbook execution was cancelled.");
        }
    }

    internal async Task<object> BuildOrchestrateDryRunFromBodyAsync(JsonBody body)
    {
        var playbookId = body.GetString("playbookId") ?? body.GetString("playbook");
        if (string.IsNullOrWhiteSpace(playbookId))
            throw new ApiCommandException(400, "playbookId is required.");
        return await BuildOrchestrateDryRunAsync(playbookId, body);
    }

    /// <summary>
    /// Creates a scanner invoker delegate for ChainCompleteService that calls
    /// local scanner endpoints via HTTP loopback.
    /// </summary>
    private Security.ChainEngine.ChainCompleteService.ScannerInvoker CreateScannerInvoker()
    {
        var port = _port;
        var apiKey = _apiKey;
        return async (method, endpoint, body, timeoutMs) =>
        {
            using var client = new HttpClient { Timeout = TimeSpan.FromMilliseconds(timeoutMs) };
            var url = $"http://localhost:{port}{endpoint}";
            var request = new HttpRequestMessage(new HttpMethod(method), url);
            if (!string.IsNullOrEmpty(apiKey))
                request.Headers.Add("Authorization", $"Bearer {apiKey}");
            if (!string.IsNullOrEmpty(body))
                request.Content = new StringContent(body, System.Text.Encoding.UTF8, "application/json");

            var response = await client.SendAsync(request);
            return await response.Content.ReadAsStringAsync();
        };
    }

    private async Task HandlePostVpxRender(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        var format = (body.GetString("format") ?? "markdown").ToLowerInvariant();

        var documents = new List<object>();
        var rawDocuments = body.GetRawJson("documents");
        if (!string.IsNullOrEmpty(rawDocuments))
        {
            try
            {
                using var docsJson = JsonDocument.Parse(rawDocuments);
                if (docsJson.RootElement.ValueKind == JsonValueKind.Array)
                {
                    foreach (var item in docsJson.RootElement.EnumerateArray())
                    {
                        if (item.ValueKind != JsonValueKind.Object) continue;
                        documents.Add(System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, object?>>(
                            item.GetRawText(),
                            new System.Text.Json.JsonSerializerOptions { PropertyNameCaseInsensitive = true })!);
                    }
                }
            }
            catch
            {
                await WriteError(response, 400, "Invalid VPX document in 'documents' array.");
                return;
            }
        }

        if (documents.Count == 0)
        {
            var rawVpx = body.GetRawJson("vpx");
            if (rawVpx == null)
            {
                await WriteError(response, 400, "Missing required 'vpx' property (or 'documents' array) containing VPX data.");
                return;
            }

            try
            {
                documents.Add(System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, object?>>(rawVpx,
                    new System.Text.Json.JsonSerializerOptions { PropertyNameCaseInsensitive = true })!);
            }
            catch
            {
                await WriteError(response, 400, "Invalid VPX document: could not parse as JSON object.");
                return;
            }
        }

        var vpxDoc = documents.Count == 1
            ? documents[0]
            : VpxRenderer.MergeDocuments(documents);

        var playbookTitle = body.GetString("playbookTitle") ?? "Security Assessment";
        var suppressedCount = body.GetInt("suppressedCount", 0);
        var playbookId = body.GetString("playbookId") ?? "trowser";

        object result = format switch
        {
            "vpx-compact" => VpxRenderer.ToCompact(vpxDoc),
            "vpx-summary" => VpxRenderer.ToSummary(vpxDoc),
            "sarif" => VpxRenderer.ToSarif(vpxDoc, playbookId, suppressedCount),
            "markdown" => VpxRenderer.ToMarkdown(vpxDoc, playbookTitle, suppressedCount),
            _ => VpxRenderer.ToMarkdown(vpxDoc, playbookTitle, suppressedCount)
        };

        await WriteSuccess(response, result);
    }

    private static PlaybookRequest ParsePlaybookRequest(JsonBody body)
    {
        var scope = ParsePlaybookScope(body);

        var budgetObj = new JsonBody(body.GetObject("budget"));
        var budget = new BudgetLimits
        {
            MaxSeconds = budgetObj.GetInt("maxSeconds", 120),
            MaxRequests = budgetObj.GetInt("maxRequests", 800),
            Adaptive = budgetObj.GetBool("adaptive", false),
            HonorRequested = budgetObj.GetBool("honorRequested", true)
        };

        return new PlaybookRequest
        {
            Scope = scope,
            IncludeCrawl = body.HasProperty("crawl")
                ? body.GetBool("crawl")
                : body.GetBool("includeCrawl", false),
            SafetyMode = SafetyModeExtensions.Parse(body.GetString("safetyMode")),
            Depth = PlaybookDepthProfile.Parse(body.GetString("depth")),
            PayloadProfile = PayloadProfileExtensions.Parse(body.GetString("payloadProfile")),
            Budget = budget,
            Evidence = body.GetString("evidence") ?? "auto",
            EmitSuggestedProofs = body.GetBool("emitSuggestedProofs", true),
            Tags = body.GetStringList("tags") ?? [],
            Format = body.GetString("format") ?? "vpx-compact",
            EmbedVpx = body.GetBool("embedVpx", false),
            PersistVpx = body.GetBool("persistVpx", true),
            ResumeRunId = body.GetString("resumeRunId")
        };
    }

    private static PlaybookScope ParsePlaybookScope(JsonBody body)
    {
        var scopeBody = new JsonBody(body.GetObject("scope"));
        var targetBody = new JsonBody(scopeBody.GetObject("target"));
        return new PlaybookScope
        {
            Host = scopeBody.GetString("host") ?? body.GetString("host"),
            IncludePaths = scopeBody.GetStringList("includePaths") ?? [],
            ExcludePaths = scopeBody.GetStringList("excludePaths") ?? [],
            ExcludeUrlPatterns = scopeBody.GetStringList("excludeUrlPatterns") ?? [],
            ExcludeLogout = scopeBody.GetBool("excludeLogout", true),
            Identities = scopeBody.GetStringList("identities") ?? [],
            TargetUrl = scopeBody.GetString("targetUrl")
                ?? targetBody.GetString("url"),
            TargetMethod = scopeBody.GetString("targetMethod")
                ?? targetBody.GetString("method")
        };
    }

    private static object SerializePlaybookResponse(PlaybookResponse r)
    {
        // Always emit findings[] + severityHistogram (docs / LLM triage contract).
        // Manual dictionary serialization previously omitted them — markdown/VPX had hits while
        // top-level findings stayed empty/missing for agents.
        var obj = new Dictionary<string, object?>
        {
            ["playbookId"] = r.PlaybookId,
            ["runId"] = r.RunId,
            ["scope"] = r.Scope,
            ["safetyMode"] = r.SafetyMode,
            ["depth"] = r.Depth,
            ["startedAt"] = r.StartedAt,
            ["finishedAt"] = r.FinishedAt,
            ["stepsExecuted"] = r.StepsExecuted,
            ["budgetUsed"] = r.BudgetUsed,
            ["warnings"] = r.Warnings,
            ["assertionsAdded"] = r.AssertionsAdded,
            ["nextActions"] = r.NextActions,
            ["findings"] = r.Findings ?? [],
            ["severityHistogram"] = r.SeverityHistogram ?? new Dictionary<string, int>
            {
                ["critical"] = 0,
                ["high"] = 0,
                ["medium"] = 0,
                ["low"] = 0,
                ["info"] = 0
            },
            ["coverageIncomplete"] = r.CoverageIncomplete
        };

        if (r.AgentInstruction != null)
            obj["agentInstruction"] = r.AgentInstruction;

        if (r.EstimatedCompletionSeconds.HasValue)
            obj["estimatedCompletionSeconds"] = r.EstimatedCompletionSeconds.Value;
        if (r.SuggestedClientTimeoutSeconds.HasValue)
            obj["suggestedClientTimeoutSeconds"] = r.SuggestedClientTimeoutSeconds.Value;

        if (r.SuppressedFindings is { Count: > 0 })
        {
            obj["suppressedFindings"] = r.SuppressedFindings.Select(s => new Dictionary<string, object?>
            {
                ["id"] = s.Id,
                ["title"] = s.Title,
                ["category"] = s.Category,
                ["severity"] = s.Severity,
                ["endpoint"] = s.Endpoint,
                ["reason"] = "cross-playbook-deduplication"
            }).ToList();
        }

        if (r.Vpx != null) obj["vpx"] = r.Vpx;
        if (r.Markdown != null) obj["markdown"] = r.Markdown;
        if (r.Sarif != null) obj["sarif"] = r.Sarif;
        if (r.VpxAttached != null) obj["vpxAttached"] = r.VpxAttached;
        if (r.CorrelatedChains != null) obj["correlatedChains"] = r.CorrelatedChains;

        return obj;
    }

    #endregion
}
