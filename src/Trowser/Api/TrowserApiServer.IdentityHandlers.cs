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
using Trowser.Security.WebSocket;
using Trowser.Seo;
using Trowser.SessionLog;

namespace Trowser.Api;

public partial class TrowserApiServer
{
    #region SSL Manager Handlers

    private async Task HandleGetSslCertificates(HttpListenerResponse response)
    {
        var sslManager = _context.SslManager;
        if (sslManager == null)
        {
            await WriteError(response, 503, "SSL Manager not available.");
            return;
        }

        var certs = sslManager.ListCertificates();
        await WriteSuccess(response, new
        {
            certificates = certs.Select(c => new
            {
                c.Alias,
                c.OriginalFileName,
                c.Thumbprint,
                c.Subject,
                c.Issuer,
                notAfter = c.NotAfter.ToString("o"),
                notBefore = c.NotBefore.ToString("o"),
                addedAt = c.AddedAt.ToString("o"),
                c.IsActive,
                c.IsExpired
            }),
            activeAlias = sslManager.ActiveAlias,
            count = certs.Count
        });
    }

    private async Task HandlePostSslCertificate(HttpListenerRequest request, HttpListenerResponse response)
    {
        var sslManager = _context.SslManager;
        if (sslManager == null)
        {
            await WriteError(response, 503, "SSL Manager not available.");
            return;
        }

        try
        {
            var body = await ReadJsonBody(request);
            var filePath = body.GetString("filePath");
            var password = body.GetString("password") ?? "";
            var alias = body.GetString("alias");

            if (string.IsNullOrWhiteSpace(filePath))
            {
                await WriteError(response, 400, "Missing required field: filePath");
                return;
            }

            if (!ExportPathGuard.TryResolveRead(filePath, out var certPath, out var pathError))
            {
                await WriteError(response, 400, pathError ?? "Certificate path rejected.");
                return;
            }

            var info = sslManager.AddCertificate(certPath, password, alias);
            await WriteSuccess(response, new
            {
                info.Alias,
                info.OriginalFileName,
                info.Thumbprint,
                info.Subject,
                info.Issuer,
                notAfter = info.NotAfter.ToString("o"),
                notBefore = info.NotBefore.ToString("o"),
                info.IsActive,
                info.IsExpired
            });
        }
        catch (Exception ex)
        {
            await WriteError(response, 400, ex.Message);
        }
    }

    private async Task HandleDeleteSslCertificate(HttpListenerRequest request, HttpListenerResponse response)
    {
        var sslManager = _context.SslManager;
        if (sslManager == null)
        {
            await WriteError(response, 503, "SSL Manager not available.");
            return;
        }

        try
        {
            var body = await ReadJsonBody(request);
            var alias = body.GetString("alias");

            if (string.IsNullOrWhiteSpace(alias))
            {
                await WriteError(response, 400, "Missing required field: alias");
                return;
            }

            var removed = sslManager.RemoveCertificate(alias);
            if (!removed)
            {
                await WriteError(response, 404, $"No certificate found with alias '{alias}'.");
                return;
            }

            await WriteSuccess(response, new { removed = true, alias });
        }
        catch (Exception ex)
        {
            await WriteError(response, 400, ex.Message);
        }
    }

    private async Task HandleGetSslActive(HttpListenerResponse response)
    {
        var sslManager = _context.SslManager;
        if (sslManager == null)
        {
            await WriteError(response, 503, "SSL Manager not available.");
            return;
        }

        var active = sslManager.GetActive();
        if (active == null)
        {
            await WriteSuccess(response, new { active = (object?)null, message = "No active client certificate." });
            return;
        }

        await WriteSuccess(response, new
        {
            active = new
            {
                active.Alias,
                active.OriginalFileName,
                active.Thumbprint,
                active.Subject,
                active.Issuer,
                notAfter = active.NotAfter.ToString("o"),
                notBefore = active.NotBefore.ToString("o"),
                active.IsExpired
            }
        });
    }

    private async Task HandlePostSslActive(HttpListenerRequest request, HttpListenerResponse response)
    {
        var sslManager = _context.SslManager;
        if (sslManager == null)
        {
            await WriteError(response, 503, "SSL Manager not available.");
            return;
        }

        try
        {
            var body = await ReadJsonBody(request);
            var alias = body.GetString("alias");

            var result = sslManager.SetActive(alias);
            if (result == null)
            {
                await WriteSuccess(response, new { active = (object?)null, message = "Active certificate cleared." });
            }
            else
            {
                await WriteSuccess(response, new
                {
                    active = new
                    {
                        result.Alias,
                        result.Thumbprint,
                        result.Subject,
                        result.Issuer,
                        notAfter = result.NotAfter.ToString("o")
                    }
                });
            }
        }
        catch (Exception ex)
        {
            await WriteError(response, 400, ex.Message);
        }
    }

    #endregion

    #region Peer Handlers

    private async Task HandleGetPeers(HttpListenerResponse response)
    {
        var peers = Peers.GetAll();
        var results = new List<object>();

        foreach (var peer in peers)
        {
            var (alive, sessionName, _, _) = await Peers.PingAsync(peer.Name);
            results.Add(new
            {
                name = peer.Name,
                baseUrl = peer.BaseUrl,
                alive,
                sessionName
            });
        }

        await WriteSuccess(response, new { peers = results, count = results.Count });
    }

    private async Task HandlePostPeerSpawn(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        int? port = null;
        if (body.HasProperty("port"))
        {
            var p = body.GetInt("port", 0);
            if (p > 0)
                port = p;
        }

        var spawnRequest = new Trowser.Peers.PeerSpawnRequest
        {
            Name = body.GetString("name"),
            Session = body.GetString("session"),
            ApiKey = body.GetString("apiKey"),
            Port = port,
            Ephemeral = !body.HasProperty("ephemeral") || body.GetBool("ephemeral"),
            Register = !body.HasProperty("register") || body.GetBool("register")
        };

        var result = await Trowser.Peers.PeerSpawnService.SpawnAsync(_context, Peers, spawnRequest);
        if (!result.Success)
        {
            await WriteError(response, 502, result.Error ?? "Peer spawn failed.");
            return;
        }

        await WriteSuccess(response, new
        {
            spawned = true,
            name = result.Name,
            baseUrl = result.BaseUrl,
            apiKey = result.ApiKey,
            sessionName = result.SessionName,
            alive = result.Alive
        });
    }

    private async Task HandlePostPeerStop(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        var name = body.GetString("name");
        if (string.IsNullOrWhiteSpace(name))
        {
            await WriteError(response, 400, "Field 'name' is required.");
            return;
        }

        var unregister = !body.HasProperty("unregister") || body.GetBool("unregister");
        var (stopped, error) = await Trowser.Peers.PeerSpawnService.StopAsync(_context, Peers, name.Trim(), unregister);
        if (!stopped && error != null)
        {
            await WriteError(response, 500, error);
            return;
        }

        await WriteSuccess(response, new { stopped = true, name, unregistered = unregister });
    }

    private async Task HandlePostPeerRegister(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        var name = body.GetString("name");
        var baseUrl = body.GetString("baseUrl");
        var apiKey = body.GetString("apiKey");

        if (string.IsNullOrWhiteSpace(name) || string.IsNullOrWhiteSpace(baseUrl))
        {
            await WriteError(response, 400, "Fields 'name' and 'baseUrl' are required.");
            return;
        }

        var peer = new PeerEntry { Name = name, BaseUrl = baseUrl, ApiKey = apiKey };
        if (!Peers.Register(peer, out var error))
        {
            await WriteError(response, 400, error!);
            return;
        }

        var (alive, sessionName, _, pingError) = await Peers.PingAsync(name);
        await WriteSuccess(response, new
        {
            registered = true,
            name,
            baseUrl,
            alive,
            sessionName,
            pingError
        });
    }

    private async Task HandleDeletePeer(string name, HttpListenerResponse response)
    {
        if (string.IsNullOrWhiteSpace(name))
        {
            await WriteError(response, 400, "Peer name is required in the URL path.");
            return;
        }

        var removed = Peers.Unregister(Uri.UnescapeDataString(name));
        if (!removed)
        {
            await WriteError(response, 404, $"Peer \"{name}\" is not registered.");
            return;
        }

        await WriteSuccess(response, new { unregistered = true, name });
    }

    private async Task HandlePostPeerFetch(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        var peerName = body.GetString("peer");
        var url = body.GetString("url");

        if (string.IsNullOrWhiteSpace(peerName))
        {
            await WriteError(response, 400, "Field 'peer' (registered peer name) is required.");
            return;
        }
        if (string.IsNullOrWhiteSpace(url))
        {
            await WriteError(response, 400, "Field 'url' is required.");
            return;
        }

        if (body.GetBool("ensureOrigin"))
        {
            var (navigated, originError) = await Peers.EnsureOriginAsync(peerName, url);
            if (originError != null)
            {
                await WriteError(response, 502, $"ensureOrigin failed: {originError}");
                return;
            }
        }

        var fetchBody = new Dictionary<string, object?> { ["url"] = url };

        var method = body.GetString("method");
        if (method != null) fetchBody["method"] = method;

        var headerMap = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (body.GetJsonElement("headers") is { ValueKind: JsonValueKind.Object } headers)
        {
            foreach (var prop in headers.EnumerateObject())
            {
                if (prop.Value.ValueKind == JsonValueKind.String && prop.Value.GetString() is { } value)
                    headerMap[prop.Name] = value;
            }
        }

        if (!Security.Authz.PeerAuthMaterial.RequestHasAuthHeader(headerMap)
            && Uri.TryCreate(url, UriKind.Absolute, out var fetchUri))
        {
            var peerAuth = await Security.Authz.PeerAuthMaterial.LoadFromPeerAsync(
                Peers, peerName, Security.Authz.AuthzHostKey.FromUri(fetchUri));
            foreach (var kv in peerAuth)
                headerMap.TryAdd(kv.Key, kv.Value);
        }

        if (headerMap.Count > 0)
            fetchBody["headers"] = headerMap;

        var jsonPayload = body.GetJsonElement("json");
        if (jsonPayload != null) fetchBody["json"] = jsonPayload;

        var bodyPayload = body.GetString("body");
        if (bodyPayload != null) fetchBody["body"] = bodyPayload;

        var timeout = body.GetInt("timeout", 0);
        if (timeout > 0) fetchBody["timeout"] = timeout;

        var jsonStr = JsonSerializer.Serialize(fetchBody, JsonOptions);
        // Use /api/fetch-direct on the peer — gate-free server-side fetch with browser cookies.
        // This avoids the gate contention that caused hangs when using /api/fetch.
        var result = await Peers.ForwardAsync(peerName, "POST", "/api/fetch-direct", jsonStr,
            timeoutMs: PeerRegistry.ForwardTimeoutForFetchMs(timeout));

        if (result.PeerBusy)
        {
            await WriteError(response, 503,
                $"Peer \"{peerName}\" is busy. Retry when the peer is idle.");
            return;
        }
        if (!result.Success && result.StatusCode == 0)
        {
            await WriteError(response, 502, result.Body ?? "Peer unreachable.");
            return;
        }

        response.StatusCode = result.StatusCode > 0 ? result.StatusCode : 502;
        response.ContentType = "application/json; charset=utf-8";
        var bytes = Encoding.UTF8.GetBytes(result.Body ?? "{}");
        response.ContentLength64 = bytes.Length;
        await response.OutputStream.WriteAsync(bytes);
        response.Close();
    }

    private async Task HandlePostPeerState(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        var peerName = body.GetString("peer");

        if (string.IsNullOrWhiteSpace(peerName))
        {
            await WriteError(response, 400, "Field 'peer' (registered peer name) is required.");
            return;
        }

        // Use /api/info (gate-free) instead of /api/state (gated) to avoid hangs
        var result = await Peers.ForwardAsync(peerName, "GET", "/api/info",
            timeoutMs: PeerRegistry.ReachabilityTimeoutMs);
        if (!result.Success && result.StatusCode == 0)
        {
            await WriteError(response, 502, result.Body ?? "Peer unreachable.");
            return;
        }

        response.StatusCode = result.StatusCode > 0 ? result.StatusCode : 502;
        response.ContentType = "application/json; charset=utf-8";
        var bytes = Encoding.UTF8.GetBytes(result.Body ?? "{}");
        response.ContentLength64 = bytes.Length;
        await response.OutputStream.WriteAsync(bytes);
        response.Close();
    }

    private async Task HandlePostPeerNavigate(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        var peerName = body.GetString("peer");
        var url = body.GetString("url");

        if (string.IsNullOrWhiteSpace(peerName))
        {
            await WriteError(response, 400, "Field 'peer' (registered peer name) is required.");
            return;
        }
        if (string.IsNullOrWhiteSpace(url))
        {
            await WriteError(response, 400, "Field 'url' is required.");
            return;
        }

        var navBody = JsonSerializer.Serialize(new { url }, JsonOptions);
        var result = await Peers.ForwardAsync(peerName, "POST", "/api/navigate", navBody,
            timeoutMs: PeerRegistry.OperationTimeoutMs);

        if (!result.Success && result.StatusCode == 0)
        {
            await WriteError(response, 502, result.Body ?? "Peer unreachable.");
            return;
        }

        response.StatusCode = result.StatusCode > 0 ? result.StatusCode : 502;
        response.ContentType = "application/json; charset=utf-8";
        var bytes = Encoding.UTF8.GetBytes(result.Body ?? "{}");
        response.ContentLength64 = bytes.Length;
        await response.OutputStream.WriteAsync(bytes);
        response.Close();
    }

    private async Task HandlePostPeerScreenshot(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        var peerName = body.GetString("peer");

        if (string.IsNullOrWhiteSpace(peerName))
        {
            await WriteError(response, 400, "Field 'peer' (registered peer name) is required.");
            return;
        }

        var format = body.GetString("format") ?? "jpeg";
        var quality = body.GetInt("quality", 60);
        var queryString = $"?format={format}&quality={quality}&base64=true";

        var result = await Peers.ForwardAsync(peerName, "GET", "/api/screenshot" + queryString,
            timeoutMs: PeerRegistry.OperationTimeoutMs);
        if (!result.Success && result.StatusCode == 0)
        {
            await WriteError(response, 502, result.Body ?? "Peer unreachable.");
            return;
        }

        response.StatusCode = result.StatusCode > 0 ? result.StatusCode : 502;
        response.ContentType = "application/json; charset=utf-8";
        var bytes = Encoding.UTF8.GetBytes(result.Body ?? "{}");
        response.ContentLength64 = bytes.Length;
        await response.OutputStream.WriteAsync(bytes);
        response.Close();
    }

    #endregion

    #region VPX Export

    private async Task HandleGetVpxExport(HttpListenerRequest request, HttpListenerResponse response)
    {
        var profile = ApiQuery(request)["profile"] ?? "compact";

        string? baseUrl = null;
        try { baseUrl = await _context.GetCurrentUrl(); } catch { /* best effort */ }

        var exported = VpxSessionIo.Export(_context, SessionLogger, profile, baseUrl);

        response.StatusCode = 200;
        response.ContentType = "application/vnd.vpx+json; charset=utf-8";
        var bytes = Encoding.UTF8.GetBytes(exported.Json);
        response.ContentLength64 = bytes.Length;
        await response.OutputStream.WriteAsync(bytes);
        response.Close();
    }

    private async Task HandlePostVpxImport(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonBody(request);
        if (!body.TryGetRoot(out var root))
        {
            await WriteError(response, 400, "Invalid JSON body.");
            return;
        }

        if (root.TryGetProperty("action", out var actionEl) &&
            actionEl.GetString()?.Equals("clear", StringComparison.OrdinalIgnoreCase) == true)
        {
            _context.ClearVpxSessionState();
            await WriteSuccess(response, new { cleared = true, dedupReset = true });
            return;
        }

        var doc = root;
        if (root.TryGetProperty("document", out var docEl) && docEl.ValueKind == JsonValueKind.Object)
            doc = docEl;

        var mode = body.GetString("mode") ?? "merge";
        try
        {
            var result = VpxImportService.ImportDocument(_context, doc, mode);
            await WriteSuccess(response, result);
        }
        catch (InvalidOperationException ex)
        {
            await WriteError(response, 400, ex.Message);
        }
    }

    private async Task HandlePostVpxClear(HttpListenerResponse response)
    {
        _context.ClearVpxSessionState();
        await WriteSuccess(response, new { cleared = true, dedupReset = true });
    }

    #endregion
}
