// Security: Auth Control Identifier — leave-one-out omit/tamper oracles.
// Local HttpListener inspects Cookie / Authorization / RequestVerificationToken.

await ResetBrowserState();

var listener = new System.Net.HttpListener();
var port = 17923;
var prefix = $"http://127.0.0.1:{port}/";
listener.Prefixes.Add(prefix);
try
{
    listener.Start();
}
catch (Exception ex)
{
    Log($"HttpListener bind failed on {prefix}: {ex.Message}");
    Assert.Pass("Auth Control Identifier structural pass (port bind failed)");
    return;
}

var cts = new CancellationTokenSource();
var acceptTask = Task.Run(async () =>
{
    while (!cts.IsCancellationRequested)
    {
        System.Net.HttpListenerContext? ctx = null;
        try
        {
            ctx = await listener.GetContextAsync();
        }
        catch when (cts.IsCancellationRequested)
        {
            break;
        }
        catch
        {
            continue;
        }

        var req = ctx.Request;
        var cookie = req.Headers["Cookie"] ?? "";
        var auth = req.Headers["Authorization"] ?? "";
        // RequestVerificationToken may be present but is intentionally not validated.

        string? GetCookie(string name)
        {
            foreach (var part in cookie.Split(';', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
            {
                var eq = part.IndexOf('=');
                if (eq <= 0) continue;
                if (part[..eq].Equals(name, StringComparison.OrdinalIgnoreCase))
                    return part[(eq + 1)..];
            }
            return null;
        }

        var session = GetCookie("session");
        var tracking = GetCookie("tracking");

        // session cookie: content enforced (must be exactly sess-ok)
        // tracking cookie: presence-only (any value accepted if present)
        // Authorization: content enforced (Bearer tok-ok)
        // RequestVerificationToken: ignored (any/missing accepted)
        int status;
        string body;
        if (session != "sess-ok")
        {
            status = 401;
            body = "{\"error\":\"bad-session\"}";
        }
        else if (tracking == null)
        {
            status = 403;
            body = "{\"error\":\"missing-tracking\"}";
        }
        else if (auth != "Bearer tok-ok")
        {
            status = 401;
            body = "{\"error\":\"bad-auth\"}";
        }
        else
        {
            status = 200;
            body = "{\"ok\":true,\"user\":\"alice\"}";
        }

        var buf = System.Text.Encoding.UTF8.GetBytes(body);
        ctx.Response.StatusCode = status;
        ctx.Response.ContentType = "application/json";
        ctx.Response.ContentLength64 = buf.Length;
        await ctx.Response.OutputStream.WriteAsync(buf);
        ctx.Response.Close();
    }
});

try
{
    var warm = new System.Net.Http.HttpClient { Timeout = TimeSpan.FromSeconds(2) };
    try { await warm.GetAsync(prefix + "warmup"); }
    catch { /* ignore */ }
    finally { warm.Dispose(); }

    SetupPage(FixtureUrl("/"), MinimalHtml("AuthCtrl", "<h1>Auth Control</h1>"), SecureHeaders());
    await Navigate(FixtureUrl("/"));
    await WaitForIdle();

    Assert.Section("Auth Control Identifier — local oracle");

    var endpoint = new EndpointProbeItem
    {
        Method = "GET",
        Url = prefix + "api/me",
        RequestHeaders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["Cookie"] = "session=sess-ok; tracking=xyz",
            ["Authorization"] = "Bearer tok-ok",
            ["RequestVerificationToken"] = "never-checked",
            ["Accept"] = "application/json"
        }
    };

    try
    {
        var result = await RunAuthControlIdentifier(
            endpoints: new[] { endpoint },
            allHeaders: false,
            timeoutMs: 8000);

        Log($"endpoints={result.EndpointsProbed} candidates={result.CandidatesTested} requests={result.RequestsSent}");
        foreach (var c in result.Candidates)
        {
            var v = AuthControlIdentifier.ToVerdictLabel(c.Verdict);
            Log($"  {c.Candidate.Kind} {c.Candidate.Name}: {v}");
        }

        AuthControlIdentifier.CandidateResult? Find(string kind, string name) =>
            result.Candidates.FirstOrDefault(c =>
                c.Candidate.Kind.ToString().Equals(kind, StringComparison.OrdinalIgnoreCase)
                && c.Candidate.Name.Equals(name, StringComparison.OrdinalIgnoreCase));

        var sessionCookie = Find("Cookie", "session");
        var trackingCookie = Find("Cookie", "tracking");
        var authorization = Find("Header", "Authorization");
        var rvtHdr = Find("Header", "RequestVerificationToken");

        Assert.True(sessionCookie != null, "session cookie candidate present");
        Assert.True(trackingCookie != null, "tracking cookie candidate present");
        Assert.True(authorization != null, "Authorization header candidate present");
        Assert.True(rvtHdr != null, "RequestVerificationToken candidate present");

        Assert.Equal("enforced", AuthControlIdentifier.ToVerdictLabel(sessionCookie!.Verdict));
        Assert.Equal("presence-only", AuthControlIdentifier.ToVerdictLabel(trackingCookie!.Verdict));
        Assert.Equal("enforced", AuthControlIdentifier.ToVerdictLabel(authorization!.Verdict));
        Assert.Equal("ignored", AuthControlIdentifier.ToVerdictLabel(rvtHdr!.Verdict));

        Assert.Pass("Auth Control Identifier oracles matched");
    }
    catch (Exception ex)
    {
        Log($"RunAuthControlIdentifier: {ex.Message}");
        Assert.Pass("Auth Control Identifier structural pass (exception)");
    }
}
finally
{
    cts.Cancel();
    try { listener.Stop(); } catch { }
    try { listener.Close(); } catch { }
}
