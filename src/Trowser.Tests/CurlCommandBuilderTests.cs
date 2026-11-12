using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Xunit;

namespace Trowser.Tests;

public class CurlCommandBuilderTests
{
    [Fact]
    public void get_omits_body_and_quotes_query_string()
    {
        var cmd = CurlCommandBuilder.ToCommandLine(
            "GET",
            "https://example.com/search?q=a&b=2",
            null,
            null);

        Assert.Equal(
            "curl 'https://example.com/search?q=a&b=2'",
            cmd);
        Assert.DoesNotContain("\n", cmd);
        Assert.DoesNotContain("\"", cmd);
        Assert.DoesNotContain("--data-raw", cmd, StringComparison.Ordinal);
        Assert.DoesNotContain("--location", cmd, StringComparison.Ordinal);
    }

    [Fact]
    public void post_json_uses_data_raw_and_content_type()
    {
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["Content-Type"] = "application/json",
            ["Authorization"] = "Bearer tok"
        };

        var cmd = CurlCommandBuilder.ToCommandLine(
            "POST",
            "https://api.example.com/v1/items",
            headers,
            "{\"name\":\"test\"}");

        Assert.Equal(
            "curl 'https://api.example.com/v1/items' -H 'Content-Type: application/json' " +
            "-H 'Authorization: Bearer tok' --data-raw '{\"name\":\"test\"}'",
            cmd);
        Assert.DoesNotContain("\n", cmd);
    }

    [Fact]
    public void follow_redirects_adds_location()
    {
        var args = CurlCommandBuilder.BuildArguments(
            "GET", "https://example.com/", null, null, followRedirects: true);
        Assert.Contains("--location", args);
    }

    [Fact]
    public void skips_headers_curl_manages_and_http2_pseudo()
    {
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            [":method"] = "POST",
            ["Content-Length"] = "12",
            ["Transfer-Encoding"] = "chunked",
            ["Connection"] = "keep-alive",
            ["Host"] = "evil.test",
            ["Cookie"] = "session=abc",
            ["Accept-Encoding"] = "gzip, deflate, br, zstd"
        };

        var args = CurlCommandBuilder.BuildArguments(
            "POST", "https://example.com/x", headers, "hello");

        Assert.DoesNotContain("--compressed", args);
        Assert.DoesNotContain(args, a => a.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(args, a => a.StartsWith("Transfer-Encoding:", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(args, a => a.StartsWith("Connection:", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(args, a => a.StartsWith("Accept-Encoding:", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(args, a => a.StartsWith(":method:", StringComparison.OrdinalIgnoreCase));
        Assert.Contains("Host: evil.test", args);
        Assert.Contains("Cookie: session=abc", args);
        Assert.Contains("--data-raw", args);
        Assert.Contains("hello", args);
    }

    [Fact]
    public void empty_body_is_omitted_whitespace_body_is_sent()
    {
        var noBody = CurlCommandBuilder.BuildArguments("POST", "https://example.com/", null, "");
        Assert.DoesNotContain("--data-raw", noBody);

        var space = CurlCommandBuilder.BuildArguments("POST", "https://example.com/", null, " ");
        Assert.Contains("--data-raw", space);
        Assert.Contains(" ", space);
    }

    [Fact]
    public void get_with_body_keeps_method_and_data_raw()
    {
        var args = CurlCommandBuilder.BuildArguments("GET", "https://example.com/", null, "{\"x\":1}");
        var x = args.IndexOf("-X");
        Assert.True(x >= 0);
        Assert.Equal("GET", args[x + 1]);
        Assert.Contains("--data-raw", args);
    }

    [Fact]
    public void custom_method_and_dash_url_use_url_flag()
    {
        var args = CurlCommandBuilder.BuildArguments("QUERY", "-odd", null, null);
        Assert.Equal("QUERY", args[args.IndexOf("-X") + 1]);
        Assert.Contains("--url", args);
        Assert.Equal("-odd", args[args.IndexOf("--url") + 1]);
    }

    [Fact]
    public void apostrophe_in_body_uses_bash_single_quote_escape()
    {
        var cmd = CurlCommandBuilder.ToCommandLine(
            "POST", "https://example.com/", null, "it's");
        Assert.Contains("--data-raw 'it'\\''s'", cmd);
    }

    [Fact]
    public void pretty_json_body_becomes_one_line()
    {
        const string pretty = "{\r\n  \"name\": \"test\",\r\n  \"ok\": true\r\n}";
        var cmd = CurlCommandBuilder.ToCommandLine(
            "POST", "https://example.com/api", null, pretty);

        Assert.Contains("--data-raw '{\"name\":\"test\",\"ok\":true}'", cmd);
        Assert.DoesNotContain("\n", cmd);
        Assert.DoesNotContain("\r", cmd);
    }

    [Fact]
    public void percent_in_url_is_unchanged_for_bash()
    {
        var cmd = CurlCommandBuilder.ToCommandLine(
            "GET", "https://example.com/?q=%PATH%", null, null);
        Assert.Equal("curl 'https://example.com/?q=%PATH%'", cmd);
    }

    [Fact]
    public void non_json_multiline_body_is_flattened_to_one_line()
    {
        var cmd = CurlCommandBuilder.ToCommandLine(
            "POST", "https://example.com/", null, "<root>\n  <a>1</a>\n</root>");
        Assert.Contains("--data-raw '<root>  <a>1</a></root>'", cmd);
        Assert.DoesNotContain("\n", cmd);
    }

    [Fact]
    public void missing_url_throws()
    {
        Assert.Throws<ArgumentException>(() =>
            CurlCommandBuilder.ToCommandLine("GET", "  ", null, null));
    }

    [Fact]
    public void at_sign_body_uses_data_raw_so_curl_does_not_read_a_file()
    {
        var args = CurlCommandBuilder.BuildArguments("POST", "https://example.com/", null, "@etc/passwd");
        Assert.Contains("--data-raw", args);
        Assert.DoesNotContain("-d", args);
        Assert.DoesNotContain("--data", args);
        Assert.Contains("@etc/passwd", args);
    }

    [Fact]
    public void url_with_dollar_path_is_kept_as_argument()
    {
        var url = "https://example.com/pdi/fhir/$search-endpoint";
        var args = CurlCommandBuilder.BuildArguments("POST", url, null, "{}");
        Assert.DoesNotContain("--globoff", args);
        Assert.DoesNotContain("--path-as-is", args);
        Assert.Equal(url, args[^1]);
    }

    [Fact]
    public async Task curl_exe_sends_json_post_matching_editor_fields()
    {
        Assert.True(TryCurlVersion(out _), "curl.exe is required for this test (bundled with Windows).");

        var port = GetFreePort();
        using var listener = new HttpListener();
        listener.Prefixes.Add($"http://127.0.0.1:{port}/");
        listener.Start();

        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["Content-Type"] = "application/json",
            ["X-Custom"] = "probe-value",
            ["Authorization"] = "Bearer tok"
        };
        const string body = "{\"name\":\"trowser\"}";
        var url = $"http://127.0.0.1:{port}/v1/items?q=a&b=2";

        var receive = ReceiveOnceAsync(listener);
        var args = CurlCommandBuilder.BuildArguments("POST", url, headers, body);
        args.Add("--silent");
        args.Add("--max-time");
        args.Add("5");
        args.Add("--output");
        args.Add("NUL");

        var exit = await RunCurlAsync(args);
        var captured = await receive;

        Assert.Equal(0, exit);
        Assert.Equal("POST", captured.Method);
        Assert.Equal("/v1/items?q=a&b=2", captured.RawUrl);
        Assert.StartsWith("application/json", captured.ContentType ?? "");
        Assert.Equal("probe-value", captured.Headers["X-Custom"]);
        Assert.Equal("Bearer tok", captured.Headers["Authorization"]);
        Assert.Equal(body, captured.Body);
    }

    [Fact]
    public async Task curl_exe_sends_get_with_cookie_header()
    {
        Assert.True(TryCurlVersion(out _), "curl.exe is required for this test (bundled with Windows).");

        var port = GetFreePort();
        using var listener = new HttpListener();
        listener.Prefixes.Add($"http://127.0.0.1:{port}/");
        listener.Start();

        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["Cookie"] = "session=abc; theme=dark"
        };
        var url = $"http://127.0.0.1:{port}/me";

        var receive = ReceiveOnceAsync(listener);
        var args = CurlCommandBuilder.BuildArguments("GET", url, headers, null);
        args.Add("--silent");
        args.Add("--max-time");
        args.Add("5");

        var exit = await RunCurlAsync(args);
        var captured = await receive;

        Assert.Equal(0, exit);
        Assert.Equal("GET", captured.Method);
        Assert.Equal("/me", captured.RawUrl);
        Assert.Contains("session=abc", captured.Headers["Cookie"]);
        Assert.Contains("theme=dark", captured.Headers["Cookie"]);
    }

    [Fact]
    public void host_override_is_kept_when_it_differs_from_the_url()
    {
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["Host"] = "evil.test"
        };
        var cmd = CurlCommandBuilder.ToCommandLine("GET", "https://example.com/x", headers, null);
        Assert.Contains("-H 'Host: evil.test'", cmd);
    }

    private static async Task<(string Method, string RawUrl, string? ContentType, Dictionary<string, string> Headers, string Body)>
        ReceiveOnceAsync(HttpListener listener)
    {
        var ctxTask = listener.GetContextAsync();
        var completed = await Task.WhenAny(ctxTask, Task.Delay(TimeSpan.FromSeconds(8)));
        Assert.Same(ctxTask, completed);
        var ctx = await ctxTask;

        var method = ctx.Request.HttpMethod;
        var rawUrl = ctx.Request.RawUrl ?? "";
        var contentType = ctx.Request.ContentType;
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var key in ctx.Request.Headers.AllKeys)
        {
            if (string.IsNullOrEmpty(key)) continue;
            headers[key] = ctx.Request.Headers[key] ?? "";
        }

        using var reader = new StreamReader(ctx.Request.InputStream, Encoding.UTF8);
        var body = await reader.ReadToEndAsync();
        ctx.Response.StatusCode = 204;
        ctx.Response.Close();
        return (method, rawUrl, contentType, headers, body);
    }

    private static async Task<int> RunCurlAsync(List<string> args)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "curl.exe",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };
        foreach (var arg in args)
            psi.ArgumentList.Add(arg);

        using var proc = Process.Start(psi);
        Assert.NotNull(proc);
        var stdout = proc.StandardOutput.ReadToEndAsync();
        var stderr = proc.StandardError.ReadToEndAsync();
        await proc.WaitForExitAsync();
        await Task.WhenAll(stdout, stderr);
        return proc.ExitCode;
    }

    private static bool TryCurlVersion(out string version)
    {
        version = "";
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "curl.exe",
                Arguments = "--version",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };
            using var proc = Process.Start(psi);
            if (proc == null) return false;
            version = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(5000);
            return proc.ExitCode == 0 && version.StartsWith("curl", StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    private static int GetFreePort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }
}
