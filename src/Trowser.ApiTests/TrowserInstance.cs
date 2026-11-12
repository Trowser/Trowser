using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Xunit;

namespace Trowser.ApiTests;

/// <summary>Headless Trowser with REST/MCP enabled (<c>--serve --api</c>).</summary>
public sealed class TrowserInstance : IAsyncLifetime, IDisposable
{
    private Process? _process;
    private readonly ConcurrentQueue<string> _processLog = new();
    private const int MaxLogLines = 80;

    public int Port { get; private set; }
    public string ApiKey { get; private set; } = "";
    public string ExePath { get; private set; } = "";
    public string BaseUrl => $"http://localhost:{Port}";
    public bool SafeMode { get; init; }

    public async Task InitializeAsync()
    {
        Port = GetFreeTcpPort();
        ApiKey = "apitest-" + Guid.NewGuid().ToString("N");
        var session = "apitest-" + Guid.NewGuid().ToString("N")[..12];
        ExePath = RepoPaths.TrowserExe();
        var args = $"--serve --api --api-port {Port} --api-key {ApiKey} --session {session} --nosplash";
        if (SafeMode) args += " --safe";

        _process = Process.Start(new ProcessStartInfo
        {
            FileName = ExePath,
            Arguments = args,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardError = true,
            RedirectStandardOutput = true
        }) ?? throw new InvalidOperationException($"Failed to start Trowser.exe ({ExePath}).");

        StartDrain(_process.StandardOutput, "stdout");
        StartDrain(_process.StandardError, "stderr");

        try
        {
            await WaitForPingAsync(TimeSpan.FromSeconds(120));
        }
        catch (Exception ex) when (ex is TimeoutException or InvalidOperationException)
        {
            throw new InvalidOperationException(
                $"{ex.Message}\nTrowser exe: {ExePath}\n--- recent process log ---\n{RecentLogText()}",
                ex);
        }
    }

    public Task DisposeAsync()
    {
        Dispose();
        return Task.CompletedTask;
    }

    public void Dispose()
    {
        if (_process == null) return;
        try
        {
            if (!_process.HasExited)
            {
                _process.Kill(entireProcessTree: true);
                _process.WaitForExit(5000);
            }
        }
        catch { /* best effort */ }
        finally
        {
            _process.Dispose();
            _process = null;
        }
    }

    internal string RecentLogText()
    {
        var lines = _processLog.ToArray();
        if (lines.Length == 0) return "(empty)";
        return string.Join(Environment.NewLine, lines.TakeLast(40));
    }

    private void StartDrain(StreamReader reader, string label)
    {
        _ = Task.Run(async () =>
        {
            try
            {
                while (await reader.ReadLineAsync() is { } line)
                    AppendLog($"{label}: {line}");
            }
            catch { /* process exited */ }
        });
    }

    private void AppendLog(string line)
    {
        _processLog.Enqueue(line);
        while (_processLog.Count > MaxLogLines && _processLog.TryDequeue(out _)) { }
    }

    private async Task WaitForPingAsync(TimeSpan timeout)
    {
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(3) };
        var deadline = DateTime.UtcNow + timeout;
        Exception? last = null;
        while (DateTime.UtcNow < deadline)
        {
            if (_process is { HasExited: true })
                throw new InvalidOperationException(
                    $"Trowser exited early (code {_process.ExitCode}). Log:\n{RecentLogText()}");

            try
            {
                var json = await http.GetStringAsync($"{BaseUrl}/api/ping");
                if (json.Contains("\"success\"", StringComparison.Ordinal))
                    return;
            }
            catch (Exception ex)
            {
                last = ex;
            }

            await Task.Delay(500);
        }

        throw new TimeoutException($"Trowser did not respond on {BaseUrl}/api/ping within {timeout.TotalSeconds}s.", last);
    }

    private static int GetFreeTcpPort()
    {
        var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        var port = ((IPEndPoint)l.LocalEndpoint).Port;
        l.Stop();
        return port;
    }
}

[CollectionDefinition(BrowserCollection.Name)]
public class BrowserCollection : ICollectionFixture<TrowserInstance>
{
    public const string Name = "Browser";
}
