using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;

namespace Trowser.Peers;

/// <summary>
/// Launches additional Trowser.exe instances on localhost for cross-session testing.
/// </summary>
public static class PeerLauncher
{
    public sealed class LaunchResult
    {
        public bool Success { get; init; }
        public Process? Process { get; init; }
        public int Port { get; init; }
        public string? Error { get; init; }
        public bool ReusedExisting { get; init; }
    }

    public static int FindFreePort(int startPort = 6924, int maxAttempts = 50)
    {
        for (var port = startPort; port < startPort + maxAttempts; port++)
        {
            if (IsPortFree(port))
                return port;
        }

        throw new InvalidOperationException($"No free port found in range {startPort}-{startPort + maxAttempts - 1}.");
    }

    public static bool IsPortFree(int port)
    {
        try
        {
            var listener = new TcpListener(IPAddress.Loopback, port);
            listener.Start();
            listener.Stop();
            return true;
        }
        catch
        {
            return false;
        }
    }

    public static string ResolveExecutablePath()
    {
        var path = Environment.ProcessPath;
        if (!string.IsNullOrEmpty(path) && File.Exists(path))
            return path;

        path = Process.GetCurrentProcess().MainModule?.FileName;
        if (!string.IsNullOrEmpty(path) && File.Exists(path))
            return path;

        throw new InvalidOperationException("Could not resolve Trowser.exe path.");
    }

    public static LaunchResult Launch(
        int port,
        string apiKey,
        string sessionName,
        string scope,
        bool apiEnabled = true,
        bool ephemeral = false)
    {
        try
        {
            var exe = ResolveExecutablePath();
            var args = new List<string>();
            if (apiEnabled) args.Add("--api");
            args.Add($"--api-port {port}");
            args.Add($"--session {sessionName}");
            if (ephemeral)
                args.Add("--ephemeral");
            if (!string.IsNullOrWhiteSpace(scope))
                args.Add($"--scope \"{scope.Replace("\"", "\\\"")}\"");
            args.Add("--nosplash");

            // Pass the API key out-of-band via the environment rather than on the command line:
            // any local user can read another process's argv (e.g. WMI/CIM Win32_Process.CommandLine),
            // and command lines are commonly captured by EDR/telemetry. UseShellExecute must be false
            // to set the child's environment.
            var psi = new ProcessStartInfo
            {
                FileName = exe,
                Arguments = string.Join(" ", args),
                UseShellExecute = false,
                WorkingDirectory = Path.GetDirectoryName(exe) ?? Environment.CurrentDirectory
            };
            if (!string.IsNullOrEmpty(apiKey))
                psi.Environment["TROWSER_API_KEY"] = apiKey;

            var process = Process.Start(psi);
            if (process == null)
                return new LaunchResult { Success = false, Error = "Process.Start returned null." };

            return new LaunchResult { Success = true, Process = process, Port = port };
        }
        catch (Exception ex)
        {
            return new LaunchResult { Success = false, Error = ex.Message };
        }
    }
}
