using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Windows;
using Trowser.Chat;

namespace Trowser;

/// <summary>
/// Parsed CLI options. Null when running in GUI mode.
/// </summary>
public class CliOptions
{
    public string ScriptFile { get; init; } = "";
    public string? Url { get; init; }
    public string? OutputFile { get; init; }
    public bool Visible { get; init; }
    public int TimeoutSeconds { get; init; } = 120;
}

/// <summary>
/// API server configuration, parsed from command-line arguments.
/// </summary>
public class ApiOptions
{
    /// <summary>API is off by default — user can toggle in the status bar; state can be persisted in api-user.json.</summary>
    public bool Enabled { get; init; } = false;

    /// <summary>True if <c>--api</c> or <c>--no-api</c> was used (overrides persisted on/off for GUI).</summary>
    public bool ApiEnabledFromCommandLine { get; init; }
    public int Port { get; init; } = 6923;

    /// <summary>True if <c>--api-port</c> was used (overrides persisted GUI port for this run).</summary>
    public bool PortFromCommandLine { get; init; }

    /// <summary>
    /// Navigation scope patterns (comma-separated).
    /// Default uses *.* for no restrictions.
    /// </summary>
    public string Scope { get; init; } = "*.*";

    /// <summary>True if <c>--scope</c> was used (overrides persisted GUI scope for this run).</summary>
    public bool ScopeFromCommandLine { get; init; }

    /// <summary>Allow <c>file://</c> navigation when scope would otherwise permit it (default: blocked).</summary>
    public bool AllowFileUrls { get; init; }

    /// <summary>True if <c>--allow-file-urls</c> was used.</summary>
    public bool AllowFileUrlsFromCommandLine { get; init; }

    /// <summary>
    /// API key for authenticating requests. Auto-generated if not provided via --api-key.
    /// </summary>
    public string ApiKey { get; init; } = GenerateApiKey();

    /// <summary>True if <c>--api-key</c> was used (key is fixed; not merged from persisted user settings).</summary>
    public bool ApiKeyFromCommandLine { get; init; }

    /// <summary>
    /// Safe mode restricts dangerous API operations (JS execution, C# scripting,
    /// network mocking, cookie manipulation). Use when browsing untrusted sites.
    /// </summary>
    public bool SafeMode { get; init; } = false;

    /// <summary>True if <c>--safe</c> was used (overrides persisted GUI safe mode for this run).</summary>
    public bool SafeModeFromCommandLine { get; init; }

    /// <summary>
    /// When true (<c>--safe-probes-only</c>), IDOR scans only use read-only HTTP verbs and never add PUT/PATCH/DELETE;
    /// auto-scan also skips mass-assignment. Strongest safety profile for security probes (CLI overrides destructive JSON).
    /// </summary>
    public bool SafeSecurityProbesOnly { get; init; }

    /// <summary>
    /// When true (<c>--dangerous-ok</c>), omitted JSON flags restore legacy behavior: IDOR may add mutating HTTP methods
    /// unless explicitly disabled in the request body.
    /// </summary>
    public bool DangerousSecurityProbesOk { get; init; }

    /// <summary>
    /// Named session for WebView2 user data isolation. Each session gets its own
    /// cookies, storage, and cache under <c>%LocalAppData%\Trowser\Sessions\{name}\</c>.
    /// Default GUI launch uses the persistent <c>default</c> session; a second instance
    /// without <c>--session</c> falls back to an isolated ephemeral profile automatically.
    /// </summary>
    public string SessionName { get; init; } = "default";

    /// <summary>True if <c>--session</c> was passed on the command line.</summary>
    public bool SessionNameFromCommandLine { get; init; }

    /// <summary>
    /// When true, the session uses a temporary GUID-based folder that is deleted on exit.
    /// Use <c>--ephemeral</c> for throwaway profiles; otherwise sessions persist under
    /// <see cref="SessionName"/>.
    /// </summary>
    public bool Ephemeral { get; init; }

    private static string GenerateApiKey() => TrowserApiKey.Generate();
}

/// <summary>
/// Interaction logic for App.xaml
/// </summary>
public partial class App : Application
{
    /// <summary>
    /// Product version from the assembly (e.g. "1.3.9"), sourced from &lt;Version&gt; in .csproj.
    /// The SDK may append <c>+&lt;git SHA&gt;</c> as SemVer build metadata; that is stripped so
    /// User-Agent, /api/info, and security scanner headers stay <c>Trowser/1.3.9</c>.
    /// </summary>
    public static string Version { get; } = ReadProductVersion();

    private static string ReadProductVersion()
    {
        var raw = typeof(App).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()
            ?.InformationalVersion ?? "0.0.0";
        var plus = raw.IndexOf('+');
        return plus >= 0 ? raw[..plus] : raw;
    }

    /// <summary>
    /// Set when running in CLI mode (--run). Null in normal GUI mode.
    /// </summary>
    public static CliOptions? CliMode { get; private set; }

    /// <summary>API server configuration (CLI flags and in-memory; GUI persistence uses <see cref="ApiUserSettings"/>).</summary>
    public static ApiOptions Api { get; private set; } = new();
    public static bool NoSplash { get; private set; }

    /// <summary>Headless API-only mode for automation (<c>--serve --api</c>). No script, no visible window.</summary>
    public static bool ServeMode { get; private set; }

    [DllImport("kernel32.dll")]
    private static extern bool AttachConsole(int dwProcessId);

    [DllImport("kernel32.dll")]
    private static extern bool FreeConsole();

    private const int ATTACH_PARENT_PROCESS = -1;

    protected override void OnStartup(StartupEventArgs e)
    {
        // Scanners run regexes (including nuclei template matchers) over attacker-controlled
        // responses; a process-wide default stops catastrophic backtracking from hanging Trowser.
        AppDomain.CurrentDomain.SetData("REGEX_DEFAULT_MATCH_TIMEOUT", TimeSpan.FromSeconds(5));

        base.OnStartup(e);

        (CliMode, Api) = ParseArgs(e.Args);

        if (CliMode != null)
        {
            // Attach to the parent console so stdout works
            AttachConsole(ATTACH_PARENT_PROCESS);
            System.Console.OutputEncoding = Encoding.UTF8;
            System.Console.InputEncoding = Encoding.UTF8;

            // Disable API in CLI mode (script runs and exits)
            Api = new ApiOptions
            {
                Enabled = false, Port = Api.Port, Scope = Api.Scope, ApiKey = Api.ApiKey, SafeMode = Api.SafeMode,
                ApiKeyFromCommandLine = Api.ApiKeyFromCommandLine, ApiEnabledFromCommandLine = Api.ApiEnabledFromCommandLine,
                PortFromCommandLine = Api.PortFromCommandLine, ScopeFromCommandLine = Api.ScopeFromCommandLine,
                SafeModeFromCommandLine = Api.SafeModeFromCommandLine,
                SessionName = Api.SessionName, SessionNameFromCommandLine = Api.SessionNameFromCommandLine,
                Ephemeral = Api.Ephemeral,
                SafeSecurityProbesOnly = Api.SafeSecurityProbesOnly, DangerousSecurityProbesOk = Api.DangerousSecurityProbesOk
            };
        }

        // Safety nets: ensure HttpListener is released even on abnormal exit.
        // Without these, HTTP.sys may hold the URL prefix and block restart.
        AppDomain.CurrentDomain.ProcessExit += (_, _) => CleanupMainWindow();
        AppDomain.CurrentDomain.UnhandledException += (_, _) => CleanupMainWindow();
        DispatcherUnhandledException += (_, _) => CleanupMainWindow();

        var mainWindow = new MainWindow();

        if ((CliMode != null && !CliMode.Visible) || ServeMode)
        {
            mainWindow.WindowState = WindowState.Minimized;
            mainWindow.ShowInTaskbar = false;
            mainWindow.Visibility = Visibility.Hidden;
        }

        mainWindow.Show();
    }

    /// <summary>
    /// Best-effort cleanup of the API server's HttpListener to release the HTTP.sys
    /// URL prefix. Called from multiple safety-net handlers; guards against double-dispose.
    /// </summary>
    private void CleanupMainWindow()
    {
        try
        {
            if (MainWindow is MainWindow mw)
                mw.DisposeApiServer();
        }
        catch { /* best effort — process is exiting */ }
    }

    private static (CliOptions?, ApiOptions) ParseArgs(string[] args)
    {
        string? scriptFile = null;
        string? url = null;
        string? outputFile = null;
        bool visible = false;
        int timeout = 120;
        int apiPort = 6923;
        bool apiEnabled = false;
        bool apiEnabledFromCommandLine = false;
        bool portFromCommandLine = false;
        string scope = "*.*";
        bool scopeFromCommandLine = false;
        string? apiKey = null;
        bool safeMode = false;
        bool safeModeFromCommandLine = false;
        bool safeSecurityProbesOnly = false;
        bool dangerousSecurityProbesOk = false;
        string sessionName = "default";
        bool ephemeral = false;
        bool sessionNameFromCommandLine = false;
        bool allowFileUrls = false;
        bool allowFileUrlsFromCommandLine = false;
        bool serveMode = false;

        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i].ToLowerInvariant())
            {
                case "--run":
                    if (i + 1 < args.Length)
                    {
                        scriptFile = args[++i];
                    }
                    break;
                case "--url":
                    if (i + 1 < args.Length)
                    {
                        url = args[++i];
                    }
                    break;
                case "--output":
                    if (i + 1 < args.Length)
                    {
                        outputFile = args[++i];
                    }
                    break;
                case "--visible":
                    visible = true;
                    break;
                case "--timeout":
                    if (i + 1 < args.Length && int.TryParse(args[++i], out var t))
                    {
                        timeout = t;
                    }
                    break;
                case "--api-port":
                    if (i + 1 < args.Length && int.TryParse(args[++i], out var p))
                    {
                        apiPort = p;
                        portFromCommandLine = true;
                    }
                    break;
                case "--api":
                    apiEnabled = true;
                    apiEnabledFromCommandLine = true;
                    break;
                case "--no-api":
                    apiEnabled = false;
                    apiEnabledFromCommandLine = true;
                    break;
                case "--nosplash":
                    NoSplash = true;
                    break;
                case "--scope":
                    if (i + 1 < args.Length)
                    {
                        scope = args[++i];
                        scopeFromCommandLine = true;
                    }
                    break;
                case "--api-key":
                    if (i + 1 < args.Length)
                    {
                        apiKey = args[++i];
                    }
                    break;
                case "--safe":
                    safeMode = true;
                    safeModeFromCommandLine = true;
                    break;
                case "--safe-probes-only":
                    safeSecurityProbesOnly = true;
                    break;
                case "--dangerous-ok":
                    dangerousSecurityProbesOk = true;
                    break;
                case "--session":
                    if (i + 1 < args.Length)
                    {
                        sessionName = args[++i];
                        sessionNameFromCommandLine = true;
                        ephemeral = false;
                    }
                    break;
                case "--ephemeral":
                    ephemeral = true;
                    break;
                case "--allow-file-urls":
                    allowFileUrls = true;
                    allowFileUrlsFromCommandLine = true;
                    break;
                case "--proxy":
                    if (i + 1 < args.Length)
                    {
                        var settings = LlmSettings.Load();
                        settings.ProxyEnabled = true;
                        settings.ProxyUrl = args[++i];
                        settings.Save();
                    }
                    break;
                case "--serve":
                    serveMode = true;
                    apiEnabled = true;
                    apiEnabledFromCommandLine = true;
                    NoSplash = true;
                    break;
            }
        }

        ServeMode = serveMode;

        // Prefer a process-injected key (PeerLauncher) over argv. A persistent User/Machine
        // TROWSER_API_KEY is ignored here so Settings → Keep API key can persist across restarts.
        if (apiKey == null && TrowserApiKey.TryTakeProcessInjectedKey(out var envKey))
            apiKey = envKey;

        var apiOptions = apiKey != null
            ? new ApiOptions
            {
                Enabled = apiEnabled,
                Port = apiPort,
                Scope = scope,
                ApiKey = apiKey,
                SafeMode = safeMode,
                ApiKeyFromCommandLine = true,
                ApiEnabledFromCommandLine = apiEnabledFromCommandLine,
                PortFromCommandLine = portFromCommandLine,
                ScopeFromCommandLine = scopeFromCommandLine,
                SafeModeFromCommandLine = safeModeFromCommandLine,
                SessionName = sessionName,
                SessionNameFromCommandLine = sessionNameFromCommandLine,
                Ephemeral = ephemeral,
                SafeSecurityProbesOnly = safeSecurityProbesOnly,
                DangerousSecurityProbesOk = dangerousSecurityProbesOk,
                AllowFileUrls = allowFileUrls,
                AllowFileUrlsFromCommandLine = allowFileUrlsFromCommandLine
            }
            : new ApiOptions
            {
                Enabled = apiEnabled,
                Port = apiPort,
                Scope = scope,
                SafeMode = safeMode,
                ApiKeyFromCommandLine = false,
                ApiEnabledFromCommandLine = apiEnabledFromCommandLine,
                PortFromCommandLine = portFromCommandLine,
                ScopeFromCommandLine = scopeFromCommandLine,
                SafeModeFromCommandLine = safeModeFromCommandLine,
                SessionName = sessionName,
                SessionNameFromCommandLine = sessionNameFromCommandLine,
                Ephemeral = ephemeral,
                SafeSecurityProbesOnly = safeSecurityProbesOnly,
                DangerousSecurityProbesOk = dangerousSecurityProbesOk,
                AllowFileUrls = allowFileUrls,
                AllowFileUrlsFromCommandLine = allowFileUrlsFromCommandLine
            };

        if (args.Length == 0 || scriptFile == null)
            return (null, apiOptions);

        // Resolve relative paths
        scriptFile = Path.GetFullPath(scriptFile);

        if (!File.Exists(scriptFile))
        {
            System.Console.Error.WriteLine($"Error: Script file not found: {scriptFile}");
            Environment.Exit(2);
        }

        var cliOptions = new CliOptions
        {
            ScriptFile = scriptFile,
            Url = url,
            OutputFile = outputFile,
            Visible = visible,
            TimeoutSeconds = timeout
        };

        return (cliOptions, apiOptions);
    }
}
