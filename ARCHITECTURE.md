# Trowser architecture

How the code is laid out, how a request travels through it, and step-by-step recipes for the changes contributors make most often. For build commands and the rules every change must follow, see [AGENTS.md](AGENTS.md) and [CONTRIBUTING.md](CONTRIBUTING.md).

## The shape of it

Trowser is one WPF application (`src/Trowser/`, .NET 8, `win-x64`) hosting WebView2 tabs. A single automation engine, `AutomationContext`, drives those tabs. Everything else is a way of reaching it:

```text
 GUI (MainWindow)    REST /api/*         MCP POST /mcp        Built-in Chat        C# scripts (.csx)
        │                 │                    │                    │                    │
        │                 └──── TrowserApiServer (HttpListener, localhost) ──┐            │
        │                         auth · safe mode · one-at-a-time gate      │            │
        │                                      │                    │        │            │
        │                                      ▼                    ▼        │            │
        │                              McpHandler.ExecuteToolAsync ◄─ LlmToolExecutor     │
        │                                      │                                          │
        ▼                                      ▼                                          ▼
 ┌─────────────────────────────────────── AutomationContext ───────────────────────────────────────┐
 │ navigation · interaction · inspection · network/mocks · storage · audits · security entry points │
 └───────────────┬───────────────────────────────┬─────────────────────────────────────────────────┘
                 ▼                               ▼
         BrowserTab / WebView2          Scanners and services (Security/, Accessibility/, Laws/, …)
```

- **REST**: `TrowserApiServer.HandleRequestAsync` (in `TrowserApiServer.Routing.cs`) checks the Host header and cross-site requests, lets a few routes skip the queue (`/api/ping`, `/api/abort`, `/api/force-navigate`), checks the bearer key, applies `SafeModePolicy` when `--safe` is on, lets in-memory read-only routes skip the queue, then waits on a `SemaphoreSlim` gate so only one browser operation runs at a time. `RouteRequestAsync` is a large `switch (path)` that calls a `HandleXxx` method.
- **MCP**: `POST /mcp` goes through the same pipeline and lands in `McpHandler`. `ExecuteToolAsync` (in `McpHandler.Protocol.cs`) is the single tool dispatcher: it normalises aliases, applies safe mode and the active tool pack, then a `switch` calls a `ToolXxx` method.
- **Built-in Chat**: `Chat/LlmToolExecutor` sends model tool calls to the same `McpHandler.ExecuteToolAsync`, so Chat, external MCP clients, and safe mode cannot drift apart.
- **Scripts**: `Scripting/ScriptEngine` runs Roslyn `CSharpScript` with `AutomationContext` as the globals object. Every public member of `AutomationContext` is therefore script API (`await Click("#go")`). Quicktests, the regression suite, and `Trowser.exe --run` all use this path.
- **GUI**: `MainWindow` calls `AutomationContext` directly and hosts the API server, Script Console, journal, and Chat panel.

All WebView2 access has to happen on the UI thread. `AutomationContext.RunJs` / `RunJsAsync` (in `AutomationContext.cs`) marshal through the dispatcher and handle timeouts and cancellation; use them rather than touching `CoreWebView2` from a background thread.

## Where things live

| Path | What it holds |
|------|---------------|
| `src/Trowser/Api/` | `TrowserApiServer.*` (REST), `McpHandler.*` (MCP), `SafeModePolicy`, request parsers, path guards |
| `src/Trowser/Automation/` | `AutomationContext.*` (the engine), `BrowserTab`, network log, mocks and intercepts, locators |
| `src/Trowser/Security/` | Scanners, probes, playbooks, Shadow. Grouped in [its own README](src/Trowser/Security/README.md) |
| `src/Trowser/Scripting/` | Roslyn host, compile hints, the `browser_scripting_help` catalog |
| `src/Trowser/Chat/` | Built-in AI assistant: LLM clients, tool executor, context compaction |
| `src/Trowser/Laws/` | Laws (Shadow invariants written in C#), sandbox, Quicktest metadata |
| `src/Trowser/Recording/` | Records GUI interaction into `.csx` |
| `src/Trowser/SessionLog/` | Journal, session log, HTML reports |
| `src/Trowser/Peers/` | Multi-instance testing (second identity, mirroring, BOLA) |
| `src/Trowser/Accessibility/`, `Performance/`, `HtmlValidation/`, `LinkChecking/`, `Seo/`, `Compatibility/`, `Consistency/`, `ThirdParty/`, `MixedContent/`, `XssAudit/` | One audit each, usually a checker plus a result type |
| `src/Trowser/Robustness/`, `ResourceUsage/`, `RaceLab/`, `EndpointProbe/` | Monkey testing, fault injection, resource probes, race testing |
| `src/Trowser/Resources/` | Embedded JS libraries (axe, gremlins, html-validate, …), Quicktests, system prompts, help pages |
| `src/Trowser/*.cs` (root) | Dialogs, settings, small app-wide services |
| `src/Trowser.Tests/` | xUnit unit and static-contract tests (no browser) |
| `src/Trowser.ApiTests/` | xUnit tests that start `Trowser.exe --serve` and call REST/MCP |
| `tests/regression/` | Black-box `.csx` oracles run through `Trowser.exe --run` |
| `trowserkit/` | User-facing docs, the API reference, the generated index, OpenAPI |
| `scripts/` | Test runner, doc generators, release and signing scripts |

### The four big partial classes

These classes are split by feature into partial files. Find the right file by feature name, then search inside it; several are thousands of lines long.

**`TrowserApiServer`** (`src/Trowser/Api/`)

| File | Owns |
|------|------|
| `TrowserApiServer.cs` | Construction, lifecycle, and many older handlers not yet moved to a feature file |
| `.Routing.cs` | `HandleRequestAsync` pipeline, gate, `RouteRequestAsync` switch, abort |
| `.JsonHelpers.cs` | `ReadJsonBody`, `WriteSuccess`, `WriteError`, `RespondAsync` |
| `.GetHandlers.cs` | GET routes, and `HandleGetHelp` (`GET /api`) whose descriptions feed the API index |
| `.InputHandlers.cs` | Click, type, key, hover, scroll, drag, upload |
| `.InterceptHandlers.cs`, `.RawFetchHandlers.cs` | Mocks, intercepts, raw HTTP |
| `.PostSecurity*.cs` | Security routes by family: `Scan`, `Injection`, `Auth`, `Client`, `Ssrf`, `SupplyChain`, `Llm`, `Nuclei` |
| `.AuthzHandlers.cs`, `.IdentityHandlers.cs`, `.ChainHandlers.cs` | Authorization testing, identities, attack chains |
| `.JournalHandlers.cs`, `.DecisionHandlers.cs`, `.PointerHandlers.cs`, `.RecordHandlers.cs`, `.ReproHandlers.cs`, `.LawsHandlers.cs`, `.RaceLab.cs` | One feature each |
| `.AssertsAndScenarios.cs`, `.PlaywrightParityHandlers.cs` | Assertions, batch scenarios, Playwright-style helpers |

**`McpHandler`** (`src/Trowser/Api/`)

| File | Owns |
|------|------|
| `McpHandler.ToolDefinitions.cs` | Every tool's name, description, and JSON schema (`Tool(...)`), plus the tool packs |
| `McpHandler.Protocol.cs` | JSON-RPC methods and `ExecuteToolAsync`, the dispatch `switch` |
| `McpHandler.ToolsBrowser.cs` | Browser, interaction, and audit tools |
| `McpHandler.ToolsSecurity*.cs`, `.ToolsDecision.cs`, `.ToolsPointer.cs`, `.ToolsRaceLab.cs`, `.ToolsMeta.cs` | Tools by family, mirroring the REST files |
| `McpHandler.ElementResolution.cs` | Turning `ref` / selector / semantic locator arguments into a target |
| `McpHandler.Helpers.cs` | `TextContent`, `ErrorContent`, `RenderHostSafe`, argument getters |

**`AutomationContext`** (`src/Trowser/Automation/`): `.Navigation`, `.Interaction`, `.Inspection`, `.Frames`, `.Network`, `.Storage`, `.BrowserSession`, `.Downloads`, `.Emulation`, `.Viewport`, `.TabTargeting`, `.Trace`, `.Audits`, `.Security`, `.AttackForm`, `.Laws`, `.Peers`, `.Quicktests`, `.RaceLab`. The core file holds state, `RunJs`, and the async callback bridge.

**`MainWindow`** (`src/Trowser/MainWindow.xaml.*.cs`): one partial file per GUI area (`Tabs`, `AddressBar`, `Scripting`, `Journal`, `Server`, `Cli`, `Logging`, …).

## Tool packs and safety

Two separate mechanisms control what a caller may do. Do not confuse them.

- **`--safe` (`SafeModePolicy`)** is a process-wide switch. It blocks whole operations — scripting, raw HTTP, mocks, session changes, active probes — on every surface. Operations are listed by key in `Api/SafeModePolicy.cs`; a route `/api/security/xss-scan` has key `security_xss_scan`, and tool `browser_security_xss_scan` maps to the same key.
- **`safetyMode` (`Security/Orchestration/SafetyMode.cs`)** is a per-call argument on security operations: `passive` (no outbound requests) → `safe` (GET/HEAD/OPTIONS only, the default) → `active` (all verbs, may create data) → `aggressive` (stress, brute force). Resolve it with `SafetyGate.Resolve(body)` or `SafetyGate.Resolve(args)`; CLI flags cap it.

MCP tools are also grouped into **packs** in `McpHandler.ToolDefinitions.cs`:

| Pack | Who sees it | Contents |
|------|-------------|----------|
| `CoreTools` | External MCP clients by default (`?mode=core`) | Allow-list; must stay under 128 tools (`LlmToolExecutor.CopilotMaxTools`) |
| Security (`?mode=security`, alias `full`) | External MCP clients that opt in | Every defined tool |
| `EconomicalTools` | Built-in Chat in Economical mode | Allow-list |
| `ChatTools` | Built-in Chat in Chat mode | Small allow-list |
| Full | Built-in Chat in Full mode | Every defined tool |

A new tool is automatically in Security and Full. Add it to an allow-list only if everyday testers need it; the Core pack has a hard size limit.

## Recipes

### Add a REST route with a matching MCP tool

The preferred pattern puts parsing and logic in one shared builder that both surfaces call. `POST /api/security/xssi-scan` / `browser_security_xssi_scan` is a compact example to copy.

1. **Engine.** Add the behavior as a public method on the matching `AutomationContext.*.cs` partial, or in a service class it calls. A public method on `AutomationContext` is also script API, so name it the way a script author would read it.
2. **REST builder.** In the matching `TrowserApiServer.*.cs` file:
   ```csharp
   private Task HandlePostFooBar(HttpListenerRequest request, HttpListenerResponse response) =>
       RespondAsync(request, response, BuildFooBarAsync);

   internal async Task<object> BuildFooBarAsync(JsonBody body)
   {
       var limit = body.GetInt("limit", 10);
       if (limit <= 0)
           throw new ApiCommandException(400, "limit must be positive");
       return await _context.FooBarAsync(limit);
   }
   ```
   Throw `ApiCommandException` for client errors; `RespondAsync` turns it into the standard `{ success: false, error }` response.
3. **Route.** Add `case "/api/foo-bar" when method == "POST":` to `RouteRequestAsync` in `TrowserApiServer.Routing.cs`. If the route only reads in-memory state, consider `IsGateFreeReadOnly`; if it drives the page, check whether it belongs in `ShouldPreferAgentTab`.
4. **Help entry.** Add a `new { method = "POST", path = "/api/foo-bar", description = "…" }` line to `HandleGetHelp` in `TrowserApiServer.GetHandlers.cs`. The API index takes its one-line description from here.
5. **MCP definition.** Add `Tool("browser_foo_bar", "description", Schema(...))` in `McpHandler.ToolDefinitions.cs`. Write the description for a model that has never seen Trowser: what it does, when to use it, what it needs first.
6. **MCP implementation.** In the matching `McpHandler.Tools*.cs` file:
   ```csharp
   private Task<object> ToolFooBar(JsonElement args) =>
       RenderHostSafe(args, h => h.BuildFooBarAsync);
   ```
7. **Dispatch.** Add `"browser_foo_bar" => await ToolFooBar(arguments),` to the `switch` in `McpHandler.ExecuteToolAsync` (`McpHandler.Protocol.cs`). `McpToolSchemaTests` fails if you forget.
8. **Safe mode.** If the operation runs code, sends raw HTTP, changes session state, or probes actively, add its key (`foo_bar`) to `SafeModePolicy.BlockedOperations`.
9. **Pack.** Add the tool to `CoreTools` / `EconomicalTools` only if it belongs there (see above).
10. **Docs.** Describe parameters and an example in `trowserkit/trowser-api-reference.md`, then run `.\scripts\regen-docs.ps1`. If the method is script API, add it to `trowserkit/scripting-reference.md` and, if it is common, to `Resources/scripting-help.txt` (what `browser_scripting_help` returns) and `Resources/script-help.html` (the Script Console help page).
11. **Tests.** A parity row in `src/Trowser.ApiTests/ParityCatalog.cs` proves REST and MCP agree; a regression `.csx` proves the behavior (recipes below).

Naming: tool `browser_foo_bar` ↔ route `/api/foo-bar`. `SafeModePolicyTests` pairs tools and routes by that convention through the API index; if your names cannot follow it, add the pair to `Get-McpRestHint` in `scripts/generate-api-index.core.ps1`.

Older handlers parse the body twice (once in `HandlePostX`, once in `ToolX`). Do not copy that; use the shared builder.

### Add a security scanner

1. Put the scanner in `src/Trowser/Security/` (or the matching subfolder): a class that takes `AutomationContext` and an options record, and returns a result type with `ToApiResponse()`. `XssiScanProbe` is a small, complete example.
2. Decide its minimum `safetyMode` and enforce it at the top of the builder with `SafetyGate.Resolve(body)`. Passive scanners read the network log only. Anything that sends state-changing requests requires `active`.
3. Emit findings as `UnifiedSecurityFinding` (`SecurityFindingContract.cs`) so correlation, export, and VPX pick them up.
4. Use the shared plumbing instead of `new HttpClient()`: `SecurityProbeHttp` for cookie-isolated probes, `DirectFetchHelper` for requests with the browser's cookie jar, `ScanTimeout` for wall-clock caps, `SecurityHostScope` / `SecurityUrlPolicy` / `SecurityPathExclusion` for what is in scope (never probe logout URLs), `SecurityScanHygiene` for dialog cleanup after proofs.
5. Expose it with the route-and-tool recipe above, usually in `TrowserApiServer.PostSecurity<Family>.cs` and `McpHandler.ToolsSecurity<Family>.cs`.
6. Add a regression oracle under `tests/regression/security/` with a positive fixture and a clean twin, so both false negatives and false positives are caught.
7. If it belongs in an OWASP playbook, call it from the matching class in `Security/Orchestration/Playbooks/`. Playbooks implement `IPlaybook` and are discovered by reflection (`PlaybookRegistry`); a new playbook class is picked up automatically.
8. Record where the technique came from in `securitykit/ScannerProvenanceAudit.md`.

### Add a built-in Quicktest

1. Add a `.csx` under `src/Trowser/Resources/Quicktests/<Category>/`. Everything there is embedded automatically (`Trowser.csproj` includes `Resources\Quicktests\**\*.csx`) and appears in the GUI menu by folder.
2. Start it with metadata headers:
   ```csharp
   // @title Back and forward
   // @shadow light
   // @effects none
   ```
   `@effects none` means the script only reads; only those may run inside Shadow. Use `mutates` if it clicks, types, or sends requests.
3. `ScriptCompileTests` compiles every embedded Quicktest against the scripting surface, so `.\scripts\test.ps1 -Level quick` catches API mistakes. Run it in the built app too.
4. If it is aimed at users, list it in `trowserkit/scripting-reference.md` (Quicktests section); security Quicktests also go in `trowserkit/QuicktestsForSecurityTesting.md`.

Product-specific checks do not belong here; users keep those in their own `UserQuicktests` folder.

### Add a regression test

1. Add `tests/regression/functional/NN-name.csx` or `tests/regression/security/NN-name.csx`. The runner prepends `_prelude.csx`, so helpers such as `SetupPage(url, html, headers)`, `SecureHeaders()`, and `VulnerableHeaders()` are available.
2. Build the target page in memory with mocks on `https://trowser-regression.test`; never depend on the internet.
3. Assert on content (finding titles, counts, text), not just "did not throw". For scanners, add a clean twin that must produce no finding.
4. Run it alone: `.\tests\regression\run-regression.ps1 -Filter "NN-name*"`. `ScriptCompileTests` also compiles it.

## Generated and owned files

| File | Source of truth | How to update |
|------|-----------------|---------------|
| `trowserkit/trowser-api-index.md` | Route `case`s, `HandleGetHelp`, `Tool(...)` definitions | `.\scripts\regen-docs.ps1` — CI fails if stale |
| `trowserkit/swagger/openapi.yaml` | The index plus hand-written schemas | `.\scripts\regen-docs.ps1`; placeholder count must not exceed `tests/baselines/openapi-stubs.txt` |
| `tests/api-coverage.md` (not committed) | Routes and tools not referenced by tests — a good source of first issues | `.\scripts\api-coverage-report.ps1` |
| `trowserkit/trowser-api-reference.md` | Hand-written | Edit with the change |
| `CHANGELOG.md` | The maintainer | Do not edit |

## Tests that guard the structure

| Test | Fails when |
|------|------------|
| `McpToolSchemaTests` | A `Tool(...)` has no dispatch arm, or a Core-pack name is not defined |
| `McpDispatchParityTests` | A tool advertised in `tools/list` would answer "Unknown tool" |
| `SafeModePolicyTests` | A tool and its REST route are not blocked alike, or a blocked key matches nothing |
| `ScriptCompileTests` | A Quicktest or regression script no longer compiles against `AutomationContext` |
| `OpenApiSpecTests` | `openapi.yaml` and the index disagree, or placeholder operations exceed the baseline |
| ApiTests `TransportParityTests` | REST and MCP give different results for a parity case |
