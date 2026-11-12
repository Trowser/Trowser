# Trowser documentation map

Trowser exposes **one automation engine** through three interfaces. Keep docs in layers — generated inventories, hand-written guides, methodology.

## Which file to read

| You want to… | Read |
|--------------|------|
| See what Trowser is, and where it is going | **[VISION.md](VISION.md)** |
| Build from source, or run the tests | **[BUILD.md](BUILD.md)** |
| Contribute, or report a bug in Trowser itself | **[CONTRIBUTING.md](CONTRIBUTING.md)**, **[SECURITY.md](SECURITY.md)** |
| Find your way around the code; recipes for adding a route, tool, scanner, or test | **[ARCHITECTURE.md](ARCHITECTURE.md)**, **[src/Trowser/Security/README.md](src/Trowser/Security/README.md)** |
| Instructions for AI coding agents changing this repo | **[AGENTS.md](AGENTS.md)** |
| Scan every REST endpoint or MCP tool (names only) | **[trowserkit/trowser-api-index.md](trowserkit/trowser-api-index.md)** — auto-generated |
| Everyday REST endpoints in one small file (good LLM context) | **[trowserkit/trowser-api-core.md](trowserkit/trowser-api-core.md)** — maintained by hand |
| REST details: parameters, examples, safety modes, responses | **[trowserkit/trowser-api-reference.md](trowserkit/trowser-api-reference.md)** — maintained by hand |
| Write C# `.csx` scripts, Quicktests, recording | **[trowserkit/scripting-reference.md](trowserkit/scripting-reference.md)** — includes **Laws** (Shadow invariants) |
| Security testing workflow (playbooks, triage, proof) | **[trowserkit/SecurityTestingWithTrowser.md](trowserkit/SecurityTestingWithTrowser.md)** — methodology, FP triage, not an endpoint list |
| Security **Quicktests** (GUI menu names, REST parity, Trowser Twelve) | **[trowserkit/QuicktestsForSecurityTesting.md](trowserkit/QuicktestsForSecurityTesting.md)** — pairs with the methodology guide |
| Agent pitfalls (budgets, priority, CRITICAL without proof) | **[securitykit/AgentAntiPatterns.md](securitykit/AgentAntiPatterns.md)** |
| Scanner provenance / quality audit scorecard | **[securitykit/ScannerProvenanceAudit.md](securitykit/ScannerProvenanceAudit.md)** — inspired-by sources, oracles, accepted limits |
| VPX (information exchange for vulnerablities) | **[securitykit/VPX/](securitykit/VPX/)** |
| Run offline product regression (API/scanners) | **[tests/regression/README.md](tests/regression/README.md)** — `.\tests\regression\run-regression.ps1` |
| Try REST in a browser UI | **[trowserkit/swagger/](trowserkit/swagger/)** — partial OpenAPI (not all endpoints) |
| Attach prompts for external LLM agents | **[trowserkit/LLM_Prompt_*.txt](trowserkit/)** + API reference + optional SecurityTesting guide |

## Three interfaces

| Interface | Entry | Typical use |
|-----------|-------|-------------|
| **REST API** | `http://localhost:6923` | Scripts, CI, Copilot/CLI agents, PowerShell |
| **MCP** | `POST http://localhost:6923/mcp` | Cursor, Claude Desktop, other MCP clients |
| **C# scripting** | `Trowser.exe --run test.csx` | Batch suites, Quicktests, recorded flows |

MCP tool schemas and descriptions live in **`src/Trowser/Api/McpHandler.ToolDefinitions.cs`** (`GetAllToolDefinitions`). The built-in Chat window uses the same tools via `LlmToolExecutor` — prompts in **`src/Trowser/Resources/llm-system-prompt*.txt`** cover behavior only, not the full tool catalog. For repeatable suites, Assistant modes use **`browser_scripting_help`** (curated C# cheat sheet) plus C# scripting — not MCP tool-call JSON.

## Keeping docs consistent

After adding or renaming REST routes or MCP tools, regenerate the index and the OpenAPI file:

```powershell
.\scripts\regen-docs.ps1
```

Verify nothing drifted (CI-friendly):

```powershell
.\scripts\regen-docs.ps1 -Check
```

Also update **`trowser-api-reference.md`** when behavior, parameters, or examples change, and **`trowser-api-core.md`** when the change touches an endpoint it covers. Update **`SecurityTestingWithTrowser.md`** only when testing *methodology* changes (new playbooks, new proof patterns).

Optional: extend **`HandleGetHelp`** in `TrowserApiServer.GetHandlers.cs` (`GET /api`) so live help stays aligned — the index generator merges that catalog with routed endpoints.

## AI agents

Two audiences, two files:

- **Changing Trowser's code:** **[AGENTS.md](AGENTS.md)**, read automatically by Cursor, Copilot, Codex, and most other coding agents. `.github/copilot-instructions.md` only points there.
- **Testing a site with Trowser:** **[trowserkit/trowser.mdc](trowserkit/trowser.mdc)**, product context and workflow for Cursor (not a tool inventory). Release ZIPs ship it as `trowserkit/.cursor/rules/trowser.mdc`.

When testing outside the IDE, attach **`trowser-api-core.md`** for everyday testing, or **`trowser-api-reference.md`** for the full surface (and **`SecurityTestingWithTrowser.md`** for security work) to your agent instead of relying on editor rules.
