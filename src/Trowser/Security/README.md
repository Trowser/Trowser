# Security/

Scanners, probes, and orchestration for Trowser's security testing. About 280 files sit in this folder's root, grouped below by what they do; larger features have their own subfolders. To add a scanner, follow the recipe in [ARCHITECTURE.md](../../../ARCHITECTURE.md#add-a-security-scanner).

Naming is consistent enough to search by prefix: `Csrf*`, `Oidc*`, `PostMessage*`, `Ssti*`, and so on. A `*Checker`, `*Scanner`, or `*ScanProbe` is the entry point; `*Result`, `*Heuristics`, `*Helper`, and `*Payload(s)` support it.

## Shared plumbing (use these, do not reinvent)

| File | Purpose |
|------|---------|
| `SecurityFindingContract.cs` | `UnifiedSecurityFinding`, the finding shape REST, MCP, and scripts all emit |
| `Orchestration/SafetyMode.cs`, `Orchestration/SafetyGate.cs` | `passive` / `safe` / `active` / `aggressive`, and resolving it from a request |
| `SecurityProbeSafety.cs` | Safe-versus-destructive defaults and CLI ceilings |
| `SecurityProbeHttp.cs` | Cookie-isolated HTTP for probes |
| `DirectFetchHelper.cs` | Server-side fetch that carries the browser's cookie jar (HttpOnly included) |
| `RawHttpClient.cs` | Byte-exact HTTP/1.x over TCP/TLS, for smuggling and malformed requests |
| `ScanTimeout.cs` | Wall-clock caps safe for `CancelAfter` and millisecond conversion |
| `SecurityHostScope.cs`, `SecurityUrlPolicy.cs`, `SecurityPathExclusion.cs` | What is in scope; logout and session-ending URLs are excluded by default |
| `SecurityScanHygiene.cs`, `SecurityScanSessionGuard.cs`, `SecurityScanTabScope.cs` | Setup and teardown around active scans: dialogs, session checks, probe popups |
| `ScannerTrafficExclusion.cs` | Trowser's own traffic, kept out of maps and counts |
| `PayloadCatalog.cs`, `PayloadProfile.cs` | Built-in payload lists, optionally merged with external corpora |
| `InjectionPointDiscovery.cs`, `InjectionScaffold.cs`, `Injection*.cs` | Finding parameters to inject into, and sending the requests |
| `SideEffectIds.cs` | Recognising responses that created a server-side object |
| `SecurityFindingCorrelator.cs`, `SecurityFindingsExport.cs` | Cross-tool correlation and export for triage |
| `SecurityVerdictFixtures.cs` | Self-check fixtures for the XSS and SQLi verdict logic |

`SecurityPreflight.cs` exists both here and in `Orchestration/`. The root one checks whether captured traffic is enough to scan; the Orchestration one is the playbook preflight step.

## Scanners by bug class

| Class | Entry points |
|-------|--------------|
| Headers, CSP, TLS, cookies | `HeadersChecker`, `CspEvaluatorChecker`, `TlsIntrospectionChecker`, `SslManager`, `CookieAuditChecker`, `CookiePrefixBypassChecker`, `TrustedTypesPosture` |
| JavaScript and dependencies | `SecurityChecker` (Retire.js), `JavaScriptStaticAudit`, `SourceMapChecker`, `ScriptDiscovery`, `SecretsHarvestPipeline`, `AssetSecretsCommentMiner`; see also `SupplyChain/` |
| Attack surface and discovery | `AttackSurfaceMapper`, `ClientSurfaceMapper`, `ClientSurfaceRiskPlanner`, `EndpointScanner`, `ApiInventoryAnalyzer`, `OpenApiSpecLoader`, `Swaggering*`, `TechStackDetector`, `LightSiteCrawler` |
| XSS and client-side injection | `XssScanner`, `XssScanRunner`, `XssReflectionAnalyzer`, `XssStoredScanProbe`, `DomXssAuditRunner`, `InputTracer`, `Csti*`, `ClientPrototypePollutionScanner`, `ReflectedDomClobberProbe`; see also `DomFlow/`, `GadgetChains/`, `Runtime/` |
| Server-side injection | `Ssti*`, `NosqlScanProbe`, `LdapScanProbe`, `CmdCanaryProbe`, `PathTraversalChecker`, `UploadXxeProbe`, `DeserializationScanProbe`, `SqliLoginSweep`, `PrototypePollutionScanProbe` |
| SSRF and redirects | `SsrfChecker`, `SsrfOrchestrator`, `OpenRedirectChecker`, `DomOpenRedirectProber`, `RedirectParamDiscovery` |
| CSRF, CORS, clickjacking, framing | `CsrfChecker`, `Csrf*`, `JsonApiCsrfProber`, `CorsChecker`, `CorsSweep`, `ClickjackTester`, `ClickjackSweep`; see also `CrossSite/` |
| postMessage, XSSI, service workers, storage | `PostMessageAuditor` and `PostMessage*`, `XssiScanProbe`, `ServiceWorkerAuditor`, `StorageAuditChecker`; see also `XsLeaks/`, `WebSocket/` |
| Authentication and sessions | `AuthBrowserLogin`, `AuthControlIdentifier`, `Jwt*`, `OAuthFlowTester`, `OAuthFlowBreaker`, `Oidc*`, `Saml*`, `Session*`, `LogoutInvalidationProbe`, `PasswordResetWeakScanProbe`, `DefaultCredentialCanary`, `AccountEnumerationScanProbe` |
| Access control | `AuthzBoundaryService`, `AuthzComparisonService`, `AuthzRoleMatrixService`, `BflaAdminProbe`, `ObjectIdHarvester`, `MassAssignment*`, `IdentityStore`; see also `Authz/` |
| HTTP protocol and caching | `HttpRequestSmugglingScanner`, `HttpMethodsSecurityProbe`, `HostHeaderInjectionScanner`, `TrustedHeaderBypassChecker`, `PathFilterBypassChecker`, `Cache*Scanner`, `CacheHeaderAnalyzer`, `WafBypassProbe`, `FirewallTester`, `SubdomainTakeoverChecker` |
| Design, logic, availability | `InsecureDesignDiscovery`, `WorkflowSkipScanProbe`, `RaceConditionScanProbe`, `RateLimitAuditProbe`, `ReDoSScanProbe`, `BodySizeLimitProbe`, `CostlyOperations*`, `FailOpenScanProbe`, `ExceptionalConditionDiscovery`, `ForcedErrorScanner` |
| Automatic and continuous | `AutoScanPipeline` (map, then run the relevant scanners), `SecurityShadowManager` (Shadow: passive checks on every navigation), `RedTeamWhisperManager` / `WhisperClue` (hints for the tester, not findings), `PassiveNetworkResponseScanner` |
| Proof | `ExploitVerifier`, `ExecProofPoller`, `ProtectedResourceOracle`; see also `Workflow/`, `ChainEngine/` |
| GUI helpers | `PowerModeManager` (reveal hidden UI for manual testing) |

## Subfolders

| Folder | Purpose |
|--------|---------|
| `Orchestration/` | OWASP playbooks (`Playbooks/A01…A14`, `Quick`, `Full`), runner, budgets, safety mode, VPX rendering. A class implementing `IPlaybook` is discovered automatically |
| `Authz/` | Live authorization shadow and boundary testing across identities |
| `ChainEngine/` | Combining individual findings into higher-impact attack chains |
| `Workflow/` | Proof templates for chain proving |
| `CrossSite/` | Cross-site CSRF proof from a mocked attacker origin |
| `DomFlow/` | Source → JavaScript → DOM → sink chains from the runtime sensor |
| `GadgetChains/` | Clobbering and client prototype-pollution gadget probes |
| `Runtime/` | The shared in-page sensor for sinks, sources, and listeners |
| `XsLeaks/` | Cross-site leak techniques and posture |
| `WebSocket/` | WebSocket handshake and frame auditing |
| `SupplyChain/` | Retire.js, SRI, exposed manifests, OSV lookups |
| `Nuclei/` | Runner for a curated subset of nuclei HTTP templates |
| `LlmRedTeam/` | Probing in-page LLM chat widgets |
| `RaceLab/` | Race-condition analysis |
| `Vpx/` | VPX import and export (finding exchange format; spec in `securitykit/VPX/`) |
