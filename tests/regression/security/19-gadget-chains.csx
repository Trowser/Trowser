// Security: gadget chains — dom-flow window-name attribution + gadget chain planner smoke.

await ResetBrowserState();

Assert.Section("window-name probe — no Trowser innerHTML self-exec on static page");
ClearMocks();
var staticHtml = MinimalHtml("WinName", "<h1>Static</h1><p>No app reader.</p>");
SetupPage(FixtureUrl("/winname-static"), staticHtml, ScriptableHeaders());
await PrepareRuntimeSensorForNavigationAsync();
await Navigate(FixtureUrl("/winname-static"));
await WaitForIdle();
await InstallRuntimeSensorAsync();

var winProbed = await RunDomFlowsAsync("probe", sources: new[] { "window-name" });
Log($"window-name probe: {winProbed.Summary} exploitable={winProbed.ExploitableChainCount}");
Assert.True(winProbed.ExploitableChainCount == 0,
    "window-name probe must not self-inject innerHTML in Trowser");
Assert.True(!winProbed.Chains.Any(c => c.Tier == "exploitable" && c.Consequence == "exec"),
    "no exploitable exec from window-name probe scaffolding");

Assert.Section("gadget chain scan — planner returns on clean page");
await ResetBrowserState();
ClearMocks();
SetupPage(FixtureUrl("/gadget-clean"), MinimalHtml("Clean", "<p>Hello</p>"), ScriptableHeaders());
await Navigate(FixtureUrl("/gadget-clean"));
await WaitForIdle();
await InstallRuntimeSensorAsync();

var plan = Trowser.Security.GadgetChains.GadgetChainPlanner.Build(
    new List<Trowser.Security.Runtime.GadgetRadarService.GadgetRadarHit>(),
    surface: null,
    active: true,
    requestedProbes: new[] { "clobber", "client-pp", "dom-flow-probe" });
Log($"planner selected: {string.Join(", ", plan.SelectedProbes)}");
Assert.True(plan.SelectedProbes.Contains("client-pp") && plan.SelectedProbes.Contains("dom-flow-probe"),
    "planner selects PP and dom-flow on clean evidence");
Assert.True(!plan.SelectedProbes.Contains("clobber"),
    "clobber skipped without trap-based clobber-eligible radar hits");
