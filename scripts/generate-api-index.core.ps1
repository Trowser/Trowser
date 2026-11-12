# Generates trowserkit/trowser-api-index.md (invoked by generate-api-index.ps1). Requires PowerShell 7+.

param(
    [switch]$Check
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path $PSScriptRoot -Parent
$apiServerGlob = Join-Path $repoRoot 'src\Trowser\Api\TrowserApiServer*.cs'
$mcpDefinitionsPath = Join-Path $repoRoot 'src\Trowser\Api\McpHandler.ToolDefinitions.cs'
$referencePath = Join-Path $repoRoot 'trowserkit\trowser-api-reference.md'
$outputPath = Join-Path $repoRoot 'trowserkit\trowser-api-index.md'

function Get-RegexNotQuoteClass([char]$QuoteChar) {
    return [string]::Concat('[', '^', [string]$QuoteChar, ']')
}

function Get-FirstSentence([string]$Text) {
    if ([string]::IsNullOrWhiteSpace($Text)) { return '' }
    $one = ($Text -replace '\s+', ' ').Trim()
    if ($one.Length -le 120) { return $one }
    $dot = $one.IndexOf('. ')
    if ($dot -gt 20 -and $dot -lt 160) { return $one.Substring(0, $dot + 1) }
    return $one.Substring(0, [Math]::Min(120, $one.Length)).TrimEnd() + '…'
}

function Get-PathCategory([string]$Path) {
    switch -Regex ($Path) {
        '^/api/journal' { return 'Session Log' }
        '^/api/(pointer|pointers|checkpoint|checkpoints)' { return 'Pointers & Checkpoints' }
        '^/api/decision' { return 'Decisions' }
        '^/api/repro' { return 'Repro & Verification' }
        '^/api/inspiration' { return 'Inspiration' }
        '^/api/message' { return 'Notifications' }
        '^/api/(ping|abort|force-navigate|info|state|diff-state|interactive|screenshot|page-text|source|console|network|clear-all|clear-session|assertions)$' { return 'Page State & Inspection' }
        '^/api/state/' { return 'Page State & Inspection' }
        '^/api/(navigate|go-back|go-forward|settings/scope|settings/throttle|wait-for-navigation|wait-for-final-navigation|wait-for-idle)$' { return 'Navigation' }
        '^/api/(click|type|upload|find|select|hover|scroll|key)$' { return 'Element Interaction' }
        '^/api/find/' { return 'Element Interaction' }
        '^/api/(text|extract-text|attribute|property|extract)$' { return 'Element Data' }
        '^/api/(execute-js|execute-script|batch|test-scenario)$' { return 'Script Execution' }
        '^/api/(wait|wait-for-network)$' { return 'Waiting' }
        '^/api/assert' { return 'Assertions' }
        '^/api/dialog' { return 'Dialog Handling' }
        '^/api/cookies' { return 'Cookies' }
        '^/api/storage' { return 'Web Storage' }
        '^/api/viewport' { return 'Viewport (Responsive Testing)' }
        '^/api/screen-curtain' { return 'Viewport (Responsive Testing)' }
        '^/api/tabs' { return 'Tab Management' }
        '^/api/webmcp' { return 'Web MCP (Page-Registered Tools)' }
        '^/api/mock' { return 'Network Mocking (Fault Injection)' }
        '^/api/intercept' { return 'Network Interception (Request Breakpoints)' }
        '^/api/load-test' { return 'Load Testing' }
        '^/api/fetch' { return 'Browser Fetch (API Testing)' }
        '^/api/header-overrides' { return 'Header Overrides' }
        '^/api/network/throttle' { return 'Network Throttling' }
        '^/api/network/\d+$' { return 'Page State & Inspection' }
        '^/api/(monkey-test|monkey-trowser|interrupter|fuzz)' { return 'Robustness Testing' }
        '^/api/peer' { return 'Peer Management (Cross-Instance Testing)' }
        '^/api/peers' { return 'Peer Management (Cross-Instance Testing)' }
        '^/api/authz' { return 'Authorization Testing' }
        '^/api/(identity|identities|session/identity)' { return 'Portable Identity' }
        '^/api/orchestrate' { return 'Security Orchestration (Playbooks)' }
        '^/api/vpx' { return 'VPX (Vulnerability Proof Exchange)' }
        '^/api/ssl' { return 'Client TLS Certificates' }
        '^/api/websocket' { return 'WebSocket' }
        '^/api/shadows' { return 'Shadows (Ambient UI)' }
        '^/api/(test-data|scripting-help)$' { return 'Utilities' }
        '^/api/security' { return 'Security Testing' }
        '^/api/(audit-all|quicktest|accessibility|tab-order|performance|validate-html|seo|compatibility|check-links|consistency|third-party|page-text/structured)$' { return 'Auditing & Analysis' }
        default { return 'Other' }
    }
}

function Get-RestPurposeFromReference {
    param([hashtable]$Map)
    if (-not (Test-Path $referencePath)) { return }
    $ref = Get-Content $referencePath -Raw
    $notStar = [string]::Concat('[', '^', '*', ']')
    $notNl = [string]::Concat('[', '^', "`r`n", ']')
    # Description runs to end of line, and must not treat '#' as required. $notNl already closes the class.
    $descClass = [string]::Concat('[', '^', "`r`n", '#]')
    $refHeaderPattern = [string]::Concat(
        '(?ms)^### (GET|POST|PUT|DELETE|PATCH) (/api/',
        $notNl, '+',
        ')\r?\n(?:\*\*',
        $notStar, '+\*\* — )?(',
        $descClass, '+)'
    )
    [regex]::Matches($ref, $refHeaderPattern) | ForEach-Object {
        $key = "$($_.Groups[1].Value) $($_.Groups[2].Value)"
        if (-not $Map.ContainsKey($key)) {
            $Map[$key] = (Get-FirstSentence $_.Groups[3].Value)
        }
    }
}

function Get-AutoPurpose([string]$Method, [string]$Path) {
    $segment = ($Path -replace '^/api/', '') -replace '/', ' '
    $braceParam = [string]::Concat('\{', '[', '^', '}', ']', '+', '\}')
    $segment = ($segment -replace '-', ' ' -replace $braceParam, 'param').Trim()
    if ($segment -eq 'security') { return 'JavaScript CVE scan (Retire.js)' }
    return (Get-FirstSentence "$Method $Path — $segment")
}

function Get-RestEndpoints {
    $apiText = (Get-ChildItem $apiServerGlob | Sort-Object Name | ForEach-Object { Get-Content $_.FullName -Raw }) -join "`n"
    $endpoints = @{}

    $restMetaPattern = @"
new \{ method = "(GET|POST|PUT|DELETE|PATCH)", path = "([^`"]+)", description = "((?:\\.|[^`"\\])*)"
"@
    [regex]::Matches($apiText, $restMetaPattern) | ForEach-Object {
        $desc = $_.Groups[3].Value -replace '\\"', '"'
        $key = "$($_.Groups[1].Value) $($_.Groups[2].Value)"
        $endpoints[$key] = [ordered]@{
            Method = $_.Groups[1].Value
            Path = $_.Groups[2].Value
            Purpose = (Get-FirstSentence $desc)
        }
    }

    $casePattern = @"
case "(/api/[^`"]+)" when method == "(GET|POST|PUT|DELETE|PATCH)"
"@
    [regex]::Matches($apiText, $casePattern) | ForEach-Object {
        $key = "$($_.Groups[2].Value) $($_.Groups[1].Value)"
        if (-not $endpoints.ContainsKey($key)) {
            $endpoints[$key] = [ordered]@{
                Method = $_.Groups[2].Value
                Path = $_.Groups[1].Value
                Purpose = ''
            }
        }
    }

    $caseMultiMethodPattern = @"
case "(/api/[^`"]+)" when method is "(GET|POST|PUT|DELETE|PATCH)" or "(GET|POST|PUT|DELETE|PATCH)"
"@
    [regex]::Matches($apiText, $caseMultiMethodPattern) | ForEach-Object {
        $path = $_.Groups[1].Value
        $m1 = $_.Groups[2].Value
        $m2 = $_.Groups[3].Value
        foreach ($method in @($m1, $m2)) {
            $key = "$method $path"
            if (-not $endpoints.ContainsKey($key)) {
                $endpoints[$key] = [ordered]@{
                    Method = $method
                    Path = $path
                    Purpose = ''
                }
            }
        }
    }

    # Dynamic routes not in switch cases (prefix routers in *Handlers.cs)
    foreach ($extra in @(
            @{ Method = 'DELETE'; Path = '/api/peer/{name}'; Purpose = 'Remove a registered peer Trowser instance' }
            @{ Method = 'GET'; Path = '/api/pointer/{id}'; Purpose = '' }
            @{ Method = 'DELETE'; Path = '/api/pointer/{id}'; Purpose = '' }
            @{ Method = 'POST'; Path = '/api/pointer/{id}/resolve'; Purpose = '' }
            @{ Method = 'GET'; Path = '/api/checkpoint/{id}'; Purpose = '' }
            @{ Method = 'GET'; Path = '/api/decision/{id}'; Purpose = '' }
            @{ Method = 'POST'; Path = '/api/decision/{id}/answer'; Purpose = '' }
            @{ Method = 'DELETE'; Path = '/api/decision/{id}'; Purpose = '' }
        )) {
        $key = "$($extra.Method) $($extra.Path)"
        if (-not $endpoints.ContainsKey($key)) {
            $endpoints[$key] = [ordered]@{
                Method = $extra.Method
                Path = $extra.Path
                Purpose = $extra.Purpose
            }
        }
    }

    $refMap = @{}
    Get-RestPurposeFromReference -Map $refMap

    foreach ($key in @($endpoints.Keys)) {
        if ([string]::IsNullOrWhiteSpace($endpoints[$key].Purpose)) {
            if ($refMap.ContainsKey($key)) {
                $endpoints[$key].Purpose = $refMap[$key]
            } else {
                $endpoints[$key].Purpose = Get-AutoPurpose $endpoints[$key].Method $endpoints[$key].Path
            }
        }
    }

    # Easter-egg / undocumented routes (implemented but omitted from public API docs).
    foreach ($hiddenPath in @('/api/mandelbrot')) {
        foreach ($key in @($endpoints.Keys)) {
            if ($endpoints[$key].Path -eq $hiddenPath) {
                $endpoints.Remove($key) | Out-Null
            }
        }
    }

    $ordered = foreach ($key in ($endpoints.Keys | Sort-Object)) {
        $ep = $endpoints[$key]
        [pscustomobject]@{ Method = $ep.Method; Path = $ep.Path; Purpose = $ep.Purpose }
    }
    return @($ordered | Sort-Object -Property Path, Method, Purpose -Stable)
}

function Get-McpTools {
    $text = Get-Content $mcpDefinitionsPath -Raw
    $tools = @{}
    $toolPattern = @"
Tool\("([^`"]+)",\s*"((?:\\.|[^`"\\])*)"
"@
    [regex]::Matches($text, $toolPattern) | ForEach-Object {
        $name = $_.Groups[1].Value
        $desc = ($_.Groups[2].Value -replace '\\"', '"') -replace '\s+', ' '
        $tools[$name] = Get-FirstSentence $desc
    }

    return ($tools.GetEnumerator() | Sort-Object Name)
}

function Get-McpRestHint([string]$ToolName) {
    switch ($ToolName) {
        'get_test_heuristics' { return '(embedded resource)' }
        'browser_security_help' { return '(MCP only)' }
        'browser_compact' { return '(built-in Chat only)' }
        'browser_session_memory' { return '(built-in Chat only)' }
        'browser_assert_element' { return 'POST /api/assert/*' }
        'browser_authz_model' { return 'GET/PUT /api/authz/model' }
        'browser_security_llm_endpoint_discover' { return 'GET or POST /api/security/llm-endpoint-discover' }
        'browser_race_lab_profiles' { return 'GET/POST /api/race-lab/profiles' }
        'browser_identity_handoff' { return 'GET/POST /api/identity/handoff' }
        'browser_laws' { return 'GET /api/laws' }
    }

    if ($ToolName -notmatch '^browser_(.+)$') { return '' }
    $tail = $Matches[1]

    if ($tail -eq 'security') { return 'POST /api/security' }
    if ($tail -eq 'security_headers') { return 'POST /api/security/headers' }
    if ($tail -match '^security_(.+)$') {
        $sub = $Matches[1] -replace '_', '-'
        if ($sub -match '(^llm-redteam-probes$|^nuclei-templates$)') {
            return "GET /api/security/$sub"
        }
        return "POST /api/security/$sub"
    }

    if ($tail -match '^peer_(.+)$') {
        if ($Matches[1] -eq 'unregister') { return 'DELETE /api/peer/{name}' }
        if ($Matches[1] -eq 'identity_apply') { return 'POST /api/peer/identity/apply' }
        return "POST /api/peer/$($Matches[1] -replace '_', '-')"
    }
    if ($tail -eq 'peers') { return 'GET /api/peers' }

    if ($tail -match '^race_lab_(.+)$') {
        return "POST /api/race-lab/$($Matches[1] -replace '_', '-')"
    }

    if ($tail -match '^authz_(.+)$') {
        return "POST /api/authz/$($Matches[1] -replace '_', '-')"
    }

    if ($tail -match '^orchestrate_(.+)$') {
        switch ($Matches[1]) {
            'list' { return 'GET /api/orchestrate/playbooks' }
            'dry_run' { return 'POST /api/orchestrate/dry-run/{id}' }
            'run' { return 'POST /api/orchestrate/{id}' }
        }
    }

    if ($tail -match '^journal_(.+)$') {
        switch ($Matches[1]) {
            'get' { return 'GET /api/journal' }
            'add' { return 'POST /api/journal' }
            'update' { return 'PATCH /api/journal' }
            'delete' { return 'DELETE /api/journal' }
            'export' { return 'GET /api/journal/export' }
            'import' { return 'POST /api/journal/import' }
        }
    }

    if ($tail -match '^record_(.+)$') {
        switch ($Matches[1]) {
            'start' { return 'POST /api/record/start' }
            'status' { return 'GET /api/record/status' }
            'stop' { return 'POST /api/record/stop' }
        }
    }

    if ($tail -match '^repro_(.+)$') {
        return "POST /api/repro/$($Matches[1] -replace '_', '-')"
    }

    if ($tail -match '^vpx_(.+)$') {
        switch ($Matches[1]) {
            'export' { return 'GET /api/vpx/export' }
            'import' { return 'POST /api/vpx/import' }
            'clear' { return 'POST /api/vpx/clear' }
            'render' { return 'POST /api/vpx/render' }
        }
    }

    if ($tail -match '^resource_(.+)$') {
        return "POST /api/resource/$($Matches[1] -replace '_', '-')"
    }

    if ($tail -match '^ssl_(.+)$') {
        switch ($Matches[1]) {
            'list' { return 'GET /api/ssl/certificates' }
            'add' { return 'POST /api/ssl/certificates' }
            'remove' { return 'DELETE /api/ssl/certificates' }
            'set_active' { return 'POST /api/ssl/certificates/active' }
            'get_active' { return 'GET /api/ssl/certificates/active' }
        }
    }

    if ($tail -match '^saml_(.+)$') {
        return "POST /api/security/saml-$($Matches[1] -replace '_', '-')"
    }

    if ($tail -match '^sse_(.+)$') {
        return "GET /api/sse/$($Matches[1] -replace '_', '-')"
    }

    if ($tail -match '^websocket_(.+)$') {
        return "POST /api/websocket/$($Matches[1] -replace '_', '-')"
    }

    if ($tail -match '^fetch_(.+)$') {
        switch ($Matches[1]) {
            'batch' { return 'POST /api/fetch/batch' }
            'raw' { return 'POST /api/fetch-raw' }
            'direct' { return 'POST /api/fetch-direct' }
        }
    }

    if ($tail -match '^network_(.+)$') {
        switch ($Matches[1]) {
            'clear' { return 'POST /api/network/clear' }
            'har' { return 'GET /api/network/har' }
            'throttle' { return 'GET /api/network/throttle' }
        }
    }

    if ($tail -match '^assert_(.+)$') {
        switch ($Matches[1]) {
            'text' { return 'POST /api/assert/page-contains' }
            'url' { return 'POST /api/assert/url' }
            'title' { return 'POST /api/assert/title' }
            'download' { return 'POST /api/downloads/assert' }
        }
    }

    if ($tail -match '^wait_for_(.+)$') {
        switch ($Matches[1]) {
            'network' { return 'POST /api/wait-for-network' }
            'final_navigation' { return 'POST /api/wait-for-final-navigation' }
            'idle' { return 'POST /api/wait-for-idle' }
            'download' { return 'POST /api/downloads/wait' }
        }
    }

    if ($tail -match '^identity_(.+)$') {
        switch ($Matches[1]) {
            'capture' { return 'POST /api/identity/capture' }
            'apply' { return 'POST /api/identity/apply' }
        }
    }

    $map = @{
        snapshot = 'GET /api/state'
        take_screenshot = 'GET /api/screenshot'
        screenshot_compare = 'POST /api/screenshot/compare'
        state_refresh = 'POST /api/state/refresh'
        diff_state = 'POST /api/diff-state'
        run_script = 'POST /api/execute-script'
        page_text = 'GET /api/page-text'
        page_text_all = 'GET /api/page-text/all'
        page_text_screen_reader = 'GET /api/page-text/screen-reader'
        page_source = 'GET /api/source'
        structured_text = 'POST /api/page-text/structured'
        console = 'GET /api/console'
        console_clear = 'POST /api/console/clear'
        network = 'GET /api/network'
        clear_all = 'POST /api/clear-all'
        clear_session = 'POST /api/clear-session'
        session_identity = 'GET /api/session/identity'
        identities = 'GET /api/identities'
        audit_all = 'POST /api/audit-all'
        surpriseme = 'POST /api/surpriseme'
        inspiration = 'GET /api/inspiration'
        coverage = 'GET /api/coverage'
        test_data = 'GET /api/test-data'
        scripting_help = 'GET /api/scripting-help'
        send_message = 'POST /api/message'
        ping = 'GET /api/ping'
        abort = 'POST /api/abort'
        force_navigate = 'POST /api/force-navigate'
        validate_html = 'POST /api/validate-html'
        check_links = 'POST /api/check-links'
        mixed_content = 'POST /api/security/mixed-content'
        firewall_test = 'POST /api/security/firewall-test'
        client_surface = 'POST /api/security/client-surface'
        postmessage_audit = 'POST /api/security/postmessage'
        dom_flows = 'POST /api/security/dom-flows'
        dom_xss_audit = 'POST /api/security/dom-xss-audit'
        gadget_radar = 'POST /api/security/gadget-radar'
        trace_input = 'POST /api/security/trace-input'
        attack_surface = 'POST /api/security/attack-surface'
        attack_form = 'POST /api/attack-form'
        shadow_check = 'POST /api/shadow/check'
        header_overrides = 'GET /api/header-overrides'
        webmcp_tools = 'GET /api/webmcp'
        webmcp_call = 'POST /api/webmcp/call'
        fetch = 'POST /api/fetch'
        monkey_test = 'POST /api/monkey-test'
        monkey_trowser = 'POST /api/monkey-trowser'
        interrupter = 'POST /api/interrupter'
        fuzz = 'POST /api/fuzz'
        seo = 'POST /api/seo'
        tabs = 'GET /api/tabs'
        new_tab = 'POST /api/tabs/new'
        close_tab = 'POST /api/tabs/close'
        switch_tab = 'POST /api/tabs/switch'
        viewport = 'GET /api/viewport'
        emulation = 'GET /api/emulation'
        trace = 'GET /api/trace'
        dialog = 'GET /api/dialog'
        handle_dialog = 'POST /api/dialog/handle'
        mock = 'POST /api/mock'
        intercept = 'POST /api/intercept'
        storage = 'POST /api/storage'
        press_key = 'POST /api/key'
        select_option = 'POST /api/select'
        find_clear = 'POST /api/find/clear'
        downloads = 'GET /api/downloads'
        pointers = 'GET /api/pointers'
        point = 'POST /api/pointer'
        checkpoint = 'POST /api/checkpoint'
        decide = 'POST /api/decision'
        decisions = 'GET /api/decisions'
        wait = 'POST /api/wait'
    }
    if ($map.ContainsKey($tail)) { return $map[$tail] }

    return "POST /api/$($tail -replace '_', '-')"
}

$rest = Get-RestEndpoints
$mcp = Get-McpTools
$generated = Get-Date -Format 'yyyy-MM-dd'
$bt = [char]96

$sb = New-Object System.Text.StringBuilder
[void]$sb.AppendLine('# Trowser API Index')
[void]$sb.AppendLine('')
[void]$sb.AppendLine('Quick-scan table of contents for all Trowser REST endpoints and MCP tools.')
[void]$sb.AppendLine('No arguments — just method, path, and one-line purpose.')
[void]$sb.AppendLine('')
[void]$sb.AppendLine("> **Auto-generated** from ${bt}TrowserApiServer*.cs${bt} and ${bt}McpHandler.ToolDefinitions.cs${bt} on $generated.")
[void]$sb.AppendLine("> Do not edit by hand — run ${bt}scripts/generate-api-index.ps1${bt} after API changes.")
[void]$sb.AppendLine('> Full details: [trowser-api-reference.md](trowser-api-reference.md) · Doc map: [DOCUMENTATION.md](../DOCUMENTATION.md)')
[void]$sb.AppendLine('')
[void]$sb.AppendLine("**Base URL:** ${bt}http://localhost:6923${bt} · **MCP:** ${bt}POST http://localhost:6923/mcp${bt}")
[void]$sb.AppendLine('')
[void]$sb.AppendLine('---')
[void]$sb.AppendLine('')
[void]$sb.AppendLine('## REST API')
[void]$sb.AppendLine('')

$restGroups = $rest | Group-Object { Get-PathCategory $_.Path } | Sort-Object {
    $order = @(
        'Session Log', 'Pointers & Checkpoints', 'Decisions', 'Page State & Inspection', 'Inspiration', 'Notifications', 'Navigation',
        'Element Interaction', 'Element Data', 'Script Execution', 'Waiting', 'Assertions',
        'Dialog Handling', 'Cookies', 'Web Storage', 'Viewport (Responsive Testing)', 'Tab Management',
        'Web MCP (Page-Registered Tools)', 'Network Mocking (Fault Injection)', 'Network Interception (Request Breakpoints)',
        'Load Testing', 'Browser Fetch (API Testing)', 'Network Throttling', 'Auditing & Analysis',
        'Security Testing', 'Robustness Testing', 'Peer Management (Cross-Instance Testing)',
        'Authorization Testing', 'Portable Identity', 'Security Orchestration (Playbooks)',
        'VPX (Vulnerability Proof Exchange)', 'Client TLS Certificates', 'WebSocket',
        'Shadows (Ambient UI)', 'Utilities', 'Other'
    )
    $i = [array]::IndexOf($order, $_.Name)
    if ($i -lt 0) { 999 } else { $i }
}

foreach ($group in $restGroups) {
    [void]$sb.AppendLine("### $($group.Name)")
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('| Method | Endpoint | Purpose |')
    [void]$sb.AppendLine('|--------|----------|---------|')
    foreach ($ep in @($group.Group | Sort-Object -Property Path, Method -Stable)) {
        $purpose = ($ep.Purpose -replace '\|', '/')
        [void]$sb.AppendLine("| $($ep.Method) | ${bt}$($ep.Path)${bt} | $purpose |")
    }
    [void]$sb.AppendLine('')
}

[void]$sb.AppendLine('---')
[void]$sb.AppendLine('')
[void]$sb.AppendLine('## MCP Tools')
[void]$sb.AppendLine('')
[void]$sb.AppendLine('| Tool | REST equivalent | Purpose |')
[void]$sb.AppendLine('|------|-----------------|---------|')
foreach ($tool in $mcp) {
    $hint = Get-McpRestHint $tool.Key
    $purpose = ($tool.Value -replace '\|', '/')
    [void]$sb.AppendLine("| ${bt}$($tool.Key)${bt} | $hint | $purpose |")
}
[void]$sb.AppendLine('')

$content = $sb.ToString()
if ($Check) {
    if (-not (Test-Path $outputPath)) {
        Write-Error "Missing $outputPath — run without -Check to generate."
    }
    $existing = [System.IO.File]::ReadAllText($outputPath)
    # Normalize line endings (editor vs git may differ on LF/CRLF) and the generation date,
    # so the check fails on API drift only, not on the day after the index was written.
    $datePattern = '(?m)^(> \*\*Auto-generated\*\* .*? on )\d{4}-\d{2}-\d{2}\.'
    $normExisting = (($existing -replace "`r`n", "`n") -replace $datePattern, '$1DATE.').TrimEnd("`n")
    $normContent = (($content -replace "`r`n", "`n") -replace $datePattern, '$1DATE.').TrimEnd("`n")
    if ($normExisting -ne $normContent) {
        Write-Error "trowser-api-index.md is out of date. Run: .\scripts\generate-api-index.ps1"
    }
    Write-Host "API index is up to date ($($rest.Count) REST routes, $($mcp.Count) MCP tools)."
    exit 0
}

$utf8NoBom = New-Object System.Text.UTF8Encoding $false
[System.IO.File]::WriteAllText($outputPath, $content, $utf8NoBom)
Write-Host "Wrote $outputPath ($($rest.Count) REST routes, $($mcp.Count) MCP tools)"
