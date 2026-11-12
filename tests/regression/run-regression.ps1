<#
.SYNOPSIS
    Offline oracle-backed Trowser regression suite.

.DESCRIPTION
    Concatenates _prelude.csx with each test under functional/ and security/,
    then runs Trowser.exe --run (CLI mode: hidden window, exit codes 0/1/2).

    Exit codes from Trowser.exe:
      0 = all assertions passed
      1 = one or more assertions failed
      2 = script error / timeout / missing file

.PARAMETER Fast
    Post scripts to a running Trowser instance via REST (/api/execute-script)
    instead of spawning CLI processes. Requires Trowser already running with --api.

.PARAMETER Filter
    Optional wildcard filter on test file names (e.g. "nav*", "*headers*").

.PARAMETER Exe
    Path to Trowser.exe. Auto-detected if omitted.

.PARAMETER Port
    REST API port for -Fast mode (default 6923).

.PARAMETER Key
    Bearer API key for -Fast mode.

.PARAMETER TimeoutSec
    Per-test timeout in seconds (default 240; tier-2 security scripts such as 15-xs-leaks can exceed 120s).

.EXAMPLE
    .\tests\regression\run-regression.ps1
    .\tests\regression\run-regression.ps1 -Filter "01-*"
    .\tests\regression\run-regression.ps1 -Fast -Key "my-key"
#>
param(
    [switch]$Fast,
    [string]$Filter = "*",
    [string]$Exe = "",
    [int]$Port = 6923,
    [string]$Key = "",
    [int]$TimeoutSec = 240,
    [switch]$Visible
)

$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
$repoRoot = (Resolve-Path (Join-Path $root "..\..")).Path
$preludePath = Join-Path $root "_prelude.csx"
$resultsPath = Join-Path $root "results.txt"
$tempDir = Join-Path $env:TEMP "trowser-regression-$(Get-Random)"

if (-not (Test-Path $preludePath)) {
    Write-Error "Missing prelude: $preludePath"
}

function Find-TrowserExe {
    param([string]$Preferred)
    if ($Preferred -and (Test-Path $Preferred)) { return (Resolve-Path $Preferred).Path }

    $candidates = @(
        (Join-Path $repoRoot "src\Trowser\bin\Release\net8.0-windows\win-x64\publish\Trowser.exe"),
        (Join-Path $repoRoot "src\Trowser\bin\Release\net8.0-windows\win-x64\Trowser.exe"),
        (Join-Path $repoRoot "src\Trowser\bin\Debug\net8.0-windows\win-x64\Trowser.exe"),
        (Join-Path $repoRoot "dist\Trowser.exe"),
        (Join-Path $repoRoot "_buildcheck\Trowser.exe")
    )
    foreach ($c in $candidates) {
        if (Test-Path $c) { return (Resolve-Path $c).Path }
    }
    return $null
}

$exePath = Find-TrowserExe -Preferred $Exe
if (-not $Fast -and -not $exePath) {
    Write-Error "Trowser.exe not found. Build the project or pass -Exe <path>."
}

$tests = @()
$tests += Get-ChildItem (Join-Path $root "functional\*.csx") -ErrorAction SilentlyContinue
$tests += Get-ChildItem (Join-Path $root "security\*.csx") -ErrorAction SilentlyContinue
$tests = $tests | Where-Object { $_.Name -like $Filter } | Sort-Object FullName

if ($tests.Count -eq 0) {
    Write-Error "No tests matched filter '$Filter' under functional/ and security/."
}

New-Item -ItemType Directory -Force -Path $tempDir | Out-Null
$prelude = [IO.File]::ReadAllText($preludePath)

$passed = 0
$failed = 0
$errors = 0
$lines = New-Object System.Collections.Generic.List[string]
$swTotal = [Diagnostics.Stopwatch]::StartNew()

Write-Host ""
Write-Host "Trowser regression suite ($($tests.Count) tests)" -ForegroundColor Cyan
if ($Fast) {
    Write-Host "Mode: Fast (REST :$Port)" -ForegroundColor DarkCyan
} else {
    Write-Host "Mode: CLI  Exe: $exePath" -ForegroundColor DarkCyan
}
Write-Host ""

function Invoke-CliTest {
    param([string]$CombinedScript, [string]$Name)
    $tempScript = Join-Path $tempDir "$Name.csx"
    $outFile = Join-Path $tempDir "$Name.out.txt"
    [IO.File]::WriteAllText($tempScript, $CombinedScript)

    $argList = @(
        "--run", $tempScript,
        "--session", ("reg-" + $Name + "-" + [Guid]::NewGuid().ToString("N").Substring(0, 8)),
        "--timeout", $TimeoutSec.ToString(),
        "--output", $outFile
    )
    if ($Visible) { $argList += "--visible" }

    $proc = Start-Process -FilePath $exePath -ArgumentList $argList -Wait -PassThru -NoNewWindow
    $exit = $proc.ExitCode
    $output = if (Test-Path $outFile) { [IO.File]::ReadAllText($outFile) } else { "" }
    return @{ ExitCode = $exit; Output = $output }
}

function Invoke-FastTest {
    param([string]$CombinedScript, [string]$Name)
    if (-not $Key) { throw "-Fast requires -Key <api-key>" }
    $headers = @{ Authorization = "Bearer $Key"; "Content-Type" = "application/json" }
    $bodyObj = @{ code = $CombinedScript }
    $json = $bodyObj | ConvertTo-Json -Compress -Depth 5
    # ConvertTo-Json escapes properly; send as UTF8 bytes
    $bytes = [Text.Encoding]::UTF8.GetBytes($json)
    try {
        $resp = Invoke-WebRequest -Uri "http://localhost:$Port/api/execute-script" `
            -Method Post -Headers $headers -Body $bytes -TimeoutSec ($TimeoutSec + 30) -UseBasicParsing
        $r = $resp.Content | ConvertFrom-Json
        $allPassed = [bool]$r.data.assertions.allPassed
        $success = [bool]$r.data.success
        $exit = if (-not $success) { 2 } elseif (-not $allPassed) { 1 } else { 0 }
        $output = if ($r.data.error) { $r.data.error } else { "assertions P=$($r.data.assertions.passed) F=$($r.data.assertions.failed)" }
        return @{ ExitCode = $exit; Output = $output }
    } catch {
        return @{ ExitCode = 2; Output = $_.Exception.Message }
    }
}

foreach ($file in $tests) {
    $name = [IO.Path]::GetFileNameWithoutExtension($file.Name)
    $rel = $file.FullName.Substring($root.Length).TrimStart('\', '/')
    $testBody = [IO.File]::ReadAllText($file.FullName)
    $combined = $prelude + "`r`n`r`n// ===== TEST: $rel =====`r`n" + $testBody

    $sw = [Diagnostics.Stopwatch]::StartNew()
    if ($Fast) {
        $result = Invoke-FastTest -CombinedScript $combined -Name $name
    } else {
        $result = Invoke-CliTest -CombinedScript $combined -Name $name
    }
    $sw.Stop()
    $ms = $sw.ElapsedMilliseconds
    $exit = $result.ExitCode

    if ($exit -eq 0) {
        $passed++
        $status = "PASS"
        $color = "Green"
    } elseif ($exit -eq 1) {
        $failed++
        $status = "FAIL"
        $color = "Red"
    } else {
        $errors++
        $status = "ERR "
        $color = "Magenta"
    }

    $line = "$status  $rel  (${ms}ms)"
    Write-Host $line -ForegroundColor $color
    if ($exit -ne 0 -and $result.Output) {
        $snippet = ($result.Output -split "`n" | Select-Object -Last 8) -join "`n  "
        Write-Host "  $snippet" -ForegroundColor DarkGray
    }
    $lines.Add($line)
    if ($exit -ne 0 -and $result.Output) {
        $lines.Add("--- output ($rel) ---")
        $lines.Add($result.Output.TrimEnd())
        $lines.Add("---")
    }
}

$swTotal.Stop()
$summary = "=== TOTAL: Passed=$passed Failed=$failed Errors=$errors  ($([int]$swTotal.Elapsed.TotalSeconds)s) ==="
Write-Host ""
Write-Host $summary -ForegroundColor $(if ($failed -eq 0 -and $errors -eq 0) { "Green" } else { "Red" })
$lines.Add("")
$lines.Add($summary)
$lines.Add("Ran: $(Get-Date -Format o)")
[IO.File]::WriteAllLines($resultsPath, $lines)

if ($env:GITHUB_STEP_SUMMARY) {
    $fence = '```'
    $md = "## Trowser regression`n`n$fence`n$summary`n$fence`n`nDetails: tests/regression/results.txt"
    Add-Content -LiteralPath $env:GITHUB_STEP_SUMMARY -Value $md
}

Remove-Item -Recurse -Force $tempDir -ErrorAction SilentlyContinue

if ($failed -gt 0 -or $errors -gt 0) { exit 1 }
exit 0
