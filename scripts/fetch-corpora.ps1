<#
.SYNOPSIS
  Fetch curated SecLists + PayloadsAllTheThings subsets for payloadProfile=big.

.DESCRIPTION
  Sparse-checkouts only the mapped paths used by PayloadCatalog into ./corpora
  (or -OutDir). Not bundled with the exe — place corpora/ next to Trowser.exe
  or set TROWSER_CORPORA.

.PARAMETER OutDir
  Destination root (default: ./corpora beside this repo).
#>
[CmdletBinding()]
param(
    [string]$OutDir = ""
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
if (-not $OutDir) { $OutDir = Join-Path $repoRoot "corpora" }

$paths = @(
    @{ Repo = "https://github.com/danielmiessler/SecLists.git"; Rel = "Fuzzing/XSS/XSS-Jhaddix.txt"; Dest = "SecLists/Fuzzing/XSS/XSS-Jhaddix.txt" },
    @{ Repo = "https://github.com/danielmiessler/SecLists.git"; Rel = "Fuzzing/SQLi/Generic-SQLi.txt"; Dest = "SecLists/Fuzzing/SQLi/Generic-SQLi.txt" },
    @{ Repo = "https://github.com/danielmiessler/SecLists.git"; Rel = "Fuzzing/LFI/LFI-Jhaddix.txt"; Dest = "SecLists/Fuzzing/LFI/LFI-Jhaddix.txt" },
    @{ Repo = "https://github.com/danielmiessler/SecLists.git"; Rel = "Fuzzing/URI/redirect-urls.txt"; Dest = "SecLists/Fuzzing/URI/redirect-urls.txt" },
    @{ Repo = "https://github.com/swisskyrepo/PayloadsAllTheThings.git"; Rel = "XSS Injection/Intruder/xss.txt"; Dest = "PayloadsAllTheThings/XSS Injection/Intruder/xss.txt" },
    @{ Repo = "https://github.com/swisskyrepo/PayloadsAllTheThings.git"; Rel = "Server Side Template Injection/Intruder/ssti.txt"; Dest = "PayloadsAllTheThings/Server Side Template Injection/Intruder/ssti.txt" },
    @{ Repo = "https://github.com/swisskyrepo/PayloadsAllTheThings.git"; Rel = "NoSQL Injection/Intruder/nosqli.txt"; Dest = "PayloadsAllTheThings/NoSQL Injection/Intruder/nosqli.txt" },
    @{ Repo = "https://github.com/swisskyrepo/PayloadsAllTheThings.git"; Rel = "Server Side Request Forgery/Intruder/ssrf.txt"; Dest = "PayloadsAllTheThings/Server Side Request Forgery/Intruder/ssrf.txt" }
)

# LDAP list may not exist on all SecLists versions — try optional raw download
$optionalRaw = @(
    @{ Url = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/LDAP-injection.txt"; Dest = "SecLists/Fuzzing/LDAP/LDAP.fuzzdb.txt" }
)

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$tmp = Join-Path $env:TEMP "trowser-corpora-$(Get-Random)"
New-Item -ItemType Directory -Force -Path $tmp | Out-Null

function Get-RawFile([string]$RepoWeb, [string]$RelPath, [string]$DestRel) {
    # Prefer raw.githubusercontent.com
    $slug = if ($RepoWeb -match 'github\.com/([^/]+/[^/]+)') { $Matches[1] -replace '\.git$','' } else { $null }
    if (-not $slug) { return $false }
    $relEnc = ($RelPath -replace ' ', '%20')
    $url = "https://raw.githubusercontent.com/$slug/master/$relEnc"
    $out = Join-Path $OutDir $DestRel
    $dir = Split-Path $out -Parent
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    try {
        Write-Host "  GET $url"
        Invoke-WebRequest -Uri $url -OutFile $out -UseBasicParsing -TimeoutSec 60
        return (Test-Path $out) -and ((Get-Item $out).Length -gt 0)
    } catch {
        Write-Warning "  Failed: $url — $($_.Exception.Message)"
        return $false
    }
}

Write-Host "Fetching corpora into $OutDir"
$ok = 0
foreach ($p in $paths) {
    if (Get-RawFile $p.Repo $p.Rel $p.Dest) { $ok++ }
}
foreach ($p in $optionalRaw) {
    $out = Join-Path $OutDir $p.Dest
    $dir = Split-Path $out -Parent
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    try {
        Write-Host "  GET $($p.Url)"
        Invoke-WebRequest -Uri $p.Url -OutFile $out -UseBasicParsing -TimeoutSec 60
        if ((Get-Item $out).Length -gt 0) { $ok++ }
    } catch {
        Write-Warning "  Optional LDAP list skipped: $($_.Exception.Message)"
    }
}

Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
Write-Host ""
Write-Host "Fetched $ok file(s). Point TROWSER_CORPORA at:"
Write-Host "  $OutDir"
Write-Host "Or copy the corpora/ folder next to Trowser.exe."
Write-Host "Licenses: MIT (SecLists, PayloadsAllTheThings) — see licenses/."
