# Update embedded Nuclei template subset (stub)
#
# Manual curation is preferred for the embedded subset shipped in Trowser.
# This script documents how to refresh from upstream nuclei-templates (MIT) when needed.
#
# Recommended workflow:
# 1. Download a pinned nuclei-templates release archive.
# 2. Filter for simple HTTP templates only (status/word/regex/header matchers; no payloads/attack/dns/tcp).
# 3. Copy selected YAML files into src/Trowser/Resources/nuclei/
# 4. Review severity/tags and trim to read-only GET probes where possible.
# 5. Copy upstream LICENSE into licenses/ if adding substantial upstream templates.
#
# Example (adjust version pin):
#   $Version = "10.2.7"
#   $Zip = "$env:TEMP\nuclei-templates-$Version.zip"
#   Invoke-WebRequest "https://github.com/projectdiscovery/nuclei-templates/archive/refs/tags/v$Version.zip" -OutFile $Zip
#   Expand-Archive $Zip -DestinationPath "$env:TEMP\nuclei-templates-$Version" -Force
#
# Trowser's native runner supports only:
#   - http: blocks with method/path/headers/body/matchers
#   - matchers: status, word, regex, header (part: body|header|all)
#   - variables: {{BaseURL}}, {{RootURL}}
#
param(
    [string]$Version = "10.2.7",
    [switch]$CopyLicense
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$DestDir = Join-Path $RepoRoot "src\Trowser\Resources\nuclei"
$LicenseDir = Join-Path $RepoRoot "licenses"

Write-Host "Nuclei subset updater (stub)"
Write-Host "Destination: $DestDir"
Write-Host "Pinned upstream version (reference): v$Version"
Write-Host ""
Write-Host "Manual curation is preferred. Edit YAML files under Resources/nuclei directly."

if ($CopyLicense) {
    $Zip = Join-Path $env:TEMP "nuclei-templates-$Version.zip"
    $Extract = Join-Path $env:TEMP "nuclei-templates-$Version"
    if (-not (Test-Path $Zip)) {
        Write-Host "Downloading nuclei-templates v$Version..."
        Invoke-WebRequest "https://github.com/projectdiscovery/nuclei-templates/archive/refs/tags/v$Version.zip" -OutFile $Zip
        Expand-Archive $Zip -DestinationPath $Extract -Force
    }
    $LicenseSrc = Get-ChildItem -Path $Extract -Recurse -Filter "LICENSE*" | Select-Object -First 1
    if ($LicenseSrc) {
        New-Item -ItemType Directory -Force -Path $LicenseDir | Out-Null
        Copy-Item $LicenseSrc.FullName (Join-Path $LicenseDir "nuclei-templates-MIT.txt") -Force
        Write-Host "Copied license to licenses/nuclei-templates-MIT.txt"
    }
}

Write-Host "Done."
