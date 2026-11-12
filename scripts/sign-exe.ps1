#Requires -Version 5.1
<#
.SYNOPSIS
    Signs Trowser.exe with the self-signed certificate.
.DESCRIPTION
    Uses signtool.exe from the Windows SDK to sign the executable.
    Requires .cert/trowser.pfx from create-cert.ps1.
.PARAMETER ExePath
    Path to Trowser.exe (default: publish output).
.PARAMETER CertPath
    Path to .pfx file (default: .cert/trowser.pfx).
.PARAMETER Password
    Certificate password. If not provided, prompts interactively.
#>

param(
    [string]$ExePath = "",
    [string]$CertPath = "",
    [string]$Password = ""
)

$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

if (-not $ExePath) {
    $ExePath = Join-Path $repoRoot "src\Trowser\bin\Release\net8.0-windows\win-x64\publish\Trowser.exe"
}
if (-not $CertPath) {
    $CertPath = Join-Path $repoRoot ".cert\trowser.pfx"
}

if (-not (Test-Path $ExePath)) {
    Write-Error "Executable not found: $ExePath"
    exit 1
}
if (-not (Test-Path $CertPath)) {
    Write-Error "Certificate not found: $CertPath. Run scripts/create-cert.ps1 first."
    exit 1
}

# Find signtool.exe (Windows SDK)
$sdkPaths = @(
    "C:\Program Files (x86)\Windows Kits\10\bin\*\x64\signtool.exe",
    "C:\Program Files\Windows Kits\10\bin\*\x64\signtool.exe"
)
$signtool = $null
foreach ($pattern in $sdkPaths) {
    $found = Get-ChildItem -Path $pattern -ErrorAction SilentlyContinue | Sort-Object -Descending | Select-Object -First 1
    if ($found) {
        $signtool = $found.FullName
        break
    }
}
if (-not $signtool) {
    Write-Error "signtool.exe not found. Install the Windows SDK (Windows SDK Signing Tools for Desktop Apps)."
    Write-Host "Download: https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/"
    exit 1
}

# Get password
$plainPassword = ""
if ($Password) {
    $plainPassword = $Password
} else {
    $secure = Read-Host "Enter certificate password" -AsSecureString
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
}

# Sign (timestamp optional for self-signed; some servers may reject)
Write-Host "Signing $ExePath..." -ForegroundColor Yellow
$signArgs = @(
    "sign",
    "/f", $CertPath,
    "/p", $plainPassword,
    "/fd", "sha256",
    "/tr", "http://timestamp.digicert.com",
    "/td", "sha256",
    $ExePath
)
& $signtool $signArgs
if ($LASTEXITCODE -ne 0) {
    Write-Host "Timestamp server may reject self-signed certs. Retrying without timestamp..." -ForegroundColor Yellow
    $signArgs = @(
        "sign",
        "/f", $CertPath,
        "/p", $plainPassword,
        "/fd", "sha256",
        $ExePath
    )
    & $signtool $signArgs
}
$plainPassword = ""
if ($LASTEXITCODE -ne 0) {
    Write-Error "Signing failed."
    exit 1
}
Write-Host "Signed successfully." -ForegroundColor Green
