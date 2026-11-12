#Requires -Version 5.1
<#
.SYNOPSIS
    Creates a self-signed code-signing certificate for Trowser.
.DESCRIPTION
    Run this script ONCE before your first signed build. It creates a certificate
    and saves it to .cert/ in the repo root. Keep the .pfx file secret; distribute
    only the .cer file with your releases.
.OUTPUTS
    .cert/trowser.pfx  - Private key + certificate (KEEP SECRET, do not commit)
    .cert/trowser.cer  - Public certificate (include in distribution for users to install)
#>

$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$certDir = Join-Path $repoRoot ".cert"

if (Test-Path $certDir) {
    $pfxPath = Join-Path $certDir "trowser.pfx"
    if (Test-Path $pfxPath) {
        Write-Host "Certificate already exists at $pfxPath" -ForegroundColor Yellow
        $overwrite = Read-Host "Overwrite? (y/N)"
        if ($overwrite -ne "y" -and $overwrite -ne "Y") {
            Write-Host "Aborted."
            exit 0
        }
    }
}

New-Item $certDir -ItemType Directory -Force | Out-Null

Write-Host "=== Creating Trowser Code-Signing Certificate ===" -ForegroundColor Cyan
Write-Host ""

# Prompt for password (used to protect the .pfx file)
$password = Read-Host "Enter a password for the certificate (min 6 chars)" -AsSecureString
$passwordConfirm = Read-Host "Confirm password" -AsSecureString
$bstr1 = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($password)
$bstr2 = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($passwordConfirm)
$pwd1 = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr1)
$pwd2 = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr2)
[System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr1)
[System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr2)
if ($pwd1 -ne $pwd2) {
    Write-Error "Passwords do not match."
    exit 1
}
if ($pwd1.Length -lt 6) {
    Write-Error "Password must be at least 6 characters."
    exit 1
}

# Create self-signed certificate (valid 5 years)
Write-Host "Creating certificate (valid 5 years)..." -ForegroundColor Yellow
$cert = New-SelfSignedCertificate `
    -Subject "CN=Trowser, O=Trowser contributors" `
    -Type CodeSigningCert `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -NotAfter (Get-Date).AddYears(5) `
    -KeySpec Signature `
    -KeyUsage DigitalSignature

# Export to PFX (private key + cert)
$pfxPath = Join-Path $certDir "trowser.pfx"
$pfxPassword = ConvertTo-SecureString -String $pwd1 -Force -AsPlainText
Export-PfxCertificate -Cert $cert -FilePath $pfxPath -Password $pfxPassword | Out-Null

# Export public .cer for distribution
$cerPath = Join-Path $certDir "trowser.cer"
Export-Certificate -Cert $cert -FilePath $cerPath -Type CERT | Out-Null

# Remove from cert store (we have it in files)
Remove-Item -Path "Cert:\CurrentUser\My\$($cert.Thumbprint)" -Force

Write-Host ""
Write-Host "=== Done! ===" -ForegroundColor Green
Write-Host "Certificate created:"
Write-Host "  PFX (private): $pfxPath"
Write-Host "  CER (public):  $cerPath"
Write-Host ""
Write-Host "IMPORTANT:" -ForegroundColor Yellow
Write-Host "  - Keep .cert/trowser.pfx SECRET. Do not commit to version control."
Write-Host "  - Distribute .cert/trowser.cer with your releases so users can install it."
Write-Host "  - Add .cert/ to .gitignore if you use Git."
Write-Host ""
Write-Host "Next: Run build-zip.ps1 -Sign to build and sign Trowser." -ForegroundColor Cyan
