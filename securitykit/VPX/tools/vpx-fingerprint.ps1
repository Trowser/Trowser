# Computes a VPX 1.1 vpx-fingerprint-1 value.
# See spec/VPX-1.1.md Appendix D.
#
# Usage:
#   pwsh -File tools/vpx-fingerprint.ps1 -Repository https://github.com/acme/webapp `
#     -File src/Api/UserSearchController.cs -Kind sqli -SinkFile src/Api/UserSearchController.cs `
#     -SinkLine 87 -Route /api/users -Method GET -Param q

[CmdletBinding()]
param(
    [string]$Repository = '',
    [string]$File = '',
    [string]$Kind = '',
    [string]$SourceFile = '',
    [int]$SourceLine = 0,
    [string]$SinkFile = '',
    [int]$SinkLine = 0,
    [string]$Route = '',
    [string]$Method = '',
    [string]$Param = ''
)

$ErrorActionPreference = 'Stop'

function Convert-Nfc([string]$s) {
    if ($null -eq $s) { return '' }
    return $s.Normalize([Text.NormalizationForm]::FormC)
}

function Normalize-Repository([string]$value) {
    $v = $value.Trim()
    if ($v.Length -eq 0) { return '' }
    if ($v -match '^(https?)://([^/]+)(/.*)?$') {
        $scheme = $Matches[1].ToLowerInvariant()
        $hostName = $Matches[2].ToLowerInvariant()
        $urlPath = $Matches[3]
        if ($null -eq $urlPath) { $urlPath = '' }
        $v = "${scheme}://${hostName}${urlPath}"
    }
    else {
        $v = $v.ToLowerInvariant()
    }
    $v = $v.TrimEnd('/')
    if ($v.EndsWith('.git')) { $v = $v.Substring(0, $v.Length - 4) }
    return Convert-Nfc $v
}

function Normalize-File([string]$value) {
    $v = $value.Trim().Replace('\', '/')
    if ($v.StartsWith('./')) { $v = $v.Substring(2) }
    return Convert-Nfc $v
}

function Normalize-Location([string]$file, [int]$line) {
    $f = Normalize-File $file
    if ($f.Length -eq 0) { return '' }
    if ($line -gt 0) { return "${f}:${line}" }
    return $f
}

function Normalize-Route([string]$value) {
    $v = $value.Trim()
    if ($v.Length -eq 0) { return '' }
    if ($v -match '^https?://[^/]+(/.*)?$') {
        $v = $Matches[1]
        if ([string]::IsNullOrEmpty($v)) { $v = '/' }
    }
    $q = $v.IndexOfAny(@([char]'?', [char]'#'))
    if ($q -ge 0) { $v = $v.Substring(0, $q) }
    $v = $v.ToLowerInvariant()
    while ($v.Contains('//')) { $v = $v.Replace('//', '/') }
    if ($v.Length -gt 1) { $v = $v.TrimEnd('/') }
    return Convert-Nfc $v
}

$fields = @(
    'vpx-fingerprint-1'
    (Normalize-Repository $Repository)
    (Normalize-File $File)
    (Convert-Nfc $Kind.Trim().ToLowerInvariant())
    (Normalize-Location $SourceFile $SourceLine)
    (Normalize-Location $SinkFile $SinkLine)
    (Normalize-Route $Route)
    (Convert-Nfc $Method.Trim().ToUpperInvariant())
    (Convert-Nfc $Param.Trim())
)

$canonical = [string]::Join([char]0x1F, $fields)
$bytes = [Text.Encoding]::UTF8.GetBytes($canonical)
$sha = [System.Security.Cryptography.SHA256]::Create()
try {
    $hash = ($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') }) -join ''
}
finally {
    $sha.Dispose()
}

Write-Output "sha256:$hash"
