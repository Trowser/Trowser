$root = Split-Path $PSScriptRoot -Parent
$lint = Join-Path $PSScriptRoot 'vpx-lint.ps1'
$files = Get-ChildItem -Path (Join-Path $root 'examples') -Filter *.json -Recurse |
    Where-Object { $_.Name -ne 'README.md' }
$failed = $false
foreach ($f in $files) {
    Write-Host "Lint $($f.FullName)"
    & $lint -InputPath $f.FullName
    if ($LASTEXITCODE -ne 0) { $failed = $true }
}
if ($failed) { exit 1 }
exit 0
