# Run Trowser test layers aligned with CI (Windows + .NET 8 + WebView2 for smoke/full).
param(
    [ValidateSet('quick', 'smoke', 'full')]
    [string]$Level = 'smoke',
    [switch]$NoBuild
)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path "$PSScriptRoot\..").Path
$sln = Join-Path $root 'Trowser.sln'
$unit = Join-Path $root 'src\Trowser.Tests\Trowser.Tests.csproj'
$api = Join-Path $root 'src\Trowser.ApiTests\Trowser.ApiTests.csproj'
$exe = if ($env:TROWSER_EXE) { $env:TROWSER_EXE } else { Join-Path $root 'src\Trowser\bin\Release\net8.0-windows\win-x64\Trowser.exe' }
$regression = Join-Path $root 'tests\regression\run-regression.ps1'

function Require-Exe {
    if (-not (Test-Path -LiteralPath $exe)) {
        Write-Host "Missing $exe" -ForegroundColor Red
        Write-Host "Build Release or set TROWSER_EXE to your Trowser.exe path." -ForegroundColor Yellow
        exit 1
    }
}

if (-not $NoBuild) {
    Write-Host "Building Release..." -ForegroundColor Cyan
    dotnet build $sln -c Release -warnaserror
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

Write-Host "Level: $Level" -ForegroundColor Cyan

Write-Host "`n--- Unit + contract tests ---" -ForegroundColor Cyan
dotnet test $unit -c Release --no-build --logger "console;verbosity=minimal"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "`n--- API index is current ---" -ForegroundColor Cyan
& (Join-Path $PSScriptRoot 'generate-api-index.ps1') -Check
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

if ($Level -eq 'quick') {
    Write-Host "`nDone (quick)." -ForegroundColor Green
    exit 0
}

Require-Exe
Write-Host "`n--- API smoke (WebView2 + --serve) ---" -ForegroundColor Cyan
dotnet test $api -c Release --no-build --filter "Category=Smoke" --logger "console;verbosity=minimal"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "`n--- Regression smoke 01-07 ---" -ForegroundColor Cyan
& $regression -Filter '0[1-7]-*' -Exe $exe
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

if ($Level -eq 'smoke') {
    Write-Host "`nDone (smoke — matches push CI)." -ForegroundColor Green
    exit 0
}

Write-Host "`n--- API sweeps (full) ---" -ForegroundColor Cyan
dotnet test $api -c Release --no-build --filter "Category=Sweep" --logger "console;verbosity=minimal"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "`n--- Full offline regression ---" -ForegroundColor Cyan
& $regression -Exe $exe
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "`nDone (full)." -ForegroundColor Green
