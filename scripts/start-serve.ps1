# Launch headless Trowser with REST/MCP for local ApiTests or regression -Fast loops.
param(
    [int]$Port = 0,
    [string]$ApiKey = "",
    [string]$Session = "dev-serve",
    [string]$Exe = ""
)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path "$PSScriptRoot\..").Path

if ([string]::IsNullOrWhiteSpace($Exe)) {
    $candidates = @(
        (Join-Path $root 'src\Trowser\bin\Release\net8.0-windows\win-x64\Trowser.exe'),
        (Join-Path $root 'src\Trowser\bin\Debug\net8.0-windows\win-x64\Trowser.exe'),
        (Join-Path $root 'dist\Trowser.exe')
    )
    $Exe = $candidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
}
if (-not $Exe -or -not (Test-Path -LiteralPath $Exe)) {
    Write-Host "Build Trowser.exe first, or pass -Exe." -ForegroundColor Red
    exit 1
}

if ($Port -le 0) {
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $listener.Start()
    $Port = ($listener.LocalEndpoint).Port
    $listener.Stop()
}

if ([string]::IsNullOrWhiteSpace($ApiKey)) {
    $ApiKey = "dev-" + [guid]::NewGuid().ToString('N')
}

$argList = @(
    '--serve', '--api',
    '--api-port', $Port,
    '--api-key', $ApiKey,
    '--session', $Session,
    '--nosplash'
)

Write-Host "Trowser: $Exe" -ForegroundColor DarkGray
Write-Host "Base URL: http://localhost:$Port" -ForegroundColor Green
Write-Host "API key:  $ApiKey" -ForegroundColor Green
Write-Host "Fast regression: .\tests\regression\run-regression.ps1 -Fast -Port $Port -Key `"$ApiKey`"" -ForegroundColor Cyan

& $Exe @argList
