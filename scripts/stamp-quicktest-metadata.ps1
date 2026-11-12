# Adds // @title, // @shadow, // @effects, // @see headers to embedded quicktests when missing.
$ErrorActionPreference = 'Stop'
$root = Join-Path $PSScriptRoot '..\src\Trowser\Resources\Quicktests'
$readOnly = @(
    'SiteHealth', 'ConsoleAndNetworkErrors', 'ResponsiveAccessibility', 'PerformanceCheck',
    'ScreenReaderTexts', 'GetAllPageStrings', 'TabOrderCheck', 'LinkCheck', 'HtmlValidation',
    'BackAndForward', 'BiggestFiles', 'ChecksAfterSession', 'GUIAudit',
    'BrowserCompatibilityScan', 'ThirdPartyAudit', 'WebPhysics', 'RequiredForbiddenStrings'
) | ForEach-Object { $_.ToLowerInvariant() }

Get-ChildItem -Path $root -Filter '*.csx' -Recurse | ForEach-Object {
    $leaf = [System.IO.Path]::GetFileNameWithoutExtension($_.Name)
    $text = Get-Content -LiteralPath $_.FullName -Raw
    if ($text -match '(?m)^\s*//\s*@title\b') { return }

    $effects = if ($readOnly -contains $leaf.ToLowerInvariant()) { 'none' } else { 'mutates' }
    $shadow = if ($_.Directory.Name -eq 'Laws') { 'light' } elseif ($effects -eq 'none') { 'light' } else { 'never' }
    $title = $leaf -creplace '([a-z])([A-Z])', '$1 $2'

    $header = @"
// @title $title
// @shadow $shadow
// @effects $effects

"@

    if ($text.StartsWith("#!")) {
        $nl = $text.IndexOf("`n")
        $text = $text.Substring(0, $nl + 1) + $header + $text.Substring($nl + 1)
    } else {
        $text = $header + $text
    }

    Set-Content -LiteralPath $_.FullName -Value $text -NoNewline
    Write-Host "Stamped $($_.FullName)"
}

Write-Host 'Done.'
