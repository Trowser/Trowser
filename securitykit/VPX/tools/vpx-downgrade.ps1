# Downgrade a VPX 1.1 document to a VPX 1.0 document (lossy).
# See spec/VPX-1.1.md §20.
#
# Usage:
#   pwsh -File tools/vpx-downgrade.ps1 -InputPath in.json -OutputPath out.json

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$InputPath,
    [Parameter(Mandatory = $true)]
    [string]$OutputPath
)

$ErrorActionPreference = 'Stop'
$doc = Get-Content -Raw -LiteralPath $InputPath | ConvertFrom-Json

function To-List($x) {
    if ($null -eq $x) { return @() }
    return @($x)
}

function Current-Verdicts($verdicts) {
    $list = @(To-List $verdicts)
    $superseded = @{}
    foreach ($v in $list) {
        $sid = [string]$v.supersedesVerdictId
            if (-not [string]::IsNullOrWhiteSpace($sid)) { $superseded[$sid] = $true }
    }
    $current = @()
    $seenFinding = @{}
    # Walk from the end so a later non-superseded verdict wins if two currents exist (should not).
    for ($i = $list.Count - 1; $i -ge 0; $i--) {
        $v = $list[$i]
        $id = [string]$v.id
        if (-not [string]::IsNullOrWhiteSpace($id) -and $superseded.ContainsKey($id)) { continue }
        $fid = [string]$v.findingId
        if ([string]::IsNullOrWhiteSpace($fid)) { continue }
        if ($seenFinding.ContainsKey($fid)) { continue }
        $seenFinding[$fid] = $true
        $current += $v
    }
    [Array]::Reverse($current)
    return $current
}

$out = [ordered]@{
    vpxVersion = '1.0'
    documentId = [string]$doc.documentId
}

if ($doc.createdAt) { $out.createdAt = $doc.createdAt }
if ($doc.updatedAt) { $out.updatedAt = $doc.updatedAt }
if ($doc.profile -in @('compact', 'full', 'summary')) { $out.profile = [string]$doc.profile }

if ($doc.target) {
    $t = [ordered]@{}
    foreach ($k in @('baseUrl', 'repository', 'commit', 'environment')) {
        if ($doc.target.$k) { $t[$k] = $doc.target.$k }
    }
    if ($t.Count -gt 0) { $out.target = $t }
}

if ($doc.policy) {
    $p = [ordered]@{}
    foreach ($k in @('cvssCap', 'proofRequiredAbove', 'deferBelowPriority')) {
        if ($null -ne $doc.policy.$k) { $p[$k] = $doc.policy.$k }
    }
    if ($p.Count -gt 0) { $out.policy = $p }
}

$out.surfaces = @(To-List $doc.surfaces)
$out.findings = foreach ($f in (To-List $doc.findings)) {
    $copy = $f | Select-Object -ExcludeProperty fingerprint, reportedByRunIds, assessmentIds
    $copy
}

$out.proofs = foreach ($pr in (To-List $doc.proofs)) {
    $passed = $false
    $outcome = [string]$pr.outcome
    if ($outcome -eq 'exploited') { $passed = $true }
    elseif ($pr.oracle -and $null -ne $pr.oracle.observed) { $passed = [bool]$pr.oracle.observed }
    elseif ($pr.oracle -and $null -ne $pr.oracle.passed) { $passed = [bool]$pr.oracle.passed }

    $oracle = $pr.oracle
    if ($null -eq $oracle) {
        $oracle = [pscustomobject]@{ type = 'none'; passed = $passed }
    }
    else {
        $o = [ordered]@{
            type   = if ($oracle.type) { [string]$oracle.type } else { 'none' }
            passed = $passed
        }
        if ($oracle.evidence) { $o.evidence = $oracle.evidence }
        elseif ($oracle.actualSignal) { $o.evidence = $oracle.actualSignal }
        $oracle = [pscustomobject]$o
    }

    $copy = [ordered]@{
        id         = $pr.id
        findingId  = $pr.findingId
        executedAt = $pr.executedAt
    }
    if ($pr.tool) { $copy.tool = $pr.tool }
    else { $copy.tool = [pscustomobject]@{ name = 'unknown' } }
    if ($pr.workflow) { $copy.workflow = $pr.workflow }
    if ($pr.injection) { $copy.injection = $pr.injection }
    if ($pr.identity) { $copy.identity = $pr.identity }
    $copy.oracle = $oracle
    if ($pr.evidenceSummary) { $copy.evidenceSummary = $pr.evidenceSummary }
    if ($pr.evidenceBundle) { $copy.evidenceBundle = $pr.evidenceBundle }
    if ($null -ne $pr.elapsedMs) { $copy.elapsedMs = $pr.elapsedMs }
    [pscustomobject]$copy
}

$out.verdicts = foreach ($v in (Current-Verdicts $doc.verdicts)) {
    $copy = [ordered]@{
        findingId      = $v.findingId
        exploitability = if ([string]$v.exploitability -eq 'not_reproduced') { 'inconclusive' } else { $v.exploitability }
    }
    $proofId = $v.proofId
    if (-not $proofId -and $v.basedOnProofIds) {
        $ids = @(To-List $v.basedOnProofIds)
        if ($ids.Count -gt 0) { $proofId = $ids[0] }
    }
    if ($proofId) { $copy.proofId = $proofId }
    foreach ($k in @('updatedAt', 'disposition', 'justification', 'effectiveSeverity', 'confidence', 'remediation', 'rerunToken')) {
        if ($null -ne $v.$k) { $copy[$k] = $v.$k }
    }
    [pscustomobject]$copy
}

$json = $out | ConvertTo-Json -Depth 12
Set-Content -LiteralPath $OutputPath -Value $json -Encoding utf8
Write-Host "Wrote VPX 1.0 document to $OutputPath"
