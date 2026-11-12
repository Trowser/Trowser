# VPX 1.1 linter: referential integrity + unknown-property warnings.
# Conformance (types/required) is defined by schema/vpx-1.1.schema.json.
# A lint warning MUST NOT make an otherwise conforming document unreadable.
#
# Usage (from repo root or this folder):
#   pwsh -File securitykit/VPX/tools/vpx-lint.ps1 -InputPath document.json
#   pwsh -File securitykit/VPX/tools/vpx-lint.ps1 -InputPath examples\compact-hypotheses.json -Strict
#
# Exit codes: 0 = no errors (warnings may exist), 1 = errors, 2 = usage.

param(
    [Parameter(Mandatory = $true, Position = 0)]
    [Alias('Path')]
    [string[]]$InputPath,
    [switch]$Strict,
    [switch]$EmitJson
)

$ErrorActionPreference = 'Stop'

$KnownRoot = [string[]]@(
    '$schema', 'vpxVersion', 'documentId', 'createdAt', 'updatedAt', 'profile',
    'target', 'policy', 'runs', 'surfaces', 'findings', 'assessments', 'proofs',
    'artifacts', 'verdicts'
)

$KnownByDef = @{
    target = @('baseUrl', 'repository', 'commit', 'environment', 'deploymentId', 'sourceDigest', 'buildDigest')
    policy = @('cvssCap', 'proofRequiredAbove', 'deferBelowPriority')
    digest = @('algorithm', 'value')
    fingerprint = @('algorithm', 'value')
    actor = @('type', 'name', 'version', 'provider')
    run = @('id', 'stage', 'actor', 'startedAt', 'completedAt', 'inputArtifactIds', 'outputArtifactIds', 'configuration')
    surface = @('id', 'route', 'method', 'params', 'auth', 'discoveredFrom', 'routeConfidence')
    param = @('name', 'in', 'type')
    auth = @('required', 'roles', 'mechanism')
    origin = @('tool', 'rule', 'file', 'line', 'snippet')
    investigationHints = @('codeSearchQueries', 'suggestedFiles', 'notes')
    proofIdentity = @('name', 'roles', 'mechanism')
    proofHints = @('category', 'payloads', 'oracle', 'identity')
    sourceLocation = @('file', 'line', 'function', 'role')
    finding = @(
        'id', 'fingerprint', 'kind', 'severity', 'title', 'description', 'status',
        'surfaceId', 'surfaceIds', 'param', 'origin', 'trace', 'proofHints',
        'reportedByRunIds', 'assessmentIds', 'owasp', 'cwe', 'cvss', 'confidence',
        'proofPriority', 'investigationHints', 'relatedFindingIds', 'tags',
        'reference', 'remediation'
    )
    assessment = @(
        'id', 'findingId', 'proofId', 'runId', 'phase', 'conclusion', 'confidence',
        'rationale', 'locations', 'trace', 'artifactIds'
    )
    tool = @('name', 'version')
    workflow = @('type', 'templateId', 'path')
    injection = @('surfaceId', 'param', 'payload')
    oracle = @('type', 'observed', 'expectedSignal', 'actualSignal', 'passed', 'evidence')
    targetSnapshot = @('deploymentId', 'buildDigest', 'environment', 'baseUrl')
    cleanup = @('status', 'notes')
    proof = @(
        'id', 'findingId', 'runId', 'executedAt', 'outcome', 'tool', 'workflow',
        'injection', 'identity', 'oracle', 'targetSnapshot', 'preconditions',
        'limitations', 'cleanup', 'artifactIds', 'evidenceSummary', 'evidenceBundle',
        'elapsedMs'
    )
    redaction = @('status', 'description')
    artifact = @(
        'id', 'kind', 'uri', 'mediaType', 'digest', 'size', 'createdAt',
        'sensitivity', 'redaction', 'producedByRunId'
    )
    remediationLocation = @('file', 'line', 'function')
    remediation = @('strategy', 'locations', 'fixPattern', 'codeHint')
    approval = @('status', 'approvedByRunId')
    verdict = @(
        'id', 'findingId', 'runId', 'supersedesVerdictId', 'basedOnAssessmentIds',
        'basedOnProofIds', 'proofId', 'updatedAt', 'exploitability', 'disposition',
        'justification', 'effectiveSeverity', 'confidence', 'remediation',
        'approval', 'rerunToken'
    )
}

function Get-IdSet {
    param($Items, [string]$Field = 'id')
    $set = @{}
    if ($null -eq $Items) { return $set }
    foreach ($item in $Items) {
        $id = [string]$item.$Field
        if (-not [string]::IsNullOrWhiteSpace($id)) { $set[$id] = $true }
    }
    return $set
}

function Add-Finding {
    param($List, [string]$Severity, [string]$Message, [string]$Path)
    $List.Add([pscustomobject]@{ severity = $Severity; message = $Message; path = $Path })
}

function Test-UnknownKeys {
    param($Object, [string[]]$Known, [string]$JsonPath, $Findings)

    if ($null -eq $Object) { return }
    foreach ($prop in $Object.PSObject.Properties) {
        $name = $prop.Name
        if ($name -like 'x-*') { continue }
        if ($Known -contains $name) { continue }
        Add-Finding $Findings 'warning' "Unknown unnamespaced property '$name'. Experimental fields SHOULD use an x- prefix." "$JsonPath.$name"
    }
}

function Test-Ref {
    param(
        [string]$Id,
        $Set,
        [string]$Kind,
        [string]$JsonPath,
        $Findings
    )
    if ([string]::IsNullOrWhiteSpace($Id)) { return }
    if (-not $Set.ContainsKey($Id)) {
        Add-Finding $Findings 'error' "Dangling $Kind reference '$Id'." $JsonPath
    }
}

function Test-RefList {
    param($Ids, $Set, [string]$Kind, [string]$JsonPath, $Findings)
    if ($null -eq $Ids) { return }
    $i = 0
    foreach ($id in $Ids) {
        Test-Ref -Id $id -Set $Set -Kind $Kind -JsonPath "$JsonPath[$i]" -Findings $Findings
        $i++
    }
}

function Test-UniqueIds {
    param($Items, [string]$Kind, [string]$JsonPath, $Findings)
    if ($null -eq $Items) { return }
    $seen = @{}
    $i = 0
    foreach ($item in $Items) {
        $id = [string]$item.id
        if ([string]::IsNullOrWhiteSpace($id)) {
            Add-Finding $Findings 'error' "$Kind is missing required 'id'." "$JsonPath[$i]"
        }
        elseif ($seen.ContainsKey($id)) {
            Add-Finding $Findings 'error' "Duplicate $Kind id '$id'." "$JsonPath[$i].id"
        }
        else {
            $seen[$id] = $true
        }
        $i++
    }
}

function Lint-Document {
    param($Doc, [string]$File)

    $findings = [System.Collections.Generic.List[object]]::new()
    $is10 = [string]$Doc.vpxVersion -eq '1.0'

    if ([string]::IsNullOrWhiteSpace([string]$Doc.vpxVersion)) {
        Add-Finding $findings 'error' 'Missing vpxVersion.' '$.vpxVersion'
    }
    elseif ($is10) {
        Add-Finding $findings 'warning' 'Document is VPX 1.0. Referential checks for 1.1 collections are skipped; prefer upgrading to 1.1.' '$.vpxVersion'
    }
    elseif ([string]$Doc.vpxVersion -notmatch '^1\.[1-9][0-9]*$') {
        Add-Finding $findings 'error' "Unsupported vpxVersion '$($Doc.vpxVersion)'. VPX 1.1 consumers accept 1.1+ minor versions and reject 2.0." '$.vpxVersion'
    }

    if ([string]::IsNullOrWhiteSpace([string]$Doc.documentId)) {
        Add-Finding $findings 'error' 'Missing documentId.' '$.documentId'
    }

    $requiredArrays = if ($is10) {
        @('surfaces', 'findings', 'proofs', 'verdicts')
    }
    else {
        @('runs', 'surfaces', 'findings', 'assessments', 'proofs', 'artifacts', 'verdicts')
    }
    foreach ($arr in $requiredArrays) {
        $val = $Doc.$arr
        if ($null -eq $val) {
            Add-Finding $findings 'error' "Missing required array '$arr'." "`$.$arr"
        }
        elseif ($val -isnot [System.Array] -and $val -isnot [System.Collections.IList]) {
            # Newtonsoft/PS may parse empty array as object[]; a single object becomes PSCustomObject
            if ($val.GetType().Name -ne 'Object[]') {
                Add-Finding $findings 'error' "Property '$arr' must be an array." "`$.$arr"
            }
        }
    }

    if ($is10) {
        return [pscustomobject]@{ file = $File; findings = $findings }
    }

    Test-UnknownKeys $Doc $KnownRoot '$' $findings
    if ($Doc.target) { Test-UnknownKeys $Doc.target $KnownByDef.target '$.target' $findings }
    if ($Doc.policy) { Test-UnknownKeys $Doc.policy $KnownByDef.policy '$.policy' $findings }

    $toList = {
        param($x)
        if ($null -eq $x) { return @() }
        if ($x -is [System.Array]) { return @($x) }
        if ($x -is [System.Collections.IList] -and $x -isnot [string]) { return @($x) }
        return @($x)
    }

    $runs = & $toList $Doc.runs
    $surfaces = & $toList $Doc.surfaces
    $findingsArr = & $toList $Doc.findings
    $assessments = & $toList $Doc.assessments
    $proofs = & $toList $Doc.proofs
    $artifacts = & $toList $Doc.artifacts
    $verdicts = & $toList $Doc.verdicts

    Test-UniqueIds $runs 'run' '$.runs' $findings
    Test-UniqueIds $surfaces 'surface' '$.surfaces' $findings
    Test-UniqueIds $findingsArr 'finding' '$.findings' $findings
    Test-UniqueIds $assessments 'assessment' '$.assessments' $findings
    Test-UniqueIds $proofs 'proof' '$.proofs' $findings
    Test-UniqueIds $artifacts 'artifact' '$.artifacts' $findings
    Test-UniqueIds $verdicts 'verdict' '$.verdicts' $findings

    $runIds = Get-IdSet $runs
    $surfaceIds = Get-IdSet $surfaces
    $findingIds = Get-IdSet $findingsArr
    $assessmentIds = Get-IdSet $assessments
    $proofIds = Get-IdSet $proofs
    $artifactIds = Get-IdSet $artifacts
    $verdictIds = Get-IdSet $verdicts

    $i = 0
    foreach ($run in $runs) {
        Test-UnknownKeys $run $KnownByDef.run "$.runs[$i]" $findings
        if ($run.actor) { Test-UnknownKeys $run.actor $KnownByDef.actor "$.runs[$i].actor" $findings }
        Test-RefList $run.inputArtifactIds $artifactIds 'artifact' "$.runs[$i].inputArtifactIds" $findings
        Test-RefList $run.outputArtifactIds $artifactIds 'artifact' "$.runs[$i].outputArtifactIds" $findings
        $i++
    }

    $i = 0
    foreach ($s in $surfaces) {
        Test-UnknownKeys $s $KnownByDef.surface "$.surfaces[$i]" $findings
        $i++
    }

    $i = 0
    foreach ($f in $findingsArr) {
        $p = "$.findings[$i]"
        Test-UnknownKeys $f $KnownByDef.finding $p $findings
        Test-Ref $f.surfaceId $surfaceIds 'surface' "$p.surfaceId" $findings
        Test-RefList $f.surfaceIds $surfaceIds 'surface' "$p.surfaceIds" $findings
        Test-RefList $f.relatedFindingIds $findingIds 'finding' "$p.relatedFindingIds" $findings
        Test-RefList $f.reportedByRunIds $runIds 'run' "$p.reportedByRunIds" $findings
        Test-RefList $f.assessmentIds $assessmentIds 'assessment' "$p.assessmentIds" $findings
        if ($f.origin) { Test-UnknownKeys $f.origin $KnownByDef.origin "$p.origin" $findings }
        if ($f.fingerprint) { Test-UnknownKeys $f.fingerprint $KnownByDef.fingerprint "$p.fingerprint" $findings }
        $i++
    }

    $i = 0
    foreach ($a in $assessments) {
        $p = "$.assessments[$i]"
        Test-UnknownKeys $a $KnownByDef.assessment $p $findings
        Test-Ref $a.findingId $findingIds 'finding' "$p.findingId" $findings
        Test-Ref $a.runId $runIds 'run' "$p.runId" $findings
        Test-Ref $a.proofId $proofIds 'proof' "$p.proofId" $findings
        Test-RefList $a.artifactIds $artifactIds 'artifact' "$p.artifactIds" $findings
        $i++
    }

    $i = 0
    foreach ($pr in $proofs) {
        $p = "$.proofs[$i]"
        Test-UnknownKeys $pr $KnownByDef.proof $p $findings
        Test-Ref $pr.findingId $findingIds 'finding' "$p.findingId" $findings
        Test-Ref $pr.runId $runIds 'run' "$p.runId" $findings
        Test-RefList $pr.artifactIds $artifactIds 'artifact' "$p.artifactIds" $findings
        if ($pr.injection -and $pr.injection.surfaceId) {
            Test-Ref $pr.injection.surfaceId $surfaceIds 'surface' "$p.injection.surfaceId" $findings
        }
        if ($pr.oracle) { Test-UnknownKeys $pr.oracle $KnownByDef.oracle "$p.oracle" $findings }
        $i++
    }

    $i = 0
    foreach ($art in $artifacts) {
        $p = "$.artifacts[$i]"
        Test-UnknownKeys $art $KnownByDef.artifact $p $findings
        Test-Ref $art.producedByRunId $runIds 'run' "$p.producedByRunId" $findings
        $i++
    }

    $i = 0
    foreach ($v in $verdicts) {
        $p = "$.verdicts[$i]"
        Test-UnknownKeys $v $KnownByDef.verdict $p $findings
        Test-Ref $v.findingId $findingIds 'finding' "$p.findingId" $findings
        Test-Ref $v.runId $runIds 'run' "$p.runId" $findings
        Test-Ref $v.supersedesVerdictId $verdictIds 'verdict' "$p.supersedesVerdictId" $findings
        Test-RefList $v.basedOnAssessmentIds $assessmentIds 'assessment' "$p.basedOnAssessmentIds" $findings
        Test-RefList $v.basedOnProofIds $proofIds 'proof' "$p.basedOnProofIds" $findings
        Test-Ref $v.proofId $proofIds 'proof' "$p.proofId" $findings
        if ($v.approval) {
            Test-UnknownKeys $v.approval $KnownByDef.approval "$p.approval" $findings
            Test-Ref $v.approval.approvedByRunId $runIds 'run' "$p.approval.approvedByRunId" $findings
        }
        $i++
    }

    return [pscustomobject]@{ file = $File; findings = $findings }
}

$files = foreach ($p in $InputPath) {
    $cleaned = $p.Trim().Trim('"')
    Get-Item -LiteralPath $cleaned
}

$all = [System.Collections.Generic.List[object]]::new()
foreach ($file in $files) {
    $raw = Get-Content -Raw -LiteralPath $file.FullName
    $doc = $raw | ConvertFrom-Json
    $all.Add((Lint-Document -Doc $doc -File $file.FullName))
}

if ($EmitJson) {
    $all | ConvertTo-Json -Depth 8
}
else {
    foreach ($result in $all) {
        $rel = $result.file
        $shown = @($result.findings)
        if (-not $Strict) {
            # Still show warnings; Strict only affects exit code for warnings
        }
        if ($shown.Count -eq 0) {
            Write-Host "OK  $rel"
            continue
        }
        Write-Host $rel
        foreach ($f in $shown) {
            $tag = $f.severity.ToUpperInvariant().PadRight(7)
            Write-Host "  $tag $($f.path): $($f.message)"
        }
    }
}

$errorCount = @($all | ForEach-Object { $_.findings } | Where-Object { $_.severity -eq 'error' }).Count
$warnCount = @($all | ForEach-Object { $_.findings } | Where-Object { $_.severity -eq 'warning' }).Count
if ($errorCount -gt 0) { exit 1 }
if ($Strict -and $warnCount -gt 0) { exit 1 }
exit 0
