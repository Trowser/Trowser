# Sync trowserkit/swagger/openapi.yaml with trowser-api-index.md
# Preserves detailed existing path definitions; adds missing endpoints from the index.
param(
    [string]$RepoRoot = (Resolve-Path "$PSScriptRoot\..").Path
)

$sync = Join-Path $RepoRoot "scripts\sync-openapi.py"
$validate = Join-Path $RepoRoot "scripts\validate-openapi.py"

python $sync
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

python $validate
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "Running OpenApiSpecTests..." -ForegroundColor Cyan
dotnet test (Join-Path $RepoRoot "src\Trowser.Tests\Trowser.Tests.csproj") -c Release --filter "FullyQualifiedName~OpenApiSpecTests" --logger "console;verbosity=minimal"
exit $LASTEXITCODE
