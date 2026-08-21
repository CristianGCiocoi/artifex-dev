param(
    [Parameter(Mandatory = $true)][string]$Artifact,
    [Parameter(Mandatory = $true)][string]$InstallRoot,
    [string]$Confirm
)
$ErrorActionPreference = "Stop"
$resolvedArtifact = (Resolve-Path -LiteralPath $Artifact).Path
if (-not $Confirm) {
    & $resolvedArtifact install --install-root $InstallRoot --source-executable $resolvedArtifact
    Write-Host "Review the plan above, then rerun with -Confirm <confirmation_token>."
    exit $LASTEXITCODE
}
& $resolvedArtifact install --install-root $InstallRoot --source-executable $resolvedArtifact --apply --confirm $Confirm
exit $LASTEXITCODE
