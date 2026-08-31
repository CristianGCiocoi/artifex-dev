[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$targets = @(
    'C:\ARTIFEX-M9-Qualification',
    'C:\ARTIFEX-M12-J09-ATTEMPT1-FAIL',
    'C:\ARTIFEX-M12-J09-Qualification',
    'C:\ARTIFEX-M12-J09-Qualification-V2',
    'C:\ARTIFEX-M12-J09-PASS.json',
    'C:\ARTIFEX-M12-J09.log',
    'C:\ARTIFEX-M12-J09.exit.txt',
    'C:\ARTIFEX-M12-J09-wrapper-error.log',
    'C:\Users\crugger\AppData\Local\ARTIFEX-M12-J09-Qualification-V3',
    'C:\Users\crugger\AppData\Local\ARTIFEX-M12-J09-PASS.json',
    'C:\Users\crugger\AppData\Local\ARTIFEX-M12-J09-wrapper.json'
)

$resolvedTargets = foreach ($target in $targets) {
    $resolved = [System.IO.Path]::GetFullPath($target)
    if ($resolved -cne $target) {
        throw "Refusing J09 cleanup because a target did not resolve exactly: $target"
    }
    $resolved
}

$runningTasks = @(
    Get-ScheduledTask |
        Where-Object {
            $_.TaskName -like 'ARTIFEX-M12-J09-*' -and $_.State -eq 'Running'
        }
)
if ($runningTasks.Count -ne 0) {
    throw 'Refusing J09 cleanup while a qualification task is still running.'
}

foreach ($target in $resolvedTargets) {
    if (Test-Path -LiteralPath $target) {
        Remove-Item -LiteralPath $target -Recurse -Force
    }
}

$remaining = @($resolvedTargets | Where-Object { Test-Path -LiteralPath $_ })
[ordered]@{
    schema_version = '1.0'
    status = if ($remaining.Count -eq 0) { 'PASS' } else { 'FAIL' }
    removed_target_count = $resolvedTargets.Count - $remaining.Count
    remaining_targets = $remaining
    preserved_media_root = Test-Path -LiteralPath 'C:\ARTIFEX-M12-Media'
} | ConvertTo-Json -Depth 4 -Compress
