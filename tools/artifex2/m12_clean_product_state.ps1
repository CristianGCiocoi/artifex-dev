[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$installRoot = [System.IO.Path]::GetFullPath('C:\Program Files\ARTIFEX')
$stateRoot = [System.IO.Path]::GetFullPath('C:\Users\crugger\AppData\Local\ARTIFEX')
$expectedInstallRoot = 'C:\Program Files\ARTIFEX'
$expectedStateRoot = 'C:\Users\crugger\AppData\Local\ARTIFEX'

if ($installRoot -cne $expectedInstallRoot -or $stateRoot -cne $expectedStateRoot) {
    throw 'Refusing cleanup because an ARTIFEX root did not resolve to the authorized path.'
}

$running = @(
    Get-CimInstance Win32_Process |
        Where-Object {
            $_.ExecutablePath -and
            [System.IO.Path]::GetFullPath($_.ExecutablePath).StartsWith(
                $installRoot + [System.IO.Path]::DirectorySeparatorChar,
                [System.StringComparison]::OrdinalIgnoreCase
            )
        }
)
if ($running.Count -ne 0) {
    throw 'Refusing cleanup while an installed ARTIFEX process is still running.'
}

$tasks = @(Get-ScheduledTask | Where-Object { $_.TaskName -like 'ARTIFEX-*' })
foreach ($task in $tasks) {
    Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false
}

foreach ($target in ($installRoot, $stateRoot)) {
    if (Test-Path -LiteralPath $target) {
        Remove-Item -LiteralPath $target -Recurse -Force
    }
}

$remainingTasks = @(
    Get-ScheduledTask |
        Where-Object { $_.TaskName -like 'ARTIFEX-*' } |
        Select-Object -ExpandProperty TaskName
)

[ordered]@{
    schema_version = '1.0'
    status = if (
        -not (Test-Path -LiteralPath $installRoot) -and
        -not (Test-Path -LiteralPath $stateRoot) -and
        $remainingTasks.Count -eq 0
    ) { 'PASS' } else { 'FAIL' }
    install_root = $installRoot
    install_root_absent = -not (Test-Path -LiteralPath $installRoot)
    state_root = $stateRoot
    state_root_absent = -not (Test-Path -LiteralPath $stateRoot)
    remaining_artifex_tasks = $remainingTasks
    running_artifex_processes = $running.Count
} | ConvertTo-Json -Depth 4 -Compress
