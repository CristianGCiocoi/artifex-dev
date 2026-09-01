[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet(104, 105, 106)]
    [int]$VmId
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$installRoot = 'C:\Program Files\ARTIFEX'
$targets = @(
    $installRoot,
    'C:\Users\Crugger\AppData\Local\ARTIFEX',
    "C:\Users\Crugger\AppData\Local\ARTIFEX-M12-Project-VM$VmId",
    "C:\Users\Crugger\AppData\Local\ARTIFEX-M12-Project-VM$VmId-catalog.sqlite3",
    'C:\Users\Crugger\AppData\Local\ARTIFEX-M12-Evidence',
    "C:\ARTIFEX-M12-M7-Staging-VM$VmId",
    'C:\ARTIFEX-M7-Qualification',
    'C:\ARTIFEX-M12-Qualification',
    'C:\ARTIFEX-M12-J09-Qualification',
    'C:\ARTIFEX-M12-J09-Qualification-V2',
    'C:\ARTIFEX-M9-Qualification'
)

foreach ($target in $targets) {
    if ([System.IO.Path]::GetFullPath($target) -cne $target) {
        throw "Refusing cleanup because a target did not resolve exactly: $target"
    }
}
if (Test-Path -LiteralPath 'C:\aidev\artifex') {
    throw 'Unexpected guest source tree is present; refusing qualification cleanup.'
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

Get-ScheduledTask |
    Where-Object { $_.TaskName -like 'ARTIFEX-*' } |
    ForEach-Object {
        Unregister-ScheduledTask -TaskName $_.TaskName -Confirm:$false
    }

foreach ($target in $targets) {
    if (Test-Path -LiteralPath $target) {
        Remove-Item -LiteralPath $target -Recurse -Force
    }
}

$remainingPaths = @($targets | Where-Object { Test-Path -LiteralPath $_ })
$remainingTasks = @(
    Get-ScheduledTask |
        Where-Object { $_.TaskName -like 'ARTIFEX-*' } |
        Select-Object -ExpandProperty TaskName
)

[ordered]@{
    schema_version = '1.0'
    status = if ($remainingPaths.Count -eq 0 -and $remainingTasks.Count -eq 0) {
        'PASS'
    } else {
        'FAIL'
    }
    vm_id = $VmId
    removed_targets = $targets
    remaining_paths = $remainingPaths
    remaining_artifex_tasks = $remainingTasks
    running_artifex_processes = $running.Count
    provider_state_touched = $false
    rdp_state_touched = $false
} | ConvertTo-Json -Depth 5 -Compress
