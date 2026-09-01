[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$wrapperErrorLog = 'C:\ARTIFEX-M12-J09-wrapper-error.log'

trap {
    [System.IO.File]::WriteAllText(
        $wrapperErrorLog,
        ($_ | Out-String),
        [System.Text.UTF8Encoding]::new($false)
    )
    exit 1
}

$python = 'C:\Program Files\Python312\python.exe'
$harness = 'E:\qualify_m9_black_box.py'
$artifact = 'E:\ARTIFEX-Setup.exe'
$executable = 'C:\Program Files\ARTIFEX\artifex.exe'
$v1Repository = 'C:\ARTIFEX-M9-Qualification\v1-project'
$qualificationRoot = 'C:\ARTIFEX-M12-J09-Qualification'
$failedRoot = 'C:\ARTIFEX-M12-J09-ATTEMPT1-FAIL'
$output = 'C:\ARTIFEX-M12-J09-PASS.json'
$log = 'C:\ARTIFEX-M12-J09.log'

$expected = [ordered]@{
    python = 'C:\Program Files\Python312\python.exe'
    harness = 'E:\qualify_m9_black_box.py'
    artifact = 'E:\ARTIFEX-Setup.exe'
    executable = 'C:\Program Files\ARTIFEX\artifex.exe'
    v1_repository = 'C:\ARTIFEX-M9-Qualification\v1-project'
    qualification_root = 'C:\ARTIFEX-M12-J09-Qualification'
    failed_root = 'C:\ARTIFEX-M12-J09-ATTEMPT1-FAIL'
    output = 'C:\ARTIFEX-M12-J09-PASS.json'
    log = 'C:\ARTIFEX-M12-J09.log'
    wrapper_error_log = 'C:\ARTIFEX-M12-J09-wrapper-error.log'
}
$actual = [ordered]@{
    python = $python
    harness = $harness
    artifact = $artifact
    executable = $executable
    v1_repository = $v1Repository
    qualification_root = $qualificationRoot
    failed_root = $failedRoot
    output = $output
    log = $log
    wrapper_error_log = $wrapperErrorLog
}
foreach ($name in $expected.Keys) {
    $resolved = [System.IO.Path]::GetFullPath($actual[$name])
    if ($resolved -cne $expected[$name]) {
        throw "Refusing J09 because $name did not resolve to the authorized path."
    }
}

foreach ($required in ($python, $harness, $artifact, $executable, (Join-Path $v1Repository '.git'))) {
    if (-not (Test-Path -LiteralPath $required)) {
        throw "Required J09 input is missing: $required"
    }
}

if (Test-Path -LiteralPath $qualificationRoot) {
    if (Test-Path -LiteralPath $failedRoot) {
        throw 'The preserved J09 attempt-one failure already exists.'
    }
    Move-Item -LiteralPath $qualificationRoot -Destination $failedRoot
}
if ((Test-Path -LiteralPath $output) -or (Test-Path -LiteralPath $log)) {
    throw 'A prior J09 output or diagnostic log would be overwritten.'
}

$arguments = @(
    $harness,
    '--artifex-executable', $executable,
    '--candidate-artifact', $artifact,
    '--expected-artifact-sha256', 'ff00500fface43eb4a15d0c0ec7b93ccef46af9ffd17d516870b51b3838c2bf8',
    '--expected-source-commit', 'e7fe88336f04e3f9e7c8b45299f7af90d3a4a1fe',
    '--v1-repository', $v1Repository,
    '--qualification-root', $qualificationRoot,
    '--output', $output
)

& $python @arguments *> $log
$exitCode = $LASTEXITCODE
$status = if (Test-Path -LiteralPath $output) {
    (Get-Content -Raw -LiteralPath $output | ConvertFrom-Json).status
} else {
    'NO_OUTPUT'
}

[ordered]@{
    schema_version = '1.0'
    status = $status
    exit_code = $exitCode
    output_present = Test-Path -LiteralPath $output
    output_sha256 = if (Test-Path -LiteralPath $output) {
        (Get-FileHash -Algorithm SHA256 -LiteralPath $output).Hash.ToLower()
    } else {
        $null
    }
    diagnostic_log_present = Test-Path -LiteralPath $log
} | ConvertTo-Json -Compress

exit $exitCode
