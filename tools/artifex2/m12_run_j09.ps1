[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

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

if (Test-Path -LiteralPath $failedRoot) {
    throw 'The preserved J09 attempt-one failure already exists.'
}
if (Test-Path -LiteralPath $qualificationRoot) {
    Move-Item -LiteralPath $qualificationRoot -Destination $failedRoot
}
if (Test-Path -LiteralPath $output -or Test-Path -LiteralPath $log) {
    throw 'A prior J09 output or diagnostic log would be overwritten.'
}

$arguments = @(
    $harness,
    '--artifex-executable', $executable,
    '--candidate-artifact', $artifact,
    '--expected-artifact-sha256', '0a094ab12420f0fe18092dd834801f4b2463ba39837e4ae0b2d0e2881ae81778',
    '--expected-source-commit', '5b5750fcee0eddc74a223334be07224c6ff4b930',
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
