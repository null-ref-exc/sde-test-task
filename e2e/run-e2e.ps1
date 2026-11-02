param([switch]$SkipBuild, [switch]$Docker)
$ErrorActionPreference = 'Stop'
$project = Join-Path $PSScriptRoot '..'
$pythonArguments = @()
if ($env:PYTHON) { $pythonPath = $env:PYTHON }
elseif (Get-Command py -ErrorAction SilentlyContinue) {
    $pythonPath = (Get-Command py).Source
    $pythonArguments = @('-3')
} elseif (Get-Command python -ErrorAction SilentlyContinue) {
    $pythonPath = (Get-Command python).Source
} else { throw 'Install Python 3.10+ and add it to PATH, or set PYTHON to its executable.' }
& $pythonPath @pythonArguments -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else "Python 3.10+ is required")'
if ($LASTEXITCODE -ne 0) { throw 'Python 3.10+ is required.' }
if ($Docker) {
    if (-not $SkipBuild) {
        docker build -t vulnerability-tracker:e2e $project
        if ($LASTEXITCODE -ne 0) { throw 'Docker build failed' }
    }
} elseif (-not $SkipBuild) {
    Push-Location $project
    try {
        dotnet tool restore
        if ($LASTEXITCODE -ne 0) { throw 'Tool restore failed' }
        dotnet build VulnerabilityTracker.slnx -c Release -v:q
        if ($LASTEXITCODE -ne 0) { throw 'Build failed' }
    } finally { Pop-Location }
}
$testArguments = @()
if ($Docker) { $testArguments += @('--docker-image', 'vulnerability-tracker:e2e') }
& $pythonPath @pythonArguments (Join-Path $PSScriptRoot 'e2e.py') @testArguments
exit $LASTEXITCODE
