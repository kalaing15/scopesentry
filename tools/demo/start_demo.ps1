[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$ProjectRoot = 'C:\scopesentry'
$Python = Join-Path $ProjectRoot '.venv\Scripts\python.exe'
$HostAddress = '127.0.0.1'
$Port = 8000
$DashboardUrl = "http://${HostAddress}:${Port}/demo"
$SwaggerUrl = "http://${HostAddress}:${Port}/docs"

if (-not (Test-Path -LiteralPath $Python -PathType Leaf)) {
    throw "ScopeSentry-R virtual-environment interpreter was not found at $Python"
}

$previousLocation = Get-Location
try {
    Set-Location -LiteralPath $ProjectRoot
    $env:PYTHONDONTWRITEBYTECODE = '1'

    Write-Host 'Running read-only demo preflight...'
    & $Python 'tools\demo\preflight.py' --host $HostAddress --port $Port
    if ($LASTEXITCODE -ne 0) {
        throw 'Demo preflight failed. Resolve the reported check before starting the backend.'
    }

    Write-Host ''
    Write-Host "Dashboard: $DashboardUrl"
    Write-Host "Swagger:   $SwaggerUrl"
    Write-Host 'Press Ctrl+C to stop the ScopeSentry-R backend.'
    Write-Host ''

    & $Python -m uvicorn app.main:app --host $HostAddress --port $Port
    if ($LASTEXITCODE -ne 0) {
        throw "Uvicorn exited with code $LASTEXITCODE"
    }
}
finally {
    Set-Location -LiteralPath $previousLocation
}
