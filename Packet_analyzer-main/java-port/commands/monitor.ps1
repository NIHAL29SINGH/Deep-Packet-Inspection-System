param(
    [Parameter(Position=0)]
    [ValidateSet("up", "down", "restart", "logs", "status")]
    [string]$Action = "up"
)

$projectRoot = Split-Path $PSScriptRoot -Parent
$monitoringDir = Join-Path $projectRoot "monitoring"

if (-not (Test-Path $monitoringDir)) {
    Write-Error "Monitoring directory not found: $monitoringDir"
    exit 1
}

Push-Location $monitoringDir
try {
    switch ($Action) {
        "up"      { docker compose up -d }
        "down"    { docker compose down }
        "restart" { docker compose down; docker compose up -d }
        "logs"    { docker compose logs -f }
        "status"  { docker compose ps }
    }
} finally {
    Pop-Location
}

