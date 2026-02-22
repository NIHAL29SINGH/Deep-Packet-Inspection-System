param(
    [Parameter(Position=0)]
    [ValidateSet("start", "stop", "status", "logs", "links", "open", "run", "runblock")]
    [string]$Action = "run",

    [Parameter(Position=1)]
    [string]$Arg1 = "",

    [Parameter(Position=2)]
    [int]$HoldSeconds = 180
)

$projectRoot = Split-Path $PSScriptRoot -Parent

function Show-Links {
    Write-Host "Prometheus: http://localhost:9090"
    Write-Host "Grafana   : http://localhost:3001 (admin/admin)"
}

function Ensure-MonitorUp {
    & "$projectRoot\monitor.cmd" up | Out-Null
}

switch ($Action) {
    "start" {
        Ensure-MonitorUp
        Show-Links
    }
    "stop" {
        & "$projectRoot\monitor.cmd" down
    }
    "status" {
        & "$projectRoot\monitor.cmd" status
        Show-Links
    }
    "logs" {
        & "$projectRoot\monitor.cmd" logs
    }
    "links" {
        Show-Links
    }
    "open" {
        Start-Process "http://localhost:9090"
        Start-Process "http://localhost:3001"
    }
    "run" {
        Ensure-MonitorUp
        $callArgs = @("normal")
        if (-not [string]::IsNullOrWhiteSpace($Arg1)) {
            $callArgs += @("-InputPcap", $Arg1)
        }
        $callArgs += @("-Monitor", "-NoBench", "-MetricsHold", $HoldSeconds)
        & powershell -ExecutionPolicy Bypass -File "$projectRoot\commands\dpi.ps1" @callArgs
        Show-Links
    }
    "runblock" {
        Ensure-MonitorUp
        $rules = if ([string]::IsNullOrWhiteSpace($Arg1)) { "youtube,facebook" } else { $Arg1 }
        & powershell -ExecutionPolicy Bypass -File "$projectRoot\commands\dpi.ps1" block $rules -Monitor -NoBench -MetricsHold $HoldSeconds
        Show-Links
    }
}
