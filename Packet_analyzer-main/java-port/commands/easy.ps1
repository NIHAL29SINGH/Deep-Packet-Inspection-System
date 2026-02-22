param(
    [Parameter(Position=0)]
    [string]$Action = "help",

    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Args
)

$projectRoot = Split-Path $PSScriptRoot -Parent

function Show-Help {
    Write-Host ""
    Write-Host "Easy Commands"
    Write-Host "-------------"
    Write-Host "  .\easy.cmd n"
    Write-Host "  .\easy.cmd b youtube,facebook"
    Write-Host "  .\easy.cmd l 30"
    Write-Host "  .\easy.cmd c output_blocked.csv"
    Write-Host "  .\easy.cmd r myreport"
    Write-Host "  .\easy.cmd build"
    Write-Host ""
    Write-Host "Short forms: n=normal, b=block, l=live, c=csv, r=report"
    Write-Host "Add -NoBench to skip benchmark, example: .\easy.cmd n -NoBench"
    Write-Host ""
}

$a = $Action.Trim().ToLowerInvariant()

switch ($a) {
    "n" {
        & "$projectRoot\normal.cmd" @Args
    }
    "normal" {
        & "$projectRoot\normal.cmd" @Args
    }
    "b" {
        if (-not $Args -or $Args.Count -eq 0) {
            & "$projectRoot\block.cmd" "youtube"
        } else {
            & "$projectRoot\block.cmd" @Args
        }
    }
    "block" {
        if (-not $Args -or $Args.Count -eq 0) {
            & "$projectRoot\block.cmd" "youtube"
        } else {
            & "$projectRoot\block.cmd" @Args
        }
    }
    "l" {
        if (-not $Args -or $Args.Count -eq 0) {
            & "$projectRoot\live.cmd" "30"
        } else {
            & "$projectRoot\live.cmd" @Args
        }
    }
    "live" {
        if (-not $Args -or $Args.Count -eq 0) {
            & "$projectRoot\live.cmd" "30"
        } else {
            & "$projectRoot\live.cmd" @Args
        }
    }
    "c" {
        if (-not $Args -or $Args.Count -eq 0) {
            & "$projectRoot\csv.cmd" "report.csv"
        } else {
            & "$projectRoot\csv.cmd" @Args
        }
    }
    "csv" {
        if (-not $Args -or $Args.Count -eq 0) {
            & "$projectRoot\csv.cmd" "report.csv"
        } else {
            & "$projectRoot\csv.cmd" @Args
        }
    }
    "r" {
        if (-not $Args -or $Args.Count -eq 0) {
            & "$projectRoot\report.cmd" "report"
        } else {
            & "$projectRoot\report.cmd" @Args
        }
    }
    "report" {
        if (-not $Args -or $Args.Count -eq 0) {
            & "$projectRoot\report.cmd" "report"
        } else {
            & "$projectRoot\report.cmd" @Args
        }
    }
    "build" {
        & "$projectRoot\build.cmd" @Args
    }
    "help" {
        Show-Help
    }
    default {
        Show-Help
    }
}

