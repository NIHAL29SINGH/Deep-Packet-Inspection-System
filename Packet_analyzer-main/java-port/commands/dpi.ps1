param(
    [Parameter(Position=0)]
    [ValidateSet("build", "normal", "block", "ifaces", "live", "csv", "report", "benchmark")]
    [string]$Mode = "normal",

    [string]$InputPcap = "..\quick_test_mixed_20mb.pcap",
    [string]$OutputPcap = ".\outputs\output_normal.pcap",
    [string]$ReportCsv = ".\outputs\report.csv",
    [string]$ReportJson = ".\outputs\report.json",
    [string]$Iface = "Realtek",
    [int]$Duration = 30,
    [string]$CaptureOut = ".\outputs\live_input.pcap",
    [int]$Lbs = 0,
    [int]$Fps = 0,
    [switch]$NoBench,
    [switch]$Monitor,
    [switch]$NoMetrics,
    [string]$MetricsBind = "0.0.0.0",
    [int]$MetricsPort = 9400,
    [int]$MetricsHold = 0,
    [string]$MetricsFile = ".\outputs\prometheus_metrics.prom",

    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ExtraRules
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path $PSScriptRoot -Parent
Set-Location $projectRoot
$outputDir = Join-Path $projectRoot "outputs"
if (-not (Test-Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir | Out-Null
}

function To-OutputsPath {
    param(
        [string]$PathValue,
        [string]$FallbackName
    )
    $name = ""
    if (-not [string]::IsNullOrWhiteSpace($PathValue)) {
        $name = [System.IO.Path]::GetFileName($PathValue)
    }
    if ([string]::IsNullOrWhiteSpace($name)) {
        $name = $FallbackName
    }
    return ".\outputs\$name"
}

# Force all generated artifacts into .\outputs
$OutputPcap = To-OutputsPath $OutputPcap "output_normal.pcap"
$ReportCsv = To-OutputsPath $ReportCsv "report.csv"
$ReportJson = To-OutputsPath $ReportJson "report.json"
$CaptureOut = To-OutputsPath $CaptureOut "live_input.pcap"

function Run-Mvn {
    param([string]$ExecArgs)
    mvn exec:java "-Dexec.mainClass=com.deeppacket.app.DpiMain" "-Dexec.args=$ExecArgs"
}

function Build-MetricsArgs {
    $parts = New-Object System.Collections.Generic.List[string]
    if ($NoMetrics) {
        $parts.Add("--no-metrics")
    } else {
        $parts.Add("--metrics-bind $MetricsBind")
        $parts.Add("--metrics-port $MetricsPort")
        $parts.Add("--metrics-hold $MetricsHold")
        $parts.Add("--metrics-file $MetricsFile")
    }
    return [string]::Join(" ", $parts)
}

function Build-MonitorReportArgs {
    param([string]$CurrentMode)
    if (-not $Monitor) { return "" }
    if ($CurrentMode -eq "csv" -or $CurrentMode -eq "report") { return "" }
    $csv = ".\outputs\monitor_${CurrentMode}.csv"
    $json = ".\outputs\monitor_${CurrentMode}.json"
    return "--report-csv $csv --report-json $json"
}

function Build-ExtraRuleArgs {
    param([string[]]$Rules)

    if (-not $Rules -or $Rules.Count -eq 0) {
        return ""
    }

    $parts = New-Object System.Collections.Generic.List[string]
    foreach ($rawRule in $Rules) {
        if ([string]::IsNullOrWhiteSpace($rawRule)) {
            continue
        }
        $expandedRules = $rawRule -split ","
        foreach ($ruleToken in $expandedRules) {
            $rule = $ruleToken.Trim()
            if ([string]::IsNullOrWhiteSpace($rule)) {
                continue
            }

            # shorthand defaults to domain block, e.g. 'telegram' -> --block-domain telegram
            if ($rule.StartsWith("app:", [System.StringComparison]::OrdinalIgnoreCase)) {
                $parts.Add("--block-app $($rule.Substring(4))")
            } elseif ($rule.StartsWith("ip:", [System.StringComparison]::OrdinalIgnoreCase)) {
                $parts.Add("--block-ip $($rule.Substring(3))")
            } elseif ($rule.StartsWith("domain:", [System.StringComparison]::OrdinalIgnoreCase)) {
                $parts.Add("--block-domain $($rule.Substring(7))")
            } else {
                $parts.Add("--block-domain $rule")
                # Add app rule only for known app labels (not raw domains like youtu.be).
                switch -Regex ($rule.ToLowerInvariant()) {
                    '^(youtube|google|facebook|instagram|twitter|x|tiktok|spotify|telegram|discord|github|cloudflare|amazon|apple|microsoft|netflix|whatsapp|http|https|dns|tls|quic)$' {
                        $parts.Add("--block-app $rule")
                    }
                }
            }
        }
    }

    return [string]::Join(" ", $parts)
}

function Try-ParseDurationSeconds {
    param([string]$Token)
    if ([string]::IsNullOrWhiteSpace($Token)) { return $null }
    $t = $Token.Trim().ToLowerInvariant()
    if ($t -match '^\d+$') { return [int]$t }
    if ($t -match '^(\d+)\s*s(ec|ecs|econd|econds)?$') { return [int]$matches[1] }
    if ($t -match '^(\d+)\s*m(in|ins|inute|inutes)?$') { return ([int]$matches[1]) * 60 }
    return $null
}

$extraArgString = Build-ExtraRuleArgs $ExtraRules
$monitorReportArgString = Build-MonitorReportArgs $Mode
if ($Monitor) {
    $NoMetrics = $false
}
$metricsArgString = Build-MetricsArgs
$benchInput = $InputPcap
$benchRules = @()
$benchLbs = 2
$benchFps = 2
if ($Lbs -gt 0) { $benchLbs = $Lbs }
if ($Fps -gt 0) { $benchFps = $Fps }
$mainModeOk = $true

switch ($Mode) {
    "build" {
        mvn clean package
    }
    "ifaces" {
        Run-Mvn "--list-ifaces"
    }
    "normal" {
        Run-Mvn "$InputPcap $OutputPcap $monitorReportArgString $metricsArgString"
    }
    "block" {
        if ($OutputPcap -eq ".\outputs\output_normal.pcap") { $OutputPcap = ".\outputs\output_blocked.pcap" }
        if ([string]::IsNullOrWhiteSpace($extraArgString)) {
            $benchRules = @("youtube", "facebook")
            Run-Mvn "$InputPcap $OutputPcap --block-app YouTube --block-domain facebook --verbose $monitorReportArgString $metricsArgString"
        } else {
            $benchRules = $ExtraRules
            Run-Mvn "$InputPcap $OutputPcap $extraArgString --verbose $monitorReportArgString $metricsArgString"
        }
    }
    "live" {
        if ($ExtraRules -and $ExtraRules.Count -gt 0) {
            $parsedDuration = Try-ParseDurationSeconds $ExtraRules[0]
            if ($parsedDuration -ne $null) {
                $Duration = $parsedDuration
            }
        }
        if ($OutputPcap -eq ".\outputs\output_normal.pcap") { $OutputPcap = ".\outputs\output_live_filtered.pcap" }
        Run-Mvn "--live $OutputPcap --iface $Iface --duration $Duration --capture-out $CaptureOut --verbose $monitorReportArgString $metricsArgString"
        $benchInput = $CaptureOut
    }
    "csv" {
        if ($OutputPcap -eq ".\outputs\output_normal.pcap") { $OutputPcap = ".\outputs\output_csv.pcap" }
        Run-Mvn "$InputPcap $OutputPcap --report-csv $ReportCsv --verbose $metricsArgString"
    }
    "report" {
        if ($OutputPcap -eq ".\outputs\output_normal.pcap") { $OutputPcap = ".\outputs\output_report.pcap" }
        Run-Mvn "$InputPcap $OutputPcap --report-csv $ReportCsv --report-json $ReportJson --verbose $metricsArgString"
    }
    "benchmark" {
        if ($OutputPcap -eq ".\outputs\output_normal.pcap") { $OutputPcap = ".\outputs\output_benchmark.pcap" }
        $threadArgs = ""
        if ($Lbs -gt 0) { $threadArgs += " --lbs $Lbs" }
        if ($Fps -gt 0) { $threadArgs += " --fps $Fps" }
        if ([string]::IsNullOrWhiteSpace($extraArgString)) {
            Run-Mvn "$InputPcap $OutputPcap --report-json $ReportJson$threadArgs $monitorReportArgString $metricsArgString"
        } else {
            Run-Mvn "$InputPcap $OutputPcap --report-json $ReportJson$threadArgs $extraArgString $monitorReportArgString $metricsArgString"
        }
    }
}

if ($LASTEXITCODE -ne 0) {
    $mainModeOk = $false
}

$autoBenchModes = @("normal", "block", "live", "csv", "report")
if ($mainModeOk -and -not $NoBench -and ($autoBenchModes -contains $Mode)) {
    Write-Host ""
    Write-Host "[AutoBench] Running quick benchmark (1 run, 1 warmup)..."
    & "$PSScriptRoot\bench.ps1" -InputPcap $benchInput -Runs 1 -Warmup 1 -Lbs $benchLbs -Fps $benchFps -Rules $benchRules
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "[AutoBench] Benchmark failed. Main command output is still valid."
    }
}
