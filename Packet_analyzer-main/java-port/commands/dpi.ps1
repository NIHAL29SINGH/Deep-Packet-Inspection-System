param(
    [Parameter(Position=0)]
    [ValidateSet("build", "normal", "block", "ifaces", "live", "csv", "report")]
    [string]$Mode = "normal",

    [string]$InputPcap = "..\test_dpi.pcap",
    [string]$OutputPcap = ".\outputs\output_normal.pcap",
    [string]$ReportCsv = ".\outputs\report.csv",
    [string]$ReportJson = ".\outputs\report.json",
    [string]$Iface = "Realtek",
    [int]$Duration = 30,
    [string]$CaptureOut = ".\outputs\live_input.pcap",

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

switch ($Mode) {
    "build" {
        mvn clean package
    }
    "ifaces" {
        Run-Mvn "--list-ifaces"
    }
    "normal" {
        Run-Mvn "$InputPcap $OutputPcap"
    }
    "block" {
        if ($OutputPcap -eq ".\outputs\output_normal.pcap") { $OutputPcap = ".\outputs\output_blocked.pcap" }
        if ([string]::IsNullOrWhiteSpace($extraArgString)) {
            Run-Mvn "$InputPcap $OutputPcap --block-app YouTube --block-domain facebook --verbose"
        } else {
            Run-Mvn "$InputPcap $OutputPcap $extraArgString --verbose"
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
        Run-Mvn "--live $OutputPcap --iface $Iface --duration $Duration --capture-out $CaptureOut --verbose"
    }
    "csv" {
        if ($OutputPcap -eq ".\outputs\output_normal.pcap") { $OutputPcap = ".\outputs\output_csv.pcap" }
        Run-Mvn "$InputPcap $OutputPcap --report-csv $ReportCsv --verbose"
    }
    "report" {
        if ($OutputPcap -eq ".\outputs\output_normal.pcap") { $OutputPcap = ".\outputs\output_report.pcap" }
        Run-Mvn "$InputPcap $OutputPcap --report-csv $ReportCsv --report-json $ReportJson --verbose"
    }
}
