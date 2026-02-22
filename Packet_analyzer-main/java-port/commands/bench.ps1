param(
    [Parameter(Position=0)]
    [string]$InputPcap = "..\quick_test_mixed_20mb.pcap",

    [Parameter(Position=1)]
    [int]$Runs = 5,

    [Parameter(Position=2)]
    [int]$Warmup = 1,

    [Parameter(Position=3)]
    [int]$Lbs = 2,

    [Parameter(Position=4)]
    [int]$Fps = 2,

    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Rules
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path $PSScriptRoot -Parent
Set-Location $projectRoot
$outputDir = Join-Path $projectRoot "outputs"
if (-not (Test-Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir | Out-Null
}

if ($Runs -lt 1) { throw "Runs must be >= 1" }
if ($Warmup -lt 0) { throw "Warmup must be >= 0" }
if ($Lbs -lt 1 -or $Fps -lt 1) { throw "Lbs/Fps must be >= 1" }

function Build-RuleTokens {
    param([string[]]$RuleTokens)
    $parts = New-Object System.Collections.Generic.List[string]
    if (-not $RuleTokens -or $RuleTokens.Count -eq 0) {
        return $parts
    }

    foreach ($raw in $RuleTokens) {
        if ([string]::IsNullOrWhiteSpace($raw)) { continue }
        foreach ($token in ($raw -split ",")) {
            $rule = $token.Trim()
            if ([string]::IsNullOrWhiteSpace($rule)) { continue }
            if ($rule.StartsWith("app:", [System.StringComparison]::OrdinalIgnoreCase)) {
                $parts.Add("--block-app")
                $parts.Add($rule.Substring(4))
            } elseif ($rule.StartsWith("ip:", [System.StringComparison]::OrdinalIgnoreCase)) {
                $parts.Add("--block-ip")
                $parts.Add($rule.Substring(3))
            } elseif ($rule.StartsWith("domain:", [System.StringComparison]::OrdinalIgnoreCase)) {
                $parts.Add("--block-domain")
                $parts.Add($rule.Substring(7))
            } else {
                $parts.Add("--block-domain")
                $parts.Add($rule)
            }
        }
    }
    return $parts
}

function Ensure-DirectJavaRuntime {
    $classesDir = Join-Path $projectRoot "target\classes"
    if (-not (Test-Path $classesDir)) {
        Write-Host "[Bench] Compiling project once..."
        mvn -q -DskipTests compile
        if ($LASTEXITCODE -ne 0) {
            throw "Compile failed."
        }
    }

    $cpFile = Join-Path $projectRoot "target\classpath.txt"
    if (-not (Test-Path $cpFile)) {
        Write-Host "[Bench] Resolving runtime classpath once..."
        mvn -q dependency:build-classpath "-Dmdep.outputFile=target\classpath.txt" "-Dmdep.pathSeparator=;"
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to build runtime classpath."
        }
    }

    if (-not (Test-Path $cpFile)) {
        throw "Missing classpath file: target\classpath.txt"
    }

    $depCp = (Get-Content $cpFile -Raw).Trim()
    if ([string]::IsNullOrWhiteSpace($depCp)) {
        return "target\classes"
    }
    return "target\classes;$depCp"
}

function Run-One {
    param(
        [string]$JavaCp,
        [string]$InputPath,
        [string]$OutPcap,
        [string]$OutJson,
        [int]$LbCount,
        [int]$FpCount,
        [System.Collections.Generic.List[string]]$RuleArgs
    )

    $dpiArgs = New-Object System.Collections.Generic.List[string]
    $dpiArgs.Add($InputPath)
    $dpiArgs.Add($OutPcap)
    $dpiArgs.Add("--report-json")
    $dpiArgs.Add($OutJson)
    $dpiArgs.Add("--lbs")
    $dpiArgs.Add("$LbCount")
    $dpiArgs.Add("--fps")
    $dpiArgs.Add("$FpCount")
    foreach ($t in $RuleArgs) { $dpiArgs.Add($t) }

    & java "-cp" $JavaCp "com.deeppacket.app.DpiMain" @dpiArgs | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Benchmark run failed."
    }

    $jsonAbs = Join-Path $projectRoot $OutJson
    if (-not (Test-Path $jsonAbs)) {
        throw "Missing benchmark JSON: $OutJson"
    }
    return (Get-Content $jsonAbs -Raw | ConvertFrom-Json)
}

function Avg([double[]]$arr) {
    if (-not $arr -or $arr.Count -eq 0) { return 0.0 }
    return ($arr | Measure-Object -Average).Average
}

$ruleTokens = Build-RuleTokens $Rules
$javaCp = Ensure-DirectJavaRuntime
$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$samples = New-Object System.Collections.Generic.List[object]

Write-Host ""
Write-Host "=============================================================="
Write-Host " BENCHMARK MODE (DIRECT JAVA)"
Write-Host "--------------------------------------------------------------"
Write-Host " Input        : $InputPcap"
Write-Host " Warmup runs  : $Warmup"
Write-Host " Measured runs: $Runs"
Write-Host " Threads      : LBs=$Lbs, FPs/LB=$Fps, Total=$($Lbs * $Fps)"
if ($ruleTokens.Count -eq 0) {
    Write-Host " Rules        : none (baseline)"
} else {
    Write-Host " Rules        : enabled"
}
Write-Host "=============================================================="

for ($i = 1; $i -le $Warmup; $i++) {
    $tmpJson = ".\outputs\bench_${stamp}_warmup_$i.json"
    $tmpPcap = ".\outputs\bench_${stamp}_warmup_$i.pcap"
    Write-Host "[Warmup $i/$Warmup] running..."
    [void](Run-One -JavaCp $javaCp -InputPath $InputPcap -OutPcap $tmpPcap -OutJson $tmpJson -LbCount $Lbs -FpCount $Fps -RuleArgs $ruleTokens)
}

for ($i = 1; $i -le $Runs; $i++) {
    $tmpJson = ".\outputs\bench_${stamp}_run_$i.json"
    $tmpPcap = ".\outputs\bench_${stamp}_run_$i.pcap"
    Write-Host "[Run $i/$Runs] running..."
    $obj = Run-One -JavaCp $javaCp -InputPath $InputPcap -OutPcap $tmpPcap -OutJson $tmpJson -LbCount $Lbs -FpCount $Fps -RuleArgs $ruleTokens
    $samples.Add([pscustomobject]@{
        run = $i
        packets = [double]$obj.stats.total_packets
        bytes = [double]$obj.stats.total_bytes
        sec = [double]$obj.performance.processing_time_sec
        pps = [double]$obj.performance.packets_per_second
        gbps = ([double]$obj.performance.throughput_bps) / 1e9
        avg_us = [double]$obj.performance.avg_latency_us
        p95_us = [double]$obj.performance.p95_latency_us
        cpu = [double]$obj.performance.avg_cpu_usage_percent
        mem_peak = [double]$obj.performance.peak_memory_mb
    })
}

$avgPps = Avg ($samples | ForEach-Object { $_.pps })
$avgGbps = Avg ($samples | ForEach-Object { $_.gbps })
$avgLat = Avg ($samples | ForEach-Object { $_.avg_us })
$avgP95 = Avg ($samples | ForEach-Object { $_.p95_us })
$avgCpu = Avg ($samples | ForEach-Object { $_.cpu })
$avgMem = Avg ($samples | ForEach-Object { $_.mem_peak })

$summary = [pscustomobject]@{
    generated_at = (Get-Date).ToString("o")
    input_pcap = $InputPcap
    warmup_runs = $Warmup
    measured_runs = $Runs
    lbs = $Lbs
    fps_per_lb = $Fps
    total_workers = ($Lbs * $Fps)
    with_rules = ($ruleTokens.Count -gt 0)
    execution_mode = "direct_java"
    average = [pscustomobject]@{
        packets_per_second = [math]::Round($avgPps, 2)
        throughput_gbps = [math]::Round($avgGbps, 4)
        avg_latency_us = [math]::Round($avgLat, 2)
        p95_latency_us = [math]::Round($avgP95, 2)
        avg_cpu_percent = [math]::Round($avgCpu, 2)
        peak_memory_mb = [math]::Round($avgMem, 2)
    }
    runs = $samples
}

$summaryJson = ".\outputs\benchmark_summary_$stamp.json"
$summaryCsv = ".\outputs\benchmark_summary_$stamp.csv"

$summary | ConvertTo-Json -Depth 6 | Set-Content -Path (Join-Path $projectRoot $summaryJson) -Encoding UTF8
$samples | Export-Csv -Path (Join-Path $projectRoot $summaryCsv) -NoTypeInformation -Encoding UTF8

Write-Host ""
Write-Host "================ PERFORMANCE SUMMARY (AVERAGE) ================"
Write-Host ""
Write-Host ("Packets Per Second : {0:N2} pps" -f $avgPps)
Write-Host ("Throughput         : {0:N4} Gbps" -f $avgGbps)
Write-Host ("Avg Latency        : {0:N2} us" -f $avgLat)
Write-Host ("P95 Latency        : {0:N2} us" -f $avgP95)
Write-Host ("Avg CPU            : {0:N2} %" -f $avgCpu)
Write-Host ("Peak Memory        : {0:N2} MB" -f $avgMem)
Write-Host ""
Write-Host "Per-run CSV  : $summaryCsv"
Write-Host "Summary JSON : $summaryJson"
Write-Host "=============================================================="
