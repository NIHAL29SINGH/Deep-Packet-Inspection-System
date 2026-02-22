param(
    [Parameter(Position=0)]
    [string]$BaseName = "report",

    [Parameter(Position=1)]
    [string]$InputPcap = "",

    [switch]$NoBench,
    [switch]$Monitor
)

$projectRoot = Split-Path $PSScriptRoot -Parent
$outputDir = Join-Path $projectRoot "outputs"
if (-not (Test-Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir | Out-Null
}

if ([string]::IsNullOrWhiteSpace($BaseName)) {
    $BaseName = "report"
}

$stem = [System.IO.Path]::GetFileNameWithoutExtension($BaseName)
if ([string]::IsNullOrWhiteSpace($stem)) {
    $stem = "report"
}

$reportCsv = ".\outputs\$stem.csv"
$reportJson = ".\outputs\$stem.json"
$outputPcap = ".\outputs\output_$stem.pcap"

if ([string]::IsNullOrWhiteSpace($InputPcap)) {
    $candidateRel = ".\outputs\$stem.pcap"
    $candidateAbs = Join-Path $projectRoot $candidateRel
    if (Test-Path $candidateAbs) {
        $InputPcap = $candidateRel
    } else {
        $InputPcap = "..\quick_test_mixed_20mb.pcap"
    }
}

& "$PSScriptRoot\dpi.ps1" report -InputPcap $InputPcap -OutputPcap $outputPcap -ReportCsv $reportCsv -ReportJson $reportJson -NoBench:$NoBench -Monitor:$Monitor @args

if ($LASTEXITCODE -eq 0) {
    $csvAbs = Join-Path $projectRoot $reportCsv
    $jsonAbs = Join-Path $projectRoot $reportJson
    if (Test-Path $csvAbs) { Start-Process $csvAbs }
    if (Test-Path $jsonAbs) { Start-Process $jsonAbs }
}
