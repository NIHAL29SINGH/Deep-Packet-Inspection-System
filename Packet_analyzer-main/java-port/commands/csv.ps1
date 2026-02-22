param(
    [Parameter(Position=0)]
    [string]$ReportCsv = ".\outputs\report.csv",

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

# Accept common typo ".output\..." and normalize it.
if ($ReportCsv -match '^[.]output\\') {
    $ReportCsv = $ReportCsv -replace '^[.]output\\', '.\outputs\'
}

# If first arg looks like a pcap path, treat it as input and auto-name CSV.
$ext = [System.IO.Path]::GetExtension($ReportCsv)
if ($ext -and $ext.Equals(".pcap", [System.StringComparison]::OrdinalIgnoreCase)) {
    if ([string]::IsNullOrWhiteSpace($InputPcap)) {
        $InputPcap = $ReportCsv
    }
    $stemFromPcap = [System.IO.Path]::GetFileNameWithoutExtension($ReportCsv)
    $ReportCsv = ".\outputs\$stemFromPcap.csv"
}

# If no extension was given, assume .csv.
if ([string]::IsNullOrWhiteSpace([System.IO.Path]::GetExtension($ReportCsv))) {
    $ReportCsv = "$ReportCsv.csv"
}

$reportDir = [System.IO.Path]::GetDirectoryName($ReportCsv)
if ([string]::IsNullOrWhiteSpace($reportDir)) {
    $ReportCsv = ".\outputs\$ReportCsv"
}

if ([string]::IsNullOrWhiteSpace($InputPcap)) {
    $baseName = [System.IO.Path]::GetFileNameWithoutExtension($ReportCsv)
    $candidateRel = ".\outputs\$baseName.pcap"
    $candidateAbs = Join-Path $projectRoot $candidateRel
    if (Test-Path $candidateAbs) {
        $InputPcap = $candidateRel
    } else {
        $InputPcap = "..\quick_test_mixed_20mb.pcap"
    }
}

function Test-IsPcapFile {
    param([string]$PathToCheck)
    try {
        if (-not (Test-Path $PathToCheck)) { return $false }
        $bytes = [System.IO.File]::ReadAllBytes($PathToCheck)
        if ($bytes.Length -lt 4) { return $false }
        $magic = '{0:X2}{1:X2}{2:X2}{3:X2}' -f $bytes[0],$bytes[1],$bytes[2],$bytes[3]
        return $magic -in @('A1B2C3D4','D4C3B2A1','A1B23C4D','4D3CB2A1')
    } catch {
        return $false
    }
}

$inputAbs = Join-Path $projectRoot $InputPcap
if (-not (Test-IsPcapFile $inputAbs)) {
    Write-Error "Input is not a valid PCAP: $InputPcap"
    Write-Host "Tip: run .\block.cmd first to regenerate .\outputs\output_blocked.pcap"
    exit 1
}

& "$PSScriptRoot\dpi.ps1" csv -InputPcap $InputPcap -ReportCsv $ReportCsv -NoBench:$NoBench -Monitor:$Monitor

if ($LASTEXITCODE -eq 0) {
    $csvAbs = Join-Path $projectRoot $ReportCsv
    if (Test-Path $csvAbs) {
        Start-Process $csvAbs
    }
}
