param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Args
)

$inputPcap = $null
$extraArgs = @()
$noBench = $false
$enableMetrics = $false

foreach ($arg in $Args) {
    if ([string]::IsNullOrWhiteSpace($arg)) {
        continue
    }

    if ([string]::Equals($arg, "metrics", [System.StringComparison]::OrdinalIgnoreCase) -or
        [string]::Equals($arg, "metrices", [System.StringComparison]::OrdinalIgnoreCase) -or
        [string]::Equals($arg, "-metrics", [System.StringComparison]::OrdinalIgnoreCase) -or
        [string]::Equals($arg, "-metrices", [System.StringComparison]::OrdinalIgnoreCase)) {
        $enableMetrics = $true
        continue
    }

    if ([string]::Equals($arg, "-nobench", [System.StringComparison]::OrdinalIgnoreCase) -or
        [string]::Equals($arg, "nobench", [System.StringComparison]::OrdinalIgnoreCase)) {
        $noBench = $true
        continue
    }

    if ($null -eq $inputPcap -and $arg.ToLowerInvariant().EndsWith(".pcap")) {
        $inputPcap = $arg
        continue
    }

    $extraArgs += $arg
}

$callArgs = @("-Mode", "normal")
if ($inputPcap) { $callArgs += @("-InputPcap", $inputPcap) }
if ($noBench -or $enableMetrics) { $callArgs += "-NoBench" }
if ($enableMetrics) {
    & "$PSScriptRoot\monitor.cmd" up | Out-Null
    Start-Process "http://localhost:3001/d/dpi-engine-overview/dpi-live-metrics-report" | Out-Null
    $callArgs += @("-Monitor", "-MetricsHold", "120")
}
$callArgs += $extraArgs

& powershell -ExecutionPolicy Bypass -File "$PSScriptRoot\dpi.ps1" @callArgs
