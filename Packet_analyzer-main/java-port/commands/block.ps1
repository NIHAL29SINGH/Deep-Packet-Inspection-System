param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Args
)

$noBench = $false
$enableMetrics = $false
$ruleArgs = @()

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

    $ruleArgs += $arg
}

$callArgs = @("-Mode", "block")
if ($noBench -or $enableMetrics) { $callArgs += "-NoBench" }
if ($enableMetrics) {
    & "$PSScriptRoot\monitor.cmd" up | Out-Null
    Start-Process "http://localhost:3001/d/dpi-engine-overview/dpi-live-metrics-report" | Out-Null
    $callArgs += @("-Monitor", "-MetricsHold", "120")
}
if ($ruleArgs.Count -gt 0) {
    $callArgs += "-ExtraRules"
    $callArgs += $ruleArgs
}

& powershell -ExecutionPolicy Bypass -File "$PSScriptRoot\dpi.ps1" @callArgs
