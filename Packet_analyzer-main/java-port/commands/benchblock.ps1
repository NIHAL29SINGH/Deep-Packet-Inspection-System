param(
    [Parameter(Position=0)]
    [string]$Domains = "youtube,facebook,google",

    [Parameter(Position=1)]
    [string]$InputPcap = "..\quick_test_mixed_20mb.pcap"
)

# Simple blocking benchmark:
# - default domains unless user provides their own
# - 5 measured runs
# - 1 warmup
# - 2 load balancers
# - 2 fast-path workers per LB
& "$PSScriptRoot\bench.ps1" $InputPcap 1 1 2 2 $Domains
