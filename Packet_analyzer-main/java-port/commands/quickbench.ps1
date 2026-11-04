param(
    [Parameter(Position=0)]
    [string]$InputPcap = "..\sample_traffic.pcap"
)

# Simple baseline benchmark:
# - 5 measured runs
# - 1 warmup
# - 2 load balancers
# - 2 fast-path workers per LB
& "$PSScriptRoot\bench.ps1" $InputPcap 1 1 2 2
