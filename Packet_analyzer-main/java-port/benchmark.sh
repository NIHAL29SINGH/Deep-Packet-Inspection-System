#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -P "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SAMPLE="${1:-$SCRIPT_DIR/../sample_traffic.pcap}"
OUT="${2:-$SCRIPT_DIR/outputs/benchmark.csv}"
mkdir -p "$(dirname "$OUT")"
printf 'workers,elapsed_seconds,packets_per_second,peak_memory_kb\n' > "$OUT"

for workers in 1 2 4 8; do
  log="$(mktemp)"
  run_log="$(mktemp)"
  start="$(date +%s%N)"
  if command -v /usr/bin/time >/dev/null 2>&1; then
    /usr/bin/time -f '%M' -o "$log" "$SCRIPT_DIR/dpi.sh" normal "$SAMPLE" \
      --lbs "$workers" --fps 1 --no-metrics >"$run_log"
  else
    "$SCRIPT_DIR/dpi.sh" normal "$SAMPLE" --lbs "$workers" --fps 1 --no-metrics >"$run_log"
    printf 'unknown' > "$log"
  fi
  end="$(date +%s%N)"
  elapsed_ns=$((end - start))
  elapsed="$(awk -v n="$elapsed_ns" 'BEGIN { printf "%.6f", n / 1000000000 }')"
  packets="$(awk -F: '/Total Packets/ {gsub(/ /, "", $2); print $2; exit}' "$run_log")"
  pps="$(awk -v n="${packets:-0}" -v t="$elapsed" 'BEGIN { printf "%.2f", n / t }')"
  memory="$(cat "$log")"
  printf '%s,%s,%s,%s\n' "$workers" "$elapsed" "$pps" "$memory" >> "$OUT"
  rm -f "$log" "$run_log"
done
echo "Benchmark written to $OUT"
