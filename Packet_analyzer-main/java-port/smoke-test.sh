#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -P "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$SCRIPT_DIR"
REPO_DIR="$(cd "$PROJECT_DIR/.." && pwd)"

cd "$PROJECT_DIR"

scripts=(dpi.sh build.sh normal.sh block.sh live.sh ifaces.sh metrics.sh report.sh monitor.sh setup-macos.sh)
for script in "${scripts[@]}"; do
  bash -n "$PROJECT_DIR/$script"
done

echo "[smoke] Shell syntax checks passed"
"$PROJECT_DIR/build.sh"
"$PROJECT_DIR/dpi.sh" normal "$REPO_DIR/quick_test_mixed_20mb.pcap" --no-metrics --verbose

echo "[smoke] Offline DPI smoke test passed"
