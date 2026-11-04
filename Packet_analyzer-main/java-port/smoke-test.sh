#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -P "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$SCRIPT_DIR"
REPO_DIR="$(cd "$PROJECT_DIR/.." && pwd)"

cd "$PROJECT_DIR"

scripts=(dpi.sh build.sh normal.sh block.sh metrics.sh report.sh monitor.sh setup-macos.sh)
for script in "${scripts[@]}"; do
  bash -n "$PROJECT_DIR/$script"
done

echo "[smoke] Shell syntax checks passed"
"$PROJECT_DIR/build.sh"
report="$(mktemp)"
trap 'rm -f "$report"' EXIT
"$PROJECT_DIR/dpi.sh" normal "$REPO_DIR/sample_traffic.pcap" --no-metrics | tee "$report"

# Assert on real results, not just "it ran": the deterministic sample must be fully classified.
expect() {
  if ! grep -Eq "$1" "$report"; then
    echo "[smoke] FAILED: expected output matching: $1" >&2
    exit 1
  fi
}
expect 'PROCESSING REPORT'
expect 'Total Packets +: [1-9][0-9]{3,}'
expect 'Netflix +[0-9]+'      # not mislabelled as Twitter (substring-matching regression)
expect 'QUIC|YouTube +[0-9]+' # QUIC Initial packets were decrypted
expect 'Not inspected +: 4'   # IPv6, ICMP, IPv4 fragment, truncated frame are counted, not hidden

# Second run: the JSON report must carry the advanced-analysis results from the same deterministic sample.
json="$(mktemp)"
csv="$(mktemp)"
trap 'rm -f "$report" "$json" "$csv"' EXIT
"$PROJECT_DIR/dpi.sh" normal "$REPO_DIR/sample_traffic.pcap" --no-metrics --report-json "$json" --report-csv "$csv" >/dev/null
expect_json() {
  if ! grep -Eq "$1" "$json"; then
    echo "[smoke] FAILED: JSON report missing: $1" >&2
    exit 1
  fi
}
expect_json '"ja3": "[0-9a-f]{32}"'                    # TLS clients are fingerprinted
expect_json '"tls_version": "TLS 1.0"'                  # the legacy client is detected
expect_json '"dns_name": "stealth.example.org"'         # a no-SNI flow is tied to its DNS answer
expect_json 'possible DNS tunnelling'                   # the tunnelling burst is flagged
# The JSON lists only the highest-risk flows; the CSV has every flow, so QUIC decryption is checked there.
if ! grep -q ',QUIC Initial,' "$csv"; then
  echo "[smoke] FAILED: no flow was classified from a QUIC Initial packet" >&2
  exit 1
fi

# The HTML report is one inline script; a single syntax slip renders a blank page and no Java test can see it.
html="$(mktemp)"
trap 'rm -f "$report" "$json" "$csv" "$html" "$html.js"' EXIT
"$PROJECT_DIR/dpi.sh" normal "$REPO_DIR/sample_traffic.pcap" --no-metrics --report-html "$html" >/dev/null
python3 - "$html" <<'PY'
import re, sys
text = open(sys.argv[1], encoding="utf-8").read()
scripts = re.findall(r"<script>(.*?)</script>", text, re.S)
if not scripts:
    sys.exit("[smoke] FAILED: no inline script found in the HTML report")
open(sys.argv[1] + ".js", "w", encoding="utf-8").write(scripts[-1])
PY
if command -v node >/dev/null 2>&1; then
  node --check "$html.js" || { echo "[smoke] FAILED: the HTML report's script has a syntax error" >&2; exit 1; }
else
  echo "[smoke] node not found; skipping the HTML script syntax check"
fi

echo "[smoke] Offline DPI smoke test passed"
