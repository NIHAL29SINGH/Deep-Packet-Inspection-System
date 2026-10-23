#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -P "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$SCRIPT_DIR"

say() { printf '%s\n' "$*"; }
warn() { printf 'Warning: %s\n' "$*" >&2; }

check_cmd() {
  local cmd="$1"
  local install_hint="$2"
  if command -v "$cmd" >/dev/null 2>&1; then
    say "[ok] $cmd: $(command -v "$cmd")"
  else
    warn "Missing $cmd. Install with: $install_hint"
  fi
}

say "== Deep Packet Inspection (macOS) prerequisite check =="
uname -a

if command -v brew >/dev/null 2>&1; then
  say "[ok] Homebrew: $(brew --prefix)"
else
  warn "Homebrew not found. Install from https://brew.sh/"
fi

check_cmd java "brew install openjdk@21"
check_cmd mvn "brew install maven"
check_cmd python3 "brew install python"

if command -v docker >/dev/null 2>&1; then
  if docker info >/dev/null 2>&1; then
    say "[ok] Docker daemon is running"
  else
    warn "Docker is installed but not running. Start Docker Desktop if you need monitoring."
  fi
else
  warn "Docker not found (optional). Install Docker Desktop for metrics monitoring."
fi

say ""
say "Apple Silicon notes:"
say "- Homebrew default prefix is /opt/homebrew"
say "- If Java is not detected after install, run:"
say "    export PATH=\"/opt/homebrew/opt/openjdk@21/bin:$PATH\""
say ""
say "Intel Mac notes:"
say "- Homebrew default prefix is /usr/local"
say ""
say "libpcap/live capture notes:"
say "- macOS includes libpcap, but live capture often needs elevated privileges."
say "- List interfaces with: ./ifaces.sh"
say "- Live capture example: sudo ./live.sh 20 en0"
say ""
say "Project directory: $PROJECT_DIR"
