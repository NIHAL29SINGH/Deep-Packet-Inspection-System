#!/usr/bin/env bash
set -euo pipefail

SCRIPT_PATH="${BASH_SOURCE[0]}"
while [ -h "$SCRIPT_PATH" ]; do
  SCRIPT_DIR="$(cd -P "$(dirname "$SCRIPT_PATH")" && pwd)"
  SCRIPT_PATH="$(readlink "$SCRIPT_PATH")"
  [[ "$SCRIPT_PATH" != /* ]] && SCRIPT_PATH="$SCRIPT_DIR/$SCRIPT_PATH"
done
SCRIPT_DIR="$(cd -P "$(dirname "$SCRIPT_PATH")" && pwd)"
PROJECT_DIR="$SCRIPT_DIR"
REPO_DIR="$(cd "$PROJECT_DIR/.." && pwd)"
OUTPUT_DIR="$PROJECT_DIR/outputs"
MONITORING_DIR="$PROJECT_DIR/monitoring"
SAMPLE_PCAP="$REPO_DIR/quick_test_mixed_20mb.pcap"

mkdir -p "$OUTPUT_DIR"
cd "$PROJECT_DIR"

err() {
  printf 'Error: %s\n' "$*" >&2
}

require_cmd() {
  local cmd="$1"
  local help_text="$2"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    err "Missing required command '$cmd'. $help_text"
    exit 1
  fi
}

require_java17() {
  require_cmd java "Install Java 17+ (e.g. 'brew install openjdk@21')."
  local version major
  version="$(java -version 2>&1 | awk -F '"' '/version/ {print $2; exit}')"
  major="$(printf '%s' "$version" | awk -F. '{if ($1 == "1") print $2; else print $1}')"
  if [ -z "$major" ] || ! [ "$major" -ge 17 ] 2>/dev/null; then
    err "Java 17+ is required. Found: ${version:-unknown}."
    exit 1
  fi
}

require_maven() {
  require_cmd mvn "Install Maven (e.g. 'brew install maven')."
}

require_python() {
  if command -v python3 >/dev/null 2>&1; then
    return
  fi
  err "Missing Python 3. Install with Homebrew: 'brew install python'."
  exit 1
}

require_java_toolchain() {
  require_java17
  require_maven
}

require_docker() {
  require_cmd docker "Install Docker Desktop for Mac from https://www.docker.com/products/docker-desktop/."
  if ! docker info >/dev/null 2>&1; then
    err "Docker daemon is not running. Start Docker Desktop and retry."
    exit 1
  fi
}

print_monitor_links() {
  printf 'Prometheus: http://localhost:9090\n'
  printf 'Grafana   : http://localhost:3001 (admin/admin)\n'
}

maybe_open_links() {
  if command -v open >/dev/null 2>&1; then
    open "http://localhost:9090" >/dev/null 2>&1 || true
    open "http://localhost:3001" >/dev/null 2>&1 || true
  elif command -v xdg-open >/dev/null 2>&1; then
    xdg-open "http://localhost:9090" >/dev/null 2>&1 || true
    xdg-open "http://localhost:3001" >/dev/null 2>&1 || true
  else
    print_monitor_links
  fi
}

docker_compose_action() {
  local action="$1"
  require_docker
  if [ ! -d "$MONITORING_DIR" ]; then
    err "Monitoring directory not found: $MONITORING_DIR"
    exit 1
  fi
  (
    cd "$MONITORING_DIR"
    case "$action" in
      up) docker compose up -d ;;
      down) docker compose down ;;
      restart) docker compose down && docker compose up -d ;;
      logs) docker compose logs -f ;;
      status) docker compose ps ;;
      *) err "Unknown monitor action: $action"; exit 1 ;;
    esac
  )
}

ensure_runtime_cp() {
  require_java_toolchain
  mvn -q -DskipTests compile
  mvn -q dependency:build-classpath "-Dmdep.outputFile=target/classpath.txt"

  if [ ! -f "$PROJECT_DIR/target/classpath.txt" ]; then
    err "Failed to generate target/classpath.txt"
    exit 1
  fi

  local dep_cp
  dep_cp="$(tr -d '\r\n' < "$PROJECT_DIR/target/classpath.txt")"
  JAVA_CP="$PROJECT_DIR/target/classes"
  if [ -n "$dep_cp" ]; then
    JAVA_CP="$JAVA_CP:$dep_cp"
  fi
}

run_dpi() {
  ensure_runtime_cp
  java -cp "$JAVA_CP" com.deeppacket.app.DpiMain "$@"
}

metrics_requested=0
clean_args=()

extract_metrics_token() {
  metrics_requested=0
  clean_args=()
  local arg
  for arg in "$@"; do
    case "$arg" in
      metrics|metrices|-metrics|-metrices) metrics_requested=1 ;;
      *) clean_args+=("$arg") ;;
    esac
  done
}

to_block_rule_args() {
  local token rule kind value
  local -a converted=()

  for token in "$@"; do
    IFS=',' read -r -a _parts <<<"$token"
    for rule in "${_parts[@]}"; do
      rule="${rule## }"
      rule="${rule%% }"
      [ -z "$rule" ] && continue
      if [[ "$rule" == app:* ]]; then
        converted+=("--block-app" "${rule#app:}")
      elif [[ "$rule" == ip:* ]]; then
        converted+=("--block-ip" "${rule#ip:}")
      elif [[ "$rule" == domain:* ]]; then
        converted+=("--block-domain" "${rule#domain:}")
      elif [[ "$rule" == --* ]]; then
        converted+=("$rule")
      else
        converted+=("--block-domain" "$rule")
      fi
    done
  done

  printf '%s\n' "${converted[@]}"
}

show_usage() {
  cat <<USAGE
Usage: ./dpi.sh <command> [arguments]

Commands:
  check                       Validate Java/Maven/Python and Docker(optional)
  build                       mvn clean package
  ifaces                      List capture interfaces (Pcap4J)
  normal [input.pcap] [opts]  Offline DPI run (default sample pcap)
  block [rules] [opts]        Offline run with blocking rules
  live [duration] [iface] [opts]
                              Live capture + DPI. Use './ifaces.sh' first.
  report [stem] [input.pcap] [opts]
                              Write CSV/JSON reports in outputs/
  monitor <up|down|restart|status|logs>
  metrics <start|stop|status|logs|links|open|run|runblock> [arg]
  generate [output.pcap]      Generate synthetic pcap via Python script

Tips:
  - Add 'metrics' token at end of normal/block/live/report commands to auto-start monitoring.
  - Pass extra DpiMain flags after the command (example: --no-metrics, --lbs 2 --fps 2).
USAGE
}

command="${1:-help}"
if [ "$#" -gt 0 ]; then
  shift
fi

case "$command" in
  help|-h|--help)
    show_usage
    ;;

  check)
    require_java17
    require_maven
    require_python
    if command -v docker >/dev/null 2>&1; then
      if docker info >/dev/null 2>&1; then
        printf 'Docker: available and running.\n'
      else
        printf 'Docker: installed but daemon not running (optional for monitoring).\n'
      fi
    else
      printf 'Docker: not installed (optional for monitoring).\n'
    fi
    java -version
    mvn -version
    python3 --version
    ;;

  build)
    require_java_toolchain
    mvn clean package
    ;;

  ifaces)
    run_dpi --list-ifaces
    ;;

  normal)
    extract_metrics_token "$@"
    input="$SAMPLE_PCAP"
    output="$OUTPUT_DIR/output_normal.pcap"
    if [ "${#clean_args[@]}" -gt 0 ] && [[ "${clean_args[0]}" == *.pcap ]]; then
      input="${clean_args[0]}"
      clean_args=("${clean_args[@]:1}")
    fi

    extra=("${clean_args[@]}")
    if [ "$metrics_requested" -eq 1 ]; then
      docker_compose_action up >/dev/null
      print_monitor_links
      extra+=("--report-csv" "$OUTPUT_DIR/monitor_normal.csv" "--report-json" "$OUTPUT_DIR/monitor_normal.json" "--metrics-hold" "120")
    fi
    run_dpi "$input" "$output" "${extra[@]}"
    ;;

  block)
    extract_metrics_token "$@"
    input="$SAMPLE_PCAP"
    output="$OUTPUT_DIR/output_blocked.pcap"

    if [ "${#clean_args[@]}" -gt 0 ] && [[ "${clean_args[0]}" == *.pcap ]]; then
      input="${clean_args[0]}"
      clean_args=("${clean_args[@]:1}")
    fi

    extra=("${clean_args[@]}")
    has_block_flag=0
    for a in "${extra[@]}"; do
      case "$a" in
        --block-ip|--block-app|--block-domain) has_block_flag=1 ;;
      esac
    done
    if [ "$has_block_flag" -eq 0 ] && [ "${#extra[@]}" -gt 0 ] && [[ "${extra[0]}" != --* ]]; then
      converted_rules=()
      while IFS= read -r line; do
        [ -n "$line" ] && converted_rules+=("$line")
      done < <(to_block_rule_args "${extra[@]}")
      extra=("${converted_rules[@]}" "--verbose")
    elif [ "$has_block_flag" -eq 0 ] && [ "${#extra[@]}" -eq 0 ]; then
      extra=("--block-app" "YouTube" "--block-domain" "facebook" "--verbose")
    fi

    if [ "$metrics_requested" -eq 1 ]; then
      docker_compose_action up >/dev/null
      print_monitor_links
      extra+=("--report-csv" "$OUTPUT_DIR/monitor_block.csv" "--report-json" "$OUTPUT_DIR/monitor_block.json" "--metrics-hold" "120")
    fi

    run_dpi "$input" "$output" "${extra[@]}"
    ;;

  live)
    extract_metrics_token "$@"
    duration="30"
    iface=""
    output="$OUTPUT_DIR/output_live_filtered.pcap"
    capture_out="$OUTPUT_DIR/live_input.pcap"

    if [ "${#clean_args[@]}" -gt 0 ] && [[ "${clean_args[0]}" =~ ^[0-9]+$ ]]; then
      duration="${clean_args[0]}"
      clean_args=("${clean_args[@]:1}")
    fi

    if [ "${#clean_args[@]}" -gt 0 ] && [[ "${clean_args[0]}" != --* ]]; then
      iface="${clean_args[0]}"
      clean_args=("${clean_args[@]:1}")
    fi

    extra=("${clean_args[@]}")
    if [ "$metrics_requested" -eq 1 ]; then
      docker_compose_action up >/dev/null
      print_monitor_links
      extra+=("--report-csv" "$OUTPUT_DIR/monitor_live.csv" "--report-json" "$OUTPUT_DIR/monitor_live.json" "--metrics-hold" "120")
    fi

    live_args=("--live" "$output" "--duration" "$duration" "--capture-out" "$capture_out" "--verbose")
    if [ -n "$iface" ]; then
      live_args+=("--iface" "$iface")
    fi

    run_dpi "${live_args[@]}" "${extra[@]}"
    ;;

  report)
    extract_metrics_token "$@"
    stem="report"
    input="$SAMPLE_PCAP"

    if [ "${#clean_args[@]}" -gt 0 ] && [[ "${clean_args[0]}" != --* ]] && [[ "${clean_args[0]}" != *.pcap ]]; then
      stem="${clean_args[0]}"
      clean_args=("${clean_args[@]:1}")
    fi
    if [ "${#clean_args[@]}" -gt 0 ] && [[ "${clean_args[0]}" == *.pcap ]]; then
      input="${clean_args[0]}"
      clean_args=("${clean_args[@]:1}")
    fi

    stem="$(basename "$stem")"
    stem="${stem%.*}"
    [ -z "$stem" ] && stem="report"

    output="$OUTPUT_DIR/output_${stem}.pcap"
    csv="$OUTPUT_DIR/${stem}.csv"
    json="$OUTPUT_DIR/${stem}.json"
    extra=("${clean_args[@]}")

    if [ "$metrics_requested" -eq 1 ]; then
      docker_compose_action up >/dev/null
      print_monitor_links
      extra+=("--metrics-hold" "120")
    fi

    run_dpi "$input" "$output" "--report-csv" "$csv" "--report-json" "$json" "--verbose" "${extra[@]}"
    ;;

  monitor)
    action="${1:-status}"
    docker_compose_action "$action"
    ;;

  metrics)
    action="${1:-run}"
    case "$action" in
      start)
        docker_compose_action up
        print_monitor_links
        ;;
      stop)
        docker_compose_action down
        ;;
      status)
        docker_compose_action status
        print_monitor_links
        ;;
      logs)
        docker_compose_action logs
        ;;
      links)
        print_monitor_links
        ;;
      open)
        maybe_open_links
        ;;
      run)
        shift || true
        "$0" normal "$@" metrics
        ;;
      runblock)
        shift || true
        if [ "$#" -eq 0 ]; then
          "$0" block "youtube,facebook" metrics
        else
          "$0" block "$@" metrics
        fi
        ;;
      *)
        err "Unknown metrics action: $action"
        exit 1
        ;;
    esac
    ;;

  generate)
    require_python
    out_file="${1:-$REPO_DIR/generated_test.pcap}"
    python3 "$REPO_DIR/generate_test_pcap.py" "$out_file"
    printf 'Generated test pcap: %s\n' "$out_file"
    ;;

  *)
    err "Unknown command: $command"
    show_usage
    exit 1
    ;;
esac
