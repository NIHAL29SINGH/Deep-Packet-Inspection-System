# Command Reference (code-verified)

All commands below are based on current implementation in:

- `Packet_analyzer-main/java-port/dpi.sh`
- `Packet_analyzer-main/java-port/src/main/java/com/deeppacket/app/DpiMain.java`

Run wrapper commands from:

```bash
cd /path/to/Deep-Packet-Inspection-System/Packet_analyzer-main/java-port
```

## `dpi.sh` commands

## `check`

```bash
./dpi.sh check
```

Checks:

- Java 17+
- Maven
- Python 3
- Docker status (optional)

---

## `build`

```bash
./dpi.sh build
```

Runs `mvn clean package`.

---

## `ifaces`

```bash
./dpi.sh ifaces
```

Lists interfaces from Pcap4J (`--list-ifaces` in Java).

---

## `normal [input.pcap] [opts]`

Default input if omitted: `../quick_test_mixed_20mb.pcap`.

Default output: `outputs/output_normal.pcap`.

Examples:

```bash
./dpi.sh normal --no-metrics
./dpi.sh normal ../quick_test_mixed_20mb.pcap --no-metrics --verbose
./dpi.sh normal ../quick_test_mixed_20mb.pcap --lbs 4 --fps 2 --report-json outputs/normal.json
```

---

## `block [rules] [opts]`

Default input if omitted: `../quick_test_mixed_20mb.pcap`.

Default output: `outputs/output_blocked.pcap`.

If no blocking flags or rule tokens are provided, wrapper defaults to:

- `--block-app YouTube`
- `--block-domain facebook`
- `--verbose`

Rules shorthand supported by wrapper:

- `youtube,facebook` (treated as domain rules)
- `app:YouTube,domain:facebook,ip:192.168.1.50`

Examples:

```bash
./dpi.sh block --block-app YouTube --block-domain facebook --no-metrics
./dpi.sh block youtube,facebook --no-metrics
./dpi.sh block app:YouTube,domain:facebook,ip:192.168.1.50 --no-metrics
./dpi.sh block ../quick_test_mixed_20mb.pcap --block-ip 192.168.1.50 --verbose
```

---

## `live [duration] [iface] [opts]`

Wrapper defaults:

- duration: `30`
- capture input file: `outputs/live_input.pcap`
- filtered output file: `outputs/output_live_filtered.pcap`
- always includes `--verbose`

Examples:

```bash
./dpi.sh live
sudo ./dpi.sh live 20 en0 --no-metrics
sudo ./dpi.sh live 30 en0 --bpf "tcp port 443" --metrics-port 9500
```

---

## `report [stem] [input.pcap] [opts]`

Defaults:

- stem: `report`
- input: `../quick_test_mixed_20mb.pcap`
- output pcap: `outputs/output_<stem>.pcap`
- csv: `outputs/<stem>.csv`
- json: `outputs/<stem>.json`
- wrapper adds `--verbose`

Examples:

```bash
./dpi.sh report
./dpi.sh report traffic --no-metrics
./dpi.sh report traffic ../quick_test_mixed_20mb.pcap --no-metrics --metrics-port 9500
```

---

## `monitor <up|down|restart|status|logs>`

```bash
./dpi.sh monitor up
./dpi.sh monitor status
./dpi.sh monitor logs
./dpi.sh monitor down
```

Uses Docker Compose in `java-port/monitoring/`.

---

## `metrics <start|stop|status|logs|links|open|run|runblock> [arg]`

Examples:

```bash
./dpi.sh metrics start
./dpi.sh metrics links
./dpi.sh metrics run
./dpi.sh metrics runblock
./dpi.sh metrics runblock youtube,facebook
./dpi.sh metrics stop
```

Behavior:

- `run` delegates to `normal ... metrics`
- `runblock` delegates to `block ... metrics` (default rules `youtube,facebook` if none provided)

---

## `generate [output.pcap]`

```bash
./dpi.sh generate
./dpi.sh generate /tmp/custom.pcap
```

Wrapper passes argument to `generate_test_pcap.py` and prints `Generated test pcap: ...`.

Current generator implementation writes `test_dpi.pcap` internally, so verify the actual created file when using a custom output argument.

---

## Help

```bash
./dpi.sh help
./dpi.sh --help
```

---

## Metrics token on workflow commands

For `normal`, `block`, `live`, `report`, appending token `metrics` auto-starts monitoring and adds scrape hold options.

Accepted tokens in wrapper:

- `metrics`
- `metrices`
- `-metrics`
- `-metrices`

Example:

```bash
./dpi.sh normal metrics
./dpi.sh block youtube,facebook metrics
```

## Direct Java CLI (`DpiMain`)

Compile/runtime helper:

```bash
mvn -q -DskipTests compile
mvn -q dependency:build-classpath -Dmdep.outputFile=target/classpath.txt
```

Help:

```bash
java -cp "target/classes:$(cat target/classpath.txt)" com.deeppacket.app.DpiMain --help
```

### Modes

- PCAP mode: `<input.pcap> <output.pcap> [options]`
- Live mode: `--live <output.pcap> [options]`

### Options

- Blocking: `--block-ip`, `--block-app`, `--block-domain`
- Rules file: `--rules <file>`, `--save-rules <file>`
- Reports: `--report-csv <file>`, `--report-json <file>`
- Threads: `--lbs <n>`, `--fps <n>`
- Live: `--iface <name>`, `--duration <sec>`, `--capture-out <file>`, `--bpf <filter>`, `--list-ifaces`
- Metrics: `--no-metrics`, `--metrics-bind <addr>`, `--metrics-port <port>`, `--metrics-hold <sec>`, `--metrics-file <file>`
- Utility: `--verbose`, `--help`, `-h`

### Java defaults (without wrapper)

- live duration: `15`
- live capture file: `./outputs/live_capture_input.pcap`
- BPF: `ip and tcp or ip and udp`
- metrics enabled: yes
- metrics bind/port: `0.0.0.0:9400`
- metrics file: `./outputs/prometheus_metrics.prom`

### Examples

PCAP mode:

```bash
java -cp "target/classes:$(cat target/classpath.txt)" \
  com.deeppacket.app.DpiMain \
  ../quick_test_mixed_20mb.pcap \
  ./outputs/direct_output.pcap \
  --block-domain facebook \
  --report-csv ./outputs/direct.csv \
  --report-json ./outputs/direct.json \
  --metrics-port 9500
```

Live mode:

```bash
sudo java -cp "target/classes:$(cat target/classpath.txt)" \
  com.deeppacket.app.DpiMain \
  --live ./outputs/output_live_filtered.pcap \
  --iface en0 \
  --duration 20 \
  --capture-out ./outputs/live_input.pcap \
  --bpf "tcp or udp"
```
