# Deep Packet Inspection System (Java, macOS-compatible)

This repository contains a Java-based Deep Packet Inspection (DPI) tool that can:

- process offline `.pcap` files,
- capture live traffic on macOS/Linux (via `libpcap`/Pcap4J),
- classify traffic (SNI/HTTP host/DNS/QUIC hints where visible),
- apply blocking rules (IP, app, domain),
- write filtered output PCAPs,
- export CSV/JSON reports,
- expose Prometheus metrics (optional Grafana/Prometheus stack via Docker).

> Primary entrypoints are shell wrappers in `Packet_analyzer-main/java-port/`, especially `dpi.sh` and `com.deeppacket.app.DpiMain`.

## Quick start (fresh macOS user)

### 1) Clone and enter the Java project

```bash
cd /path/to/Deep-Packet-Inspection-System/Packet_analyzer-main/java-port
```

### 2) Check prerequisites

```bash
bash setup-macos.sh
./dpi.sh check
```

Required for core usage:

- Java 17+
- Maven
- Python 3

Optional (only for monitoring dashboards):

- Docker Desktop (running daemon)

Install commonly used packages with Homebrew:

```bash
brew install openjdk@21 maven python
```

Apple Silicon Java PATH (if `java` is not found after install):

```bash
export PATH="/opt/homebrew/opt/openjdk@21/bin:$PATH"
```

Intel Mac Java PATH (common Homebrew path):

```bash
export PATH="/usr/local/opt/openjdk@21/bin:$PATH"
```

### 3) Build

```bash
./dpi.sh build
```

### 4) First successful offline run (included sample PCAP)

```bash
./dpi.sh normal --no-metrics
```

Default input:

- `Packet_analyzer-main/quick_test_mixed_20mb.pcap`

Default output:

- `Packet_analyzer-main/java-port/outputs/output_normal.pcap`

### 5) Run blocking

```bash
./dpi.sh block --block-app YouTube --block-domain facebook --no-metrics --verbose
```

Default blocked output:

- `Packet_analyzer-main/java-port/outputs/output_blocked.pcap`

### 6) Generate reports

```bash
./dpi.sh report traffic --no-metrics
```

Outputs:

- `outputs/output_traffic.pcap`
- `outputs/traffic.csv`
- `outputs/traffic.json`

### 7) List interfaces and attempt live capture

```bash
./dpi.sh ifaces
sudo ./dpi.sh live 20 en0 --no-metrics --verbose
```

Live outputs (wrapper defaults):

- capture input: `outputs/live_input.pcap`
- filtered output: `outputs/output_live_filtered.pcap`

---

## Project architecture (high-level)

Pipeline:

1. Read packets from PCAP (`PcapReader`) or live capture (`LiveCaptureService`).
2. Parse L2/L3/L4 and protocol hints (`PacketParser`, SNI/HTTP/DNS/QUIC extractors).
3. Classify + apply rules in multithreaded DPI engine (`DPIEngine`).
4. Forward allowed packets to output PCAP (`PcapWriter`), drop blocked packets.
5. Emit text report + optional CSV/JSON + Prometheus metrics.

Default engine concurrency (`DPIEngine.Config`):

- `--lbs` default: `2`
- `--fps` default: `2` per load balancer

---

## Directory structure

```text
Deep-Packet-Inspection-System/
├── README.md
└── Packet_analyzer-main/
    ├── quick_test_mixed_20mb.pcap
    ├── generate_test_pcap.py
    └── java-port/
        ├── dpi.sh
        ├── setup-macos.sh
        ├── normal.sh / block.sh / live.sh / report.sh / ifaces.sh
        ├── monitor.sh / metrics.sh
        ├── monitoring/docker-compose.yml
        ├── pom.xml
        └── src/main/java/com/deeppacket/
            ├── app/DpiMain.java
            ├── engine/
            ├── parser/
            ├── dpi/
            ├── pcap/
            └── monitoring/
```

---

## Command interface (`dpi.sh`)

Run from `Packet_analyzer-main/java-port`:

```bash
./dpi.sh help
```

Supported commands:

- `check` – verify Java/Maven/Python; report Docker status (optional)
- `build` – `mvn clean package`
- `ifaces` – list capture interfaces from Pcap4J
- `normal [input.pcap] [opts]` – offline processing
- `block [rules] [opts]` – offline processing + blocking
- `live [duration] [iface] [opts]` – live capture + DPI
- `report [stem] [input.pcap] [opts]` – generate CSV/JSON + filtered PCAP
- `monitor <up|down|restart|status|logs>` – Docker Compose monitoring control
- `metrics <start|stop|status|logs|links|open|run|runblock> [arg]`
- `generate [output.pcap]` – run Python PCAP generator
- `help` / `-h` / `--help`

> You can append the token `metrics` (also accepted misspellings: `metrices`, `-metrics`, `-metrices`) to `normal/block/live/report` to auto-start monitoring and keep metrics scrape window open.

See detailed examples in [`docs/COMMANDS.md`](docs/COMMANDS.md).

---

## Direct Java CLI (`com.deeppacket.app.DpiMain`)

Usage modes:

```text
pcap mode: java com.deeppacket.app.DpiMain <input.pcap> <output.pcap> [options]
live mode: java com.deeppacket.app.DpiMain --live <output.pcap> [options]
```

Options:

- Blocking/rules: `--block-ip`, `--block-app`, `--block-domain`, `--rules`, `--save-rules`
- Reports: `--report-csv`, `--report-json`
- Threads/perf: `--lbs`, `--fps`, `--verbose`
- Live capture: `--live`, `--iface`, `--duration`, `--capture-out`, `--bpf`, `--list-ifaces`
- Prometheus: `--no-metrics`, `--metrics-bind`, `--metrics-port`, `--metrics-hold`, `--metrics-file`
- Help: `--help`, `-h`

Key defaults in Java mode:

- live duration default: `15s`
- live capture output default: `./outputs/live_capture_input.pcap`
- default BPF: `ip and tcp or ip and udp`
- metrics enabled by default at `0.0.0.0:9400`
- metrics file default: `./outputs/prometheus_metrics.prom`

---

## Outputs and artifacts

### PCAP outputs

- `normal`: `outputs/output_normal.pcap`
- `block`: `outputs/output_blocked.pcap`
- `report <stem>`: `outputs/output_<stem>.pcap`
- `live`: `outputs/output_live_filtered.pcap` and capture source `outputs/live_input.pcap`

### CSV report (`--report-csv`)

Connection rows including:

- source/destination IP + ports
- protocol
- app classification
- connection state/action
- SNI/domain hint (if present)
- packet/byte counters
- first/last seen timestamps (ns)

### JSON report (`--report-json`)

Includes:

- summary stats (packets/bytes/tcp/udp/forwarded/dropped/connections)
- performance metrics (pps, throughput, latency, CPU, memory)
- app distribution
- top domains
- top connections by bytes

### Prometheus metrics

- HTTP endpoint: `http://<bind>:<port>/metrics` (default `http://0.0.0.0:9400/metrics`)
- optional file export via `--metrics-file`

---

## Optional monitoring stack (Docker)

`./dpi.sh monitor up` starts services from `java-port/monitoring/docker-compose.yml`:

- Prometheus: `http://localhost:9090`
- Grafana: `http://localhost:3001`
- Grafana credentials: `admin / admin`

Stop:

```bash
./dpi.sh monitor down
```

---

## Troubleshooting (macOS-focused)

### `java` / `mvn` / `python3` not found

- Run `bash setup-macos.sh` and `./dpi.sh check`
- Install missing tools: `brew install openjdk@21 maven python`
- Ensure Java path is exported (Apple Silicon vs Intel paths above)

### Apple Silicon Java installed but still not detected

```bash
export PATH="/opt/homebrew/opt/openjdk@21/bin:$PATH"
java -version
```

### Live capture permission errors / capture fails

- Use `./dpi.sh ifaces` to choose interface
- Retry with elevated privilege:
  ```bash
  sudo ./dpi.sh live 20 en0 --no-metrics
  ```
- Confirm interface exists and is active (Wi-Fi is commonly `en0`)

### Wrong interface selected

- List all interfaces and descriptions:
  ```bash
  ./dpi.sh ifaces
  ```
- In direct Java live mode, if `--iface` is omitted, code chooses first non-loopback interface

### Docker monitoring errors (`monitor` / `metrics`)

- Ensure Docker Desktop is installed and running
- `./dpi.sh check` shows whether Docker daemon is reachable

### Port conflicts (`9090`, `3001`, `9400`)

- Monitoring stack uses `9090` and `3001`
- DPI Prometheus endpoint uses `9400` by default
- Change metrics port if needed:
  ```bash
  ./dpi.sh normal --metrics-port 9500
  ```

---

## Security and limitations

- This is a DPI analysis/filtering tool for offline PCAP and host-level live capture.
- It can inspect traffic metadata and plaintext/handshake-visible fields (for example DNS queries, HTTP host headers, TLS SNI where present).
- It does **not** decrypt payloads of encrypted traffic; visibility is limited by protocol encryption and available metadata.
- Live capture requires host privileges and only sees traffic observable from selected interfaces.

---

## Additional docs

- Detailed command reference: [`docs/COMMANDS.md`](docs/COMMANDS.md)
