# DPI Engine - Deep Packet Inspection System

This document explains **everything** about this Java project - from basic networking concepts to the complete code architecture. After reading this, you should understand exactly how packets flow through the system without needing to read the code.

---

## Table of Contents

1. [What is DPI?](#1-what-is-dpi)
2. [Networking Background](#2-networking-background)
3. [Project Overview](#3-project-overview)
4. [File Structure](#4-file-structure)
5. [The Journey of a Packet (Simple Version)](#5-the-journey-of-a-packet-simple-version)
6. [The Journey of a Packet (Multi-threaded Version)](#6-the-journey-of-a-packet-multi-threaded-version)
7. [Deep Dive: Each Component](#7-deep-dive-each-component)
8. [How SNI Extraction Works](#8-how-sni-extraction-works)
9. [How Blocking Works](#9-how-blocking-works)
10. [Building and Running](#10-building-and-running)
11. [Understanding the Output](#11-understanding-the-output)
12. [Extending the Project](#12-extending-the-project)

---

## 1. What is DPI?

**Deep Packet Inspection (DPI)** is a technology used to examine the contents of network packets as they pass through a checkpoint. Unlike simple firewalls that only look at packet headers (source/destination IP), DPI looks *inside* the packet payload.

### Real-World Uses:
- **ISPs**: Throttle or block certain applications (e.g., BitTorrent)
- **Enterprises**: Block social media on office networks
- **Parental Controls**: Block inappropriate websites
- **Security**: Detect malware or intrusion attempts

### What Our DPI Engine Does:
```text
User Traffic (PCAP) -> [DPI Engine] -> Filtered Traffic (PCAP)
                           |
                    - Identifies apps (YouTube, Facebook, etc.)
                    - Blocks based on rules
                    - Generates reports
```

---

## 2. Networking Background

### The Network Stack (Layers)

When you visit a website, data travels through multiple layers:

```text
┌─────────────────────────────────────────────────────────┐
│ Layer 7: Application    │ HTTP, TLS, DNS               │
├─────────────────────────────────────────────────────────┤
│ Layer 4: Transport      │ TCP (reliable), UDP (fast)   │
├─────────────────────────────────────────────────────────┤
│ Layer 3: Network        │ IP addresses (routing)       │
├─────────────────────────────────────────────────────────┤
│ Layer 2: Data Link      │ MAC addresses (local network)│
└─────────────────────────────────────────────────────────┘
```

### A Packet's Structure

Every network packet is like a **Russian nesting doll** - headers wrapped inside headers:

```text
┌──────────────────────────────────────────────────────────────────┐
│ Ethernet Header (14 bytes)                                       │
│ ┌──────────────────────────────────────────────────────────────┐ │
│ │ IP Header (20 bytes)                                         │ │
│ │ ┌──────────────────────────────────────────────────────────┐ │ │
│ │ │ TCP Header (20 bytes)                                    │ │ │
│ │ │ ┌──────────────────────────────────────────────────────┐ │ │ │
│ │ │ │ Payload (Application Data)                           │ │ │ │
│ │ │ │ e.g., TLS Client Hello with SNI                      │ │ │ │
│ │ │ └──────────────────────────────────────────────────────┘ │ │ │
│ │ └──────────────────────────────────────────────────────────┘ │ │
│ └──────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
```

### The Five-Tuple

A **connection** (or "flow") is uniquely identified by 5 values:

| Field | Example | Purpose |
|-------|---------|---------|
| Source IP | 192.168.1.100 | Who is sending |
| Destination IP | 172.217.14.206 | Where it's going |
| Source Port | 54321 | Sender's application identifier |
| Destination Port | 443 | Service being accessed (443 = HTTPS) |
| Protocol | TCP (6) | TCP or UDP |

**Why is this important?**
- All packets with the same 5-tuple belong to the same connection
- If we block one packet of a connection, we should block all of them
- This is how we "track" conversations between computers

### What is SNI?

**Server Name Indication (SNI)** is part of the TLS/HTTPS handshake. When you visit `https://www.youtube.com`:

1. Your browser sends a "Client Hello" message
2. This message includes the domain name in plaintext (not encrypted yet)
3. The server uses this to know which certificate to send

```text
TLS Client Hello:
├── Version: TLS 1.2+
├── Random: [32 bytes]
├── Cipher Suites: [list]
└── Extensions:
    └── SNI Extension:
        └── Server Name: "www.youtube.com"  <- We extract THIS
```

**This is the key to DPI**: even though HTTPS is encrypted, the destination domain is often visible in Client Hello.

---

## 3. Project Overview

### What This Project Does

```text
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│ Wireshark   │     │ DPI Engine  │     │ Output      │
│ Capture     │ --> │             │ --> │ PCAP        │
│ (input.pcap)│     │ - Parse     │     │ (filtered)  │
└─────────────┘     │ - Classify  │     └─────────────┘
                    │ - Block     │
                    │ - Report    │
                    └─────────────┘
```

### Two Versions (Java)

| Version | File | Use Case |
|---------|------|----------|
| Simple (Single-threaded) | `java-port/src/main/java/com/deeppacket/app/PacketAnalyzerMain.java` | Learning, packet inspection |
| Multi-threaded DPI | `java-port/src/main/java/com/deeppacket/app/DpiMain.java` | Full DPI engine, filtering |

---

## 4. File Structure

```text
Packet_analyzer-main/
├── generate_test_pcap.py
├── test_dpi.pcap
├── README.md
└── java-port/
    ├── pom.xml
    └── src/main/java/com/deeppacket/
        ├── app/
        │   ├── DpiMain.java
        │   ├── PacketAnalyzerMain.java
        │   └── SimpleDpiMain.java
        ├── pcap/
        │   ├── PcapReader.java
        │   ├── PcapWriter.java
        │   ├── PcapGlobalHeader.java
        │   ├── PcapPacketHeader.java
        │   └── RawPacket.java
        ├── parser/
        │   ├── PacketParser.java
        │   └── ParsedPacket.java
        ├── dpi/
        │   ├── SNIExtractor.java
        │   ├── HTTPHostExtractor.java
        │   ├── DNSExtractor.java
        │   └── QUICSNIExtractor.java
        ├── model/
        │   ├── FiveTuple.java
        │   ├── AppType.java
        │   ├── Connection.java
        │   ├── ConnectionState.java
        │   ├── PacketAction.java
        │   ├── PacketJob.java
        │   └── DPIStats.java
        └── engine/
            ├── DPIEngine.java
            ├── RuleManager.java
            ├── ConnectionTracker.java
            ├── GlobalConnectionTable.java
            ├── ThreadSafeQueue.java
            ├── LoadBalancer.java
            ├── LBManager.java
            ├── FastPathProcessor.java
            └── FPManager.java
```

---

## 5. The Journey of a Packet (Simple Version)

Let's trace a packet through `PacketAnalyzerMain.java`:

### Step 1: Read PCAP File
```java
PcapReader reader = new PcapReader();
reader.open("capture.pcap");
```

### Step 2: Read Each Packet
```java
while (reader.readNextPacket().isPresent()) {
    // raw packet bytes + packet header
}
```

### Step 3: Parse Protocol Headers
```java
ParsedPacket parsed = PacketParser.parse(rawPacket);
```

### Step 4: Print Human-Readable Fields
- MAC addresses
- IP addresses
- ports
- protocol
- TCP flags
- payload preview

This mode is mainly for learning and debugging packet structure.

---

## 6. The Journey of a Packet (Multi-threaded Version)

The multi-threaded engine (`DpiMain` + `DPIEngine`) adds parallelism.

### Architecture Overview

```text
                    ┌─────────────────┐
                    │  Reader Thread  │
                    │  (reads PCAP)   │
                    └────────┬────────┘
                             │
              ┌──────────────┴──────────────┐
              │      hash(5-tuple) % LBs    │
              ▼                             ▼
    ┌─────────────────┐           ┌─────────────────┐
    │  LB0 Thread     │           │  LB1 Thread     │
    │  (Load Balancer)│           │  (Load Balancer)│
    └────────┬────────┘           └────────┬────────┘
             │                             │
      ┌──────┴──────┐               ┌──────┴──────┐
      │hash % local │               │hash % local │
      ▼             ▼               ▼             ▼
┌──────────┐ ┌──────────┐   ┌──────────┐ ┌──────────┐
│FP0 Thread│ │FP1 Thread│   │FP2 Thread│ │FP3 Thread│
│(Fast Path)│ │(Fast Path)│ │(Fast Path)│ │(Fast Path)│
└─────┬────┘ └─────┬────┘   └─────┬────┘ └─────┬────┘
      │            │              │            │
      └────────────┴──────────────┴────────────┘
                          │
                          ▼
              ┌───────────────────────┐
              │   Output Queue        │
              └───────────┬───────────┘
                          │
                          ▼
              ┌───────────────────────┐
              │  Output Writer Thread │
              │  (writes PCAP)        │
              └───────────────────────┘
```

### Why This Design?
- Load balancers distribute work
- Fast-path workers do DPI and decisions
- Consistent hashing keeps a flow on the same FP worker

---

## 7. Deep Dive: Each Component

### `pcap/*`
- `PcapReader`: validates header, reads packets
- `PcapWriter`: writes forwarded packets to output file

### `parser/*`
- `PacketParser`: parses Ethernet, IPv4, TCP/UDP, payload offsets

### `dpi/*`
- `SNIExtractor`: TLS ClientHello SNI parsing
- `HTTPHostExtractor`: Host header extraction
- `DNSExtractor`: DNS query domain extraction
- `QUICSNIExtractor`: basic QUIC initial detection/extraction attempt

### `model/*`
- `FiveTuple`: flow key
- `Connection`: per-flow state
- `AppType`: application classification enum
- `PacketJob`: queue payload across threads
- `DPIStats`: counters

### `engine/*`
- `RuleManager`: blocking rules + load/save
- `ConnectionTracker`: per-FP flow table
- `ThreadSafeQueue`: producer/consumer handoff
- `LoadBalancer`/`LBManager`: distribution stage
- `FastPathProcessor`/`FPManager`: DPI workers
- `DPIEngine`: orchestration + report generation

---

## 8. How SNI Extraction Works

`SNIExtractor` logic:
1. Verify TLS handshake record
2. Verify ClientHello message
3. Skip session/cipher/compression sections
4. Parse extensions
5. Find extension `0x0000` (SNI)
6. Extract hostname

Simplified flow:
```text
TLS record -> ClientHello -> Extensions -> SNI -> Hostname
```

---

## 9. How Blocking Works

### Rule Types

| Rule Type | Example | What it Blocks |
|-----------|---------|----------------|
| IP | `192.168.1.50` | All traffic from source IP |
| App | `YouTube` | Classified YouTube flows |
| Domain | `facebook` or `*.facebook.com` | Matching SNI/domain |

### Blocking Flow

```text
Packet arrives
      │
      ▼
Check IP rule -> Check Port rule -> Check App rule -> Check Domain rule
      │
      ├── match -> DROP
      └── no match -> FORWARD
```

### Flow-Based Behavior

Once a flow is marked blocked, later packets in the same flow are dropped.

---

## 10. Building and Running

### Prerequisites
- Java 17+
- Maven 3.9+
- Wireshark (for verification)

### Build
```powershell
cd "D:\deep packet\Packet_analyzer-main\java-port"
mvn clean package
```

### Basic Run
```powershell
mvn exec:java "-Dexec.mainClass=com.deeppacket.app.DpiMain" "-Dexec.args=../test_dpi.pcap ../output.pcap"
```

### With Blocking
```powershell
mvn exec:java "-Dexec.mainClass=com.deeppacket.app.DpiMain" "-Dexec.args=../test_dpi.pcap ../output_blocked.pcap --block-app YouTube --block-app TikTok --block-ip 192.168.1.50 --block-domain facebook --verbose"
```

### Configure Threads
```powershell
mvn exec:java "-Dexec.mainClass=com.deeppacket.app.DpiMain" "-Dexec.args=../test_dpi.pcap ../output_threads.pcap --lbs 4 --fps 4"
```

### CLI Help
```powershell
mvn exec:java "-Dexec.mainClass=com.deeppacket.app.DpiMain" "-Dexec.args=--help"
```

### Create Test Data
```powershell
cd "D:\deep packet\Packet_analyzer-main"
python generate_test_pcap.py
```

---

## 11. Understanding the Output

### Sample Output (style)

```text
╔══════════════════════════════════════════════════════════════╗
║              DPI ENGINE v2.0 (Multi-threaded)               ║
╠══════════════════════════════════════════════════════════════╣
║ Load Balancers:  2    FPs per LB:  2    Total FPs:  4        ║
╚══════════════════════════════════════════════════════════════╝

[Rules] Blocked app: YouTube
[Rules] Blocked IP: 192.168.1.50

[Reader] Processing packets...
[Reader] Done reading 77 packets

╔══════════════════════════════════════════════════════════════╗
║                      PROCESSING REPORT                       ║
╠══════════════════════════════════════════════════════════════╣
║ Total Packets:                77                             ║
║ Total Bytes:                5738                             ║
║ TCP Packets:                  73                             ║
║ UDP Packets:                   4                             ║
╠══════════════════════════════════════════════════════════════╣
║ Forwarded:                    69                             ║
║ Dropped:                       8                             ║
╠══════════════════════════════════════════════════════════════╣
║ THREAD STATISTICS                                            ║
║   LB0 dispatched:             53                             ║
║   LB1 dispatched:             24                             ║
║   FP0 processed:              53                             ║
║   FP1 processed:               0                             ║
║   FP2 processed:               0                             ║
║   FP3 processed:              24                             ║
╠══════════════════════════════════════════════════════════════╣
║                   APPLICATION BREAKDOWN                      ║
╠══════════════════════════════════════════════════════════════╣
║ HTTPS                39  50.6% ##########                    ║
║ Unknown              16  20.8% ####                          ║
║ YouTube               4   5.2% #                             ║
║ DNS                   4   5.2% #                             ║
║ Facebook              3   3.9%                               ║
╚══════════════════════════════════════════════════════════════╝
```

### What Each Section Means

| Section | Meaning |
|---------|---------|
| Configuration | Thread layout created |
| Rules | Active blocking rules |
| Total Packets | Packets read from input |
| Forwarded | Packets written to output |
| Dropped | Packets blocked |
| Thread Statistics | Work distribution |
| Application Breakdown | Classification counts |
| Detected SNIs | Extracted domain names |

### Wireshark Validation
- Open input + output PCAP
- Compare packet counts
- Use filters:
  - `tls.handshake.extensions_server_name contains "youtube"`
  - `tls.handshake.extensions_server_name contains "facebook"`

---

## 12. Extending the Project

1. Add more app signatures in `AppType.fromSni`
2. Improve QUIC/HTTP3 support
3. Add CIDR/IP-set and richer domain patterns
4. Add JSON/CSV report export
5. Add benchmark mode (pps, CPU, latency)
6. Add unit/integration tests + CI pipeline
7. Add optional live-capture mode

---

## Summary

This DPI engine demonstrates:

1. Network protocol parsing
2. Deep packet inspection (SNI/HTTP/DNS)
3. Flow tracking by five-tuple
4. Rule-based filtering
5. Multi-threaded architecture with producer-consumer queues
6. Output verification through Wireshark

The key insight is that TLS metadata (especially ClientHello SNI) enables application-aware traffic control even when payload encryption is used.

---

## 13. Recent Updates (Appended, Original Content Unchanged)

The following updates were added to the Java project after the original document:

- Command wrappers were simplified:
  - `.\normal.cmd`
  - `.\block.cmd <rules>`
  - `.\live.cmd <duration>`
- Metrics mode can be enabled directly from the same commands:
  - `.\normal.cmd metrics`
  - `.\block.cmd youtube,twitter metrics`
  - `.\live.cmd 45 metrics`
- Metrics mode behavior:
  - Starts Prometheus/Grafana automatically (if not running)
  - Opens Grafana dashboard directly
  - Runs with `-NoBench` to avoid mixed benchmark output in metrics runs
- Output organization:
  - Generated artifacts are directed to `java-port/outputs/` (pcap/csv/json/prom metrics files)
- Added/updated monitoring stack:
  - Prometheus + Grafana Docker setup under `java-port/monitoring/`
  - Provisioned Grafana dashboard for DPI metrics
- Dashboard currently focuses on:
  - Processing totals (packets/bytes/tcp/udp/forwarded/dropped)
  - Performance metrics (pps/throughput/latency/cpu/memory)
  - Thread statistics (LB/FP)
  - Application breakdown
  - Detected domains/SNIs

### Quick Run Commands (Current)

```powershell
cd "D:\deep packet\Packet_analyzer-main\java-port"
.\build.cmd

.\normal.cmd
.\normal.cmd metrics

.\block.cmd youtube,twitter
.\block.cmd youtube,twitter metrics

.\live.cmd 45
.\live.cmd 45 metrics
```

### Monitoring Commands (Current)

```powershell
cd "D:\deep packet\Packet_analyzer-main\java-port"
.\monitor.cmd up
.\monitor.cmd status
.\monitor.cmd restart
.\monitor.cmd down
```

Grafana:
- `http://localhost:3001/d/dpi-engine-overview/dpi-live-metrics-report`

Prometheus:
- `http://localhost:9090`
