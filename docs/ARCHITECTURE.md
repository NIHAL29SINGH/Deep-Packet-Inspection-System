# DPI Sentinel Architecture

DPI Sentinel is a local-first Java 17 deep-packet-inspection and network-security
engine for authorized packet-capture files (offline analysis only). This document describes the
implemented data path, concurrency model, decision points, evidence outputs,
and observability boundaries.

> **Authorization:** Use the engine only on captures and networks that you own
> or are explicitly authorized to monitor.

## 1. System context

```mermaid
flowchart LR
    analyst[Security analyst]
    operator[Authorized network operator]
    capture[pcap or pcapng file]
    dpi[DPI Sentinel Java engine]
    reports[HTML / JSON / CSV / filtered PCAP]
    evidence[Evidence bundle with hashes]
    prometheus[Prometheus]
    grafana[Grafana]
    rules[rules.txt and risk-rules.properties]

    analyst -->|Run CLI and review findings| dpi
    operator -->|Authorized input| capture
    capture --> dpi
    rules -->|Policy and scoring configuration| dpi
    dpi --> reports
    dpi --> evidence
    dpi -->|/metrics and /health :9400| prometheus
    prometheus --> grafana
    analyst -->|Investigate| reports
    analyst -->|Share controlled artifacts| evidence
```

The engine processes data locally. It does not upload packet contents to a
remote service. Generated reports and evidence can contain sensitive network
metadata and must be handled according to the organization's security policy.

## 2. Component architecture

```mermaid
flowchart TB
    subgraph input[Input]
        pcap[PcapReader<br/>pcap and pcapng]
    end

    subgraph parsing[Validated parsing]
        frame[Ethernet and VLAN parser]
        ip[IPv4 / IPv6 metadata parser]
        transport[TCP / UDP parser]
        tuple[FiveTuple]
    end

    subgraph engine[DPIEngine]
        lbm[LBManager]
        lb[LoadBalancer]
        queues[Bounded ThreadSafeQueue]
        fp[FastPathProcessor workers]
        tracking[ConnectionTracker]
        global[GlobalConnectionTable]
    end

    subgraph intelligence[Inspection and decisions]
        extractors[DNS / HTTP Host / TLS SNI / QUIC SNI]
        classify[Application and domain classification]
        rules[RuleManager]
        risk[RiskAnalyzer]
    end

    subgraph output[Outputs]
        outq[Bounded output queue]
        writer[PcapWriter]
        reports[HTML / JSON / CSV reports]
        bundle[Evidence bundle]
        metrics[PrometheusMetricsServer]
    end

    pcap --> frame
    frame --> ip
    ip --> transport
    transport --> tuple
    tuple --> lbm
    lbm --> lb
    lb --> queues
    queues --> fp
    fp --> tracking
    fp --> extractors
    extractors --> classify
    classify --> rules
    rules --> outq
    outq --> writer
    tracking --> global
    global --> risk
    risk --> reports
    writer --> reports
    reports --> bundle
    global --> metrics
```

## 3. Offline packet-processing flow

```mermaid
sequenceDiagram
    autonumber
    participant R as PcapReader
    participant P as PacketParser
    participant L as LBManager
    participant Q as Bounded queue
    participant F as FastPathProcessor
    participant C as ConnectionTracker
    participant X as Protocol extractors
    participant M as RuleManager
    participant W as Output queue and PcapWriter

    R->>P: Read next frame
    P->>P: Validate lengths and decode headers
    alt Non-IPv4, non-TCP/UDP, IP fragment or malformed frame
        P-->>R: Count in a separate counter and skip safely
    else Eligible packet
        P->>L: Create PacketJob with FiveTuple
        L->>Q: Hash-route flow to worker queue
        Q->>F: Deliver PacketJob
        F->>C: Create/update connection state
        F->>X: Inspect visible payload metadata
        X-->>C: Application/domain/SNI classification
        F->>M: Evaluate IP, app, domain, and port rules
        alt Block rule matches
            M-->>F: DROP
            F->>W: Omit packet from filtered output
        else No rule matches
            M-->>F: FORWARD
            F->>W: Write packet to filtered PCAP
        end
    end
```

The reader, worker queues, processors, and output writer have explicit
completion and drain behavior. Completion does not depend on a fixed sleep.
Malformed or truncated frames are rejected safely by the parser.

## 4. Flow affinity and concurrency

```mermaid
flowchart LR
    packet[Packet]
    hash["Direction-independent<br/>five-tuple hash"]
    lb0[Load balancer 0]
    lb1[Load balancer 1]
    q0[Bounded queues]
    q1[Bounded queues]
    fp0["FastPath workers<br/>(chosen by a second-stage hash)"]
    fp1["FastPath workers<br/>(chosen by a second-stage hash)"]
    state0[Local connection state]
    state1[Local connection state]
    output[Output queue and writer]

    packet --> hash
    hash --> lb0
    hash --> lb1
    lb0 --> q0
    lb1 --> q1
    q0 --> fp0
    q1 --> fp1
    fp0 --> state0
    fp1 --> state1
    state0 --> output
    state1 --> output
```

Packets belonging to the same conversation, in either direction, are routed to the same
load-balancer path and then to the same worker (the hash is direction-independent, and the
worker is picked with a different slice of the hash than the load balancer). This preserves connection-local state without requiring every packet
operation to lock a shared connection table. Bounded queues provide
backpressure; a hot flow can still create uneven distribution, which is an
explicit trade-off documented in [ADR-001](ADR-001-flow-affinity.md).

## 5. Risk, evidence, and report pipeline

```mermaid
flowchart TB
    connection[Tracked connection]
    observations[Visible observations<br/>ports, app, SNI, bytes, action]
    rules[Configurable risk rules]
    assessment[Deterministic assessment]
    score[Score and severity]
    findings[Findings and confidence]
    action[Recommended analyst action]
    id[Stable SHA-256 evidence ID]
    html[HTML report]
    json[JSON report]
    csv[CSV flow export]
    pcap[Filtered PCAP]
    manifest[Manifest with source/artifact hashes]

    connection --> observations
    observations --> assessment
    rules --> assessment
    assessment --> score
    assessment --> findings
    assessment --> action
    connection --> id
    score --> html
    findings --> html
    action --> html
    id --> html
    score --> json
    findings --> json
    id --> json
    connection --> csv
    connection --> pcap
    html --> manifest
    json --> manifest
    csv --> manifest
    pcap --> manifest
```

Risk is explainable heuristic triage, not a malware verdict. Signals include
blocked policy flows, clear-text legacy services, sensitive/high-risk ports,
missing visible SNI, unknown applications, unusual domains, and strong
outbound byte asymmetry. Risk and confidence are reported separately.

## 6. Monitoring

```mermaid
flowchart LR
    input[pcap or pcapng file]
    engine[DPI Sentinel engine]
    endpoint[Metrics and health<br/>:9400]
    prom[Prometheus<br/>:9090]
    grafana[Grafana<br/>:3001]
    analyst[Analyst dashboard]

    input --> engine
    engine --> endpoint
    endpoint --> prom
    prom --> grafana
    grafana --> analyst
```

The engine exposes plain-text `/metrics` and `/health` endpoints while a run
is active. The repository's monitoring Compose file starts Prometheus and
Grafana separately. The root Compose profile packages the DPI container; it
does not replace the monitoring Compose stack.

## 7. Deployment boundaries

```mermaid
flowchart TB
    subgraph host[Developer or analysis host]
        cli[./dpi launcher]
        engine[Java 17 DPI container or local JVM]
        data[Mounted PCAPs and outputs]
    end

    subgraph monitoring[Monitoring Compose stack]
        prometheus[Prometheus]
        grafana[Grafana]
    end

    cli --> engine
    data <--> engine
    engine -->|host.docker.internal:9400| prometheus
    prometheus --> grafana
```

The container only needs read access to capture files and write access to the output folder.
No packet-capture privileges or host networking are required because the engine never captures live traffic.

## 8. Trust boundaries and limitations

| Boundary | Risk | Implemented control |
| --- | --- | --- |
| Capture file into reader and parser | Malformed, truncated or hostile input | Length validation, bounded allocation, seeded fuzz tests |
| Rule/configuration files | Invalid or unsafe values | Validation before engine startup |
| Reports and evidence | Sensitive metadata disclosure | Local processing, hashes, pseudonymous IDs |
| Metrics endpoint | Operational data exposure | Bind and network controls required |
| Capture file provenance | Analysing data you are not authorised to hold | Operator responsibility; the tool never captures traffic itself |

The current engine intentionally does not claim:

- TLS decryption.
- Full TCP stream reassembly.
- Full IP-fragment reassembly.
- Full IPv6 flow processing through the IPv4 DPI path.
- Complete QUIC visibility.
- Malware classification accuracy without a labeled dataset.

## 9. Flow lifecycle, reassembly and QUIC

- **One flow, two directions.** Routing uses `FiveTuple.symmetricHash()`, so a request and its reply reach the same worker and
  the same `Connection`. The connection remembers its initiator, which is how packets are counted as inbound or outbound.
- **Two independent hash stages.** The load balancer and the worker are chosen from different bits (`symmetricHash`, `fastPathHash`);
  otherwise `hash % lbs` and `hash % fps` are correlated and some workers stay idle.
- **Retire, don't delete.** Closed, idle and evicted flows move to a bounded history, so reports still contain them. A reused 4-tuple
  after a closed connection starts a new flow and keeps the old one.
- **TLS reassembly.** When the client's first TLS record is larger than the first segment, in-order segments are buffered (exact record
  size, 16 KiB cap, 16 MiB budget per worker) until the ClientHello is complete, then the buffer is released.
- **QUIC.** `QUICSNIExtractor` derives the v1 Initial keys from the destination connection ID, removes header protection, decrypts
  with AES-128-GCM, reads the CRYPTO frame and parses the ClientHello. It is verified against RFC 9001 appendix A key values and a packet
  built by an independent implementation.
- **Reporting is separate from processing.** `DPIEngine` owns the pipeline lifecycle; `ReportExporter`, `ConsoleReport`,
  `PrometheusPublisher` and `PerformanceMonitor` are standalone classes fed with an immutable snapshot. Latency is recorded in a
  lock-free log-scale histogram, so recording costs O(1) time and constant memory per packet.

See [ADR-002](ADR-002-flow-lifecycle-and-reassembly.md) for the reasoning and trade-offs.

## 10. Advanced analysis stages

```mermaid
flowchart LR
    pkt["Payload of one packet"] --> tls{"TLS ClientHello?"}
    tls -->|yes| ja3["JA3 fingerprint<br/>+ TLS version"]
    tls -->|yes| sni["SNI (reassembled if split)"]
    pkt --> quic{"QUIC v1 / v2 Initial?"}
    quic -->|yes| dec["Derive keys, decrypt,<br/>collect CRYPTO fragments"]
    dec --> asm["ReassemblyBuffer<br/>(bounded, out-of-order safe)"]
    asm --> sni
    pkt --> dnsq{"DNS?"}
    dnsq -->|query| name["Query name"]
    dnsq -->|response| cache["DnsCache<br/>(address to name)"]
    sni --> cls["Classification<br/>+ classified_by evidence"]
    name --> cls
    ja3 --> rules["RuleManager<br/>(JA3 block rule)"]
    cache -.->|"after the run"| enrich["Correlate flows with no SNI<br/>and flag DNS tunnelling"]
    cls --> enrich
```

- **JA3** is computed from the hello's cipher suites, extensions, groups and point formats (GREASE removed), so it identifies the client
  implementation. It is computed before rules run, so the hello packet itself can be dropped by a JA3 rule.
- **DnsCache** is shared by all workers but keeps the answer with the latest capture timestamp, so the result does not depend on thread scheduling.
- **Enrichment** runs once, single-threaded, after the workers have stopped: it never races with packet processing.
- **ReassemblyBuffer** accepts fragments in any order within a fixed capacity; its memory counts against the same per-worker budget as TLS reassembly.

See [ADR-003](ADR-003-advanced-analysis.md).
