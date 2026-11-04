# Changelog

## Scope: offline analysis only

- **Live capture removed.** `LiveCaptureService`, the `live` and `ifaces` commands (shell, Windows and wrapper), and the pcap4j dependency are gone.
  The runtime has no third-party dependencies, the Docker image needs no privileges, and every code path is testable with files.
- Windows launcher defaults now bind metrics to `127.0.0.1`, matching the Java and shell defaults.

## Advanced analysis (added after the correctness fixes below)

- **pcapng input:** sections, multiple interfaces, simple and enhanced packet blocks, any timestamp resolution, big- or little-endian, with strict length
  validation. Verified with a Python-written pair of files that must give identical packets and identical flows. The reader is buffered.
- **QUIC v2** (RFC 9369; key schedule checked against the RFC values) and **ClientHello reassembly across several Initial packets** with a bounded, out-of-order-safe
  `ReassemblyBuffer` charged to the per-worker memory budget.
- **JA3 TLS fingerprinting** and TLS version detection on every ClientHello (single segment or reassembled), including hellos with no SNI; a `--block-ja3` rule and a JA3
  watchlist in `risk-rules.properties`; a deprecated-TLS finding. Checked against an independent implementation, including GREASE.
- **DNS answer correlation:** flows with no visible SNI are tied to the name DNS resolved for their server (reported as `classified_by: DNS answer`, never as an SNI).
- **DNS tunnelling heuristics:** encoded-looking labels and many distinct names under one domain.
- **Explainability:** `classified_by` evidence on every flow; JSON `tls_fingerprints` inventory; new CSV/JSON/HTML fields (`ja3`, `tls_version`, `classified_by`, `dns_name`).
- **CLI:** `--block-port`, `--block-ja3`, validation of every numeric option, rule errors reported cleanly.
- **Fuzzing:** seeded mutation tests for the parser, every extractor, both capture readers and the full engine; mutation checks confirm they fail when a safety check is removed.
- **Sample data:** the generator now produces three client families (with GREASE), a TLS 1.0 client, a no-SNI flow whose server DNS resolved earlier, a DNS-tunnelling burst, and can write pcapng.

A bug found by the new end-to-end tests: DNS answers were parsed in network byte order while flows use a different internal address encoding, so lookups never matched.
It is fixed with an explicit conversion and covered by two tests.

## Correctness

- **Flow direction:** every packet was counted as outbound, so `bytesIn` was always 0 and the outbound-asymmetry
  (possible exfiltration) finding fired for any flow above the byte threshold. Direction now comes from the flow initiator.
- **Flow affinity:** the routing hash was direction-dependent, so request and reply could be tracked as two flows on
  different workers. Routing now uses a symmetric hash.
- **Worker imbalance:** load balancer and worker were chosen with the same hash, so with matching counts (for example 2x2)
  half of the workers never received traffic. A second-stage hash now selects the worker.
- **Application classification:** matching was substring-based, so `www.netflix.com` (contains "x.com") and `www.microsoft.com`
  (contains "t.co") were labelled Twitter/X. Matching now respects domain boundaries. Plain HTTP to an unknown host is labelled HTTP, not HTTPS.
- **Domain rules:** `x.com` blocked `dropbox.com`. Rules now match the domain or its subdomains; a dot-less keyword such as
  `facebook` matches a whole DNS label.
- **IP rules:** blocking an address now matches the source or the destination.
- **Lost flows:** closed, idle and evicted flows were deleted and disappeared from reports. They are now retired into a bounded history,
  and a reused 4-tuple after a close starts a new flow.
- **HTTP Host:** the header was found anywhere in the payload, including inside URLs; it must now begin a header line.
- **Parser:** Ethernet padding was counted as payload; non-first IPv4 fragments were parsed as if they had ports and created phantom flows.
- **Reports:** flows were ranked by bytes only, so high-risk flows could be missing from the report that announced them. They are ranked by risk first.

## New capability

- **QUIC v1 Initial decryption (RFC 9001):** SNI recovery for QUIC traffic. The previous extractor was a heuristic that was never called.
- **TLS ClientHello reassembly** across in-order TCP segments, within a hard memory budget.
- **PCAP:** nanosecond-resolution captures are read; pcapng and non-Ethernet link types are rejected with an explicit message.
- **Counters:** fragments, malformed frames and other non-inspected packets are reported separately instead of silently dropped.
- **Sample data:** `generate_sample_pcap.py` builds a deterministic, bidirectional capture with valid checksums, handshakes, split ClientHellos,
  real QUIC Initials, scenarios (Telnet, RDP, upload, no-SNI, fragment, IPv6) and replaces the 20 MB binary, whose HTTP payloads contained
  literal backslash-r-backslash-n instead of line breaks.

## Security and robustness

- Hostnames from packets are validated at extraction; JSON escapes all control characters; the HTML data block cannot close its script tag;
  CSV cells are protected against formula injection.
- The metrics endpoint binds to `127.0.0.1` by default (it was `0.0.0.0`).
- `ConnectionTracker` is thread-safe (concurrent map, atomic counters); the latency recorder is a lock-free histogram with constant memory
  (previously a globally locked, unbounded array).
- Output write failures are counted, logged and make `processFile` return `false`.
- Flow-table eviction removes a batch of the oldest flows instead of scanning the table for every new flow.

## Structure and tooling

- Architecture diagrams corrected to match the code (live capture records a file first, workers do inspection and policy inline,
  reports and metrics are built after the run, both stages of the symmetric flow hash, and the output queue).
- `DPIEngine` split from 760 to about 290 lines: `ReportExporter`, `ConsoleReport`, `PrometheusPublisher`, `PerformanceMonitor`,
  `LatencyHistogram`. The HTML template is now a resource file.
- The build produces a runnable shaded jar (the Dockerfile's `java -jar` previously had no `Main-Class`).
- CI runs `mvn verify` (tests + coverage gate, now 50%) on Java 17 and 21, uploads reports, builds and runs the Docker image, and the smoke
  test asserts on real results. Added Dependabot, LICENSE (MIT) and SECURITY.md.
- Tests grew from 12 to 130, including mutation-style checks that each fixed bug fails its test when reintroduced.

## Behaviour changes to be aware of

- `--block-domain example.com` blocks `example.com` and its subdomains only; it no longer blocks unrelated names that merely contain the string.
- JSON key `top_connections_by_bytes` is now `priority_flows` (ordered by risk, then bytes) and holds 50 flows instead of 20.
- JSON `stats` gained `other_packets`, `fragment_packets`, `malformed_packets`, `retired_connections`.
