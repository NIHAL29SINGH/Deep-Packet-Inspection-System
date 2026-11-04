# Threat model and limitations

## Protected assets

- Captured packet metadata and payloads supplied by an authorized operator.
- Investigation reports, evidence hashes, and policy configuration.
- The integrity of generated artifacts.

## Trust boundaries

1. PCAP input crosses into the parser and is untrusted.
2. Rule files and CLI values are untrusted configuration.
3. Reports may be shared outside the processing host.
4. The Prometheus endpoint is an operational interface and must not be exposed publicly without network controls.

## Controls

- Bounds checks reject truncated and malformed Ethernet/IP/TCP/UDP frames.
- PCAP lengths are bounded by snap length and 65,535 bytes.
- Reports include SHA-256 provenance hashes and stable pseudonymous evidence IDs.
- TLS payloads are not decrypted or uploaded.
- Hostnames extracted from packets (SNI, Host, DNS) are validated at the source; anything that is not a plausible
  hostname is discarded, so attacker-controlled names cannot carry markup or control characters downstream.
- Reports escape what remains: JSON escapes every control character, the HTML data block escapes `<` so it cannot
  close the script tag, and CSV cells that start with `=`, `+`, `-` or `@` are neutralised against spreadsheet formula injection.
- Memory is bounded per worker: bounded queues, a 16 MiB TLS-reassembly budget, bounded flow tables with batch eviction,
  and a bounded history of retired flows.
- CPU is bounded per flow: at most three QUIC Initial decryption attempts per flow, and non-TLS traffic never allocates a reassembly buffer.
- The tool is offline-only: it has no capture mode, so it needs no packet-capture privileges and cannot be used to sniff a network.
- The Prometheus endpoint binds to loopback by default.
- Capture readers validate every length (including pcapng block and option lengths) before allocating; seeded fuzz tests cover them.
- JA3 values and rule hashes are validated as 32 hex characters; QUIC decryption authenticates every packet (AES-GCM tag) and is capped per flow.
- CI runs tests with a coverage gate on Java 17 and 21, plus dependency-aware build checks and CodeQL.

## Known limitations

- The current processing engine routes IPv4 TCP/UDP flows; IPv6 is parsed for visibility but not sent through the IPv4-only DPI path.
- TCP reassembly is limited to the client's first TLS record (in-order segments only); IPv4 fragments are counted and skipped.
- QUIC support covers v1 client Initial packets. Their keys derive from the public connection ID (RFC 9001), so the SNI can be read without any secret;
  a ClientHello split across several Initial datagrams, QUIC v2 and draft versions are not decoded.
- An attacker who controls the capture can still make individual flows unclassifiable (for example by fragmenting, reordering or using ECH);
  absence of a finding is not evidence of benign traffic.
- Risk scores are deterministic triage signals, not malware verdicts.
