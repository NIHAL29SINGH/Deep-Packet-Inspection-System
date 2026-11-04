# ADR-003: Offline-only scope and the advanced analysis stages

Status: accepted

## Context

After ADR-002 the engine had trustworthy flows. Three questions remained:

1. Live capture added privileges, platform differences and a native dependency (pcap4j/libpcap) for a mode that only recorded a file and then ran
   the offline pipeline anyway. It was the most complex and least testable part of the project.
2. Real captures arrive as pcapng, and modern QUIC clients split their ClientHello over several packets, so two common inputs were not analysed.
3. Encrypted traffic still carries useful signals (client implementation, resolved names, query patterns) that the engine ignored.

## Decisions

1. **Offline only.** Live capture, its CLI commands and scripts, and the pcap4j dependency are removed. The runtime now has no third-party
   dependencies, the Docker image needs no privileges, and every code path is testable with files.
2. **pcapng input** (sections, interfaces, timestamp resolutions, simple and enhanced packet blocks), validated against a Python-built pair of
   files that must yield identical packets and identical flows. The reader is also buffered, which removes a system call per record.
3. **QUIC v2 and fragment reassembly.** Decryption now returns CRYPTO fragments; a bounded `ReassemblyBuffer` rebuilds the ClientHello across
   Initial packets, sized from the handshake header and charged to the per-worker memory budget. v2 is checked against the RFC 9369 key values.
4. **JA3** (plus TLS version) is computed on every ClientHello before rules run, so it can be used to block and to watch-list clients. It is verified
   against an independent implementation, including GREASE handling.
5. **DNS correlation after the run.** Workers only record answers into a deterministic cache; a single-threaded pass after shutdown ties flows with no
   SNI to a name and flags tunnelling patterns. Doing this after the run avoids any dependence on which worker saw the DNS reply first.
6. **Evidence field.** Every classification records what it rests on, so an inferred name is never presented as an observed SNI.
7. **Fuzzing as a test class.** Seeded mutation of valid traffic and of capture files, with mutation checks that deleting a safety check makes a test fail.

## Consequences

- Smaller attack surface and an easier build, at the price of no real-time monitoring (use a dedicated capture tool and analyse the file).
- JA3 and the DNS heuristics have false positives (hash-named CDN hosts, imitated hellos); they add to an explainable score and never decide alone.
- A QUIC hello whose first packet is lost or arrives last cannot be sized and is skipped; this is counted as an unclassified flow, not guessed.
- Unconfirmed: behaviour on very large pcapng files has not been benchmarked.
