# ADR-002: Flow lifecycle, bounded reassembly and QUIC Initial decryption

Status: accepted

## Context

A review of the first version found that flow state was not trustworthy:

- Packets were all counted as outbound, so inbound bytes were always zero.
- The routing hash depended on direction, so a reply could be processed by a different worker than its request.
- The load-balancer and worker stages used the same hash, leaving workers idle for matching counts.
- Closed and evicted flows were deleted, so they vanished from reports.
- Classification used substring matching ("x.com" matched "netflix.com"), mislabelling Netflix and Microsoft as Twitter.
- QUIC extraction was a heuristic that the engine never called.

## Decisions

1. **Symmetric routing hash + initiator-based direction.** Both directions of a conversation map to one `Connection`.
   Direction is "same as the first packet seen", which is wrong only when a capture begins mid-flow.
2. **Independent second-stage hash** for choosing a worker, validated by a test that every (LB, worker) pair receives traffic.
3. **Retirement instead of deletion.** Flows move to a bounded history. Eviction removes the oldest ~1% in one pass
   (a heap-based selection), so inserting into a full table is amortised O(log n) rather than a full scan per packet.
4. **Domain-boundary matching** for applications and rules: a host matches a domain if equal or a true subdomain; a dot-less
   rule keyword matches a whole DNS label.
5. **Bounded TLS ClientHello reassembly.** Only the client's first TLS record, only in-order segments, buffer sized to the record,
   16 KiB cap per flow and 16 MiB per worker. Out-of-order or retransmitted segments abandon reassembly rather than guessing.
6. **QUIC v1 Initial decryption** per RFC 9001 using only JDK crypto, capped at three attempts per flow.
7. **Untrusted hostnames are validated where they enter** instead of being escaped everywhere they leave.

## Consequences

- Reports are complete, and byte directions and classifications are correct. Each decision has a regression test that fails when the old behaviour returns.
- Memory use is bounded under hostile input, at the price of missing SNI for reordered or heavily fragmented handshakes.
- QUIC visibility depends on the first Initial packet containing the SNI; future work is multi-datagram CRYPTO reassembly and QUIC v2.
- A worker's flow table is no longer exact-size: eviction removes a batch, so "active" can briefly drop by about 1% when full.
