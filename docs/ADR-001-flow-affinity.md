# ADR-001: Preserve flow affinity with hash routing

## Decision

Route each packet to a load balancer and fast-path queue using the hash of its five-tuple.

## Rationale

Connection classification and blocking are stateful. Sending packets from one flow to
different workers would require a shared mutable connection table and introduce more
locking. Hash routing keeps the common path local to one tracker while retaining
parallelism across independent flows.

## Implementation notes

- The routing hash is **direction-independent** (`FiveTuple.symmetricHash()`): the endpoints are ordered
  before hashing, so request and reply packets reach the same worker and share one `Connection`.
- The load balancer and the fast-path worker are chosen from **different bits** of the hash
  (`symmetricHash()` vs `fastPathHash()`). Using one hash for both stages makes `hash % lbs` and
  `hash % fps` correlated, which leaves some workers permanently idle.
- A `Connection` records its initiating direction; `Connection.isOutbound(tuple)` decides whether a packet
  counts toward `bytesOut` or `bytesIn`.

## Trade-offs

- A hot flow can be unevenly distributed.
- The current engine has bounded queues and explicit drain completion.
- A future adaptive scheduler can rebalance only at flow boundaries.
