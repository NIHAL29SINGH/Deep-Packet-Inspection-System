# Benchmarks

These are measurements, not marketing. They were taken in a small sandbox, so treat them as a baseline you can
reproduce on your own hardware rather than as a throughput claim.

## Environment

| | |
| --- | --- |
| CPU | 1 shared vCPU, Intel Xeon @ 2.10 GHz |
| Memory | about 3 GB |
| OS / JVM | Linux 6.x, OpenJDK 21 |
| Input | `generate_sample_pcap.py <file> 6000`: 102,731 inspected packets (seed 1337, deterministic), 31.2 MB as pcap and 33.0 MB as pcapng |
| Work per packet | flow tracking, SNI/Host/DNS extraction, QUIC Initial decryption, JA3, TLS reassembly, rules, latency histogram |

Because there is **one** vCPU, the multi-worker configurations cannot run in parallel; they only show the cost of
thread coordination. **No multi-core scaling claim is made.** Re-run `./dpi benchmark` on a multi-core machine to measure that.

## Results

Cold JVM, one process per run (this is what the CLI does, so it includes JIT warm-up). Five runs each, packets per second:

| Input | Configuration | Runs (k pps) | Median |
| --- | --- | --- | --- |
| pcap | 1 LB x 1 worker | 28.0, 31.5, 32.3, 36.6, 37.2 | **32.3k pps** |
| pcap | 2 LB x 2 workers | 28.4, 30.7, 33.3, 34.3, 36.5 | **33.3k pps** |
| pcapng | 1 LB x 1 worker | 30.1, 30.3, 30.4, 31.0, 31.1 | **30.4k pps** |
| pcapng | 2 LB x 2 workers | 27.3, 28.2, 28.6, 29.1, 31.5 | **28.6k pps** |

Warm JVM, nine consecutive runs inside one process, 1 LB x 1 worker:

| Input | Min | Median | Max |
| --- | --- | --- | --- |
| pcap | 42.2k | **80.9k pps** | 104.1k |
| pcapng | 31.4k | **84.7k pps** | 114.7k |

## How to read this

- Run-to-run variance on a shared vCPU is large (a 25-40% spread across five runs), so differences smaller than that are noise.
  In particular, pcap and pcapng read at **about the same speed**, and 1x1 versus 2x2 workers is not distinguishable on one core.
- An earlier comparison with the original (pre-fix) version, on an older and simpler capture, was also indistinguishable within noise
  (median about 33k versus 39k packets/s cold). That capture exercised less work per packet, so it is not directly comparable with the table above.
  The fixes and features were for correctness and capability, not speed; nothing here claims a speed-up.
- The reader now uses buffered I/O. An intermediate measurement suggested a warm-throughput gain, but it did not reproduce on the final, heavier
  workload, so no gain is claimed.
- On one core, 2x2 workers cannot beat 1x1 because six threads share one CPU. That is expected, not a defect.
- Latency percentiles come from a log-scale histogram (about 6% resolution), not exact sorting.

## Reproduce

```bash
python3 Packet_analyzer-main/generate_sample_pcap.py /tmp/bench.pcap 6000
python3 Packet_analyzer-main/generate_sample_pcap.py /tmp/bench.pcapng 6000
./dpi benchmark /tmp/bench.pcap          # writes Packet_analyzer-main/java-port/outputs/benchmark.csv
```

## What is not measured

Detection precision/recall on labelled traffic, behaviour above about 100k flows per worker (eviction path), behaviour on very large pcapng files,
and multi-core scaling.
