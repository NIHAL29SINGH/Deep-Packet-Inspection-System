# Security policy

DPI Sentinel parses untrusted network data, so parser and report-safety bugs are treated as
security issues.

## Reporting a vulnerability

Please report suspected vulnerabilities privately through GitHub's
"Report a vulnerability" button (Security tab -> Advisories) instead of opening a public issue.
Include a minimal PCAP or byte sequence that reproduces the problem if you can.
Expect an acknowledgement within a few days.

## Scope

In scope: crashes, hangs or unbounded memory use triggered by a crafted capture; output that
lets packet-derived text break out of the HTML/JSON/CSV reports; rule-matching bypasses.

Out of scope: the documented limitations in the README (for example, no general TCP
reassembly), and misuse against networks you are not authorised to monitor.

## Design notes

See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for trust boundaries and the controls in place
(bounded queues, bounded reassembly memory, hostname validation, output escaping, loopback-only
metrics by default).
