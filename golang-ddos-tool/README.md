# Golang DDoS Simulation Tool

This folder contains a proof‑of‑concept tool written in Go that demonstrates how to simulate two classic application‑layer DoS techniques:

1. **HTTP/2 Rapid Reset (CVE‑2023-44487)** – abuse of HTTP/2's ability to send many `HEADERS` frames followed immediately by `RST_STREAM` frames, causing excessive server‑side work with minimal bandwidth.
2. **Slowloris** – opening many concurrent connections and sending partial HTTP headers, keeping the connections alive and exhausting the server's connection pool.

The tool uses goroutines for concurrency and optionally integrates with [Vegeta](https://github.com/tsenart/vegeta) for metrics collection (the current skeleton focuses on the raw attack logic; you can extend it to export Vegeta attack results).

## Prerequisites

- Go 1.22 or later
- (Optional) For vegeta integration: `go install github.com/tsenart/vegeta/v12@latest`

## Building

```bash
cd golang-ddos-tool
go build -o ddos-tool .
```

## Usage

```bash
# HTTP/2 Rapid Reset simulation
./ddos-tool -target https://example.com:443 -mode rapidreset -conns 200 -duration 2m

# Slowloris simulation
./ddos-tool -target http://example.com:80 -mode slowloris -conns 500 -duration 5m
```

### Flags

| Flag          | Description                                              | Default                |
|---------------|----------------------------------------------------------|------------------------|
| `-target`     | Target URL (must include scheme)                         | `https://localhost:8443` |
| `-mode`       | Attack mode: `rapidreset` or `slowloris`                 | `rapidreset`           |
| `-conns`      | Number of concurrent goroutines / connections            | `100`                  |
| `-duration`   | How long the attack should run                           | `30s`                  |

**Note:** This tool is intended for **authorized security testing only**. Running it against systems without explicit permission is illegal and unethical.

## Extending the Tool

- Add proper atomic counters for requests sent, errors, etc.
- Integrate Vegeta's `Attacker` to collect latency/success metrics.
- Implement TLS certificate validation (remove `InsecureSkipVerify` for production testing).
- Add support for HTTP/1.1 pipelining or other techniques (e.g., Slow Read).
- Output results to JSON/CSV for post‑processing.

## Disclaimer

The authors assume no liability for misuse. Use this code solely in controlled environments (e.g., your own lab, bug‑bounty programs with explicit consent, or authorized red‑team engagements).

