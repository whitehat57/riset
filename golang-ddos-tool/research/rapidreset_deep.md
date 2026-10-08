# Deep Research: HTTP/2 Rapid Reset (CVE-2023-44487)

## Overview
HTTP/2 Rapid Reset is a denial-of-service vulnerability affecting HTTP/2 implementations. It allows an attacker to cause excessive server-side work by abusing the stream cancellation mechanism (RST_STREAM frames) while keeping the connection open, leading to high CPU/memory consumption with minimal network traffic.

**CVE**: CVE-2023-44487  
**Published**: October 2023  
**Affected**: Many HTTP/2 servers (e.g., nginx, Apache Tomcat, Jetty, Envoy, Envoy-based proxies like Istio, Cloudflare, AWS ALB, etc.) and libraries (golang.org/x/net/http2 prior to fix, etc.).

## Technical Details

### HTTP/2 Primer
- HTTP/2 is a binary, multiplexed protocol. Multiple streams (logical request/response exchanges) share a single TCP connection.
- Each stream is identified by a stream ID and can be in states: idle, reserved, open, half-closed, closed.
- Endpoints can send `WINDOW_UPDATE` frames to advertise flow‑control credit.
- To cancel a stream, an endpoint sends an `RST_STREAM` frame with an error code (e.g., `CANCEL`, `REFUSED_STREAM`, `INTERNAL_ERROR`).

### The Attack Idea
1. **Open many streams** (by sending `HEADERS` frames) – each consumes server resources (allocating request object, parsing headers, possibly applying WAF rules, etc.).
2. **Immediately cancel each stream** by sending an `RST_STREAM` frame *before* the server has a chance to send a response (or even before it finishes parsing headers).
3. Because the stream is cancelled, the server may discard the request early, but many implementations still performed significant work up to the point of receiving the RST (e.g., header decompression, HPACK table updates, memory allocation for request structs, logging, WAF inspection).
4. The attacker can pipeline these HEADERS+RST_STREAM pairs back‑to‑back without waiting for acknowledgments, causing the server to process work at a rate limited only by its ability to read from the TCP socket, not by network bandwidth.

### Why It’s Effective
- **Amplification**: A single TCP connection can generate thousands of streams per second. The attacker’s outbound bandwidth is roughly the size of HEADERS + RST_STREAM (~100 bytes each) → a few hundred kbps can cause megabytes/second of server-side work.
- **Stealth**: Traffic looks like normal HTTP/2 (valid frames). No malformed packets; many DDoS mitigation systems that look for abnormal volume, malformed requests, or known attack signatures may not trigger.
- **Connection Persistence**: The connection stays open, so the attacker does not need to perform expensive TCP handshakes repeatedly.

### Affected Components
- **HTTP/2 server core** (stream handling, HPACK decoder).
- **WAF / security modules** that inspect headers per stream.
- **Logging / metrics** subsystems that allocate per‑request structures.
- **Application frameworks** that create request/context objects on stream open.

### Mitigation Strategies (Server‑Side)
1. **Limit concurrent streams per connection** (e.g., `max_concurrent_streams` SETTINGS frame). Lower values reduce the blast radius.
2. **Rate‑limit RST_STREAM frames** – track number of RST_STREAM received per connection and throttle or close connection if exceeding a threshold.
3. **Early stream cancellation cleanup** – ensure that when an RST_STREAM is received, any allocated request resources are released promptly and that no further processing (e.g., WAF, logging) continues.
4. **Enable HTTP/2 timeout on idle streams** – if a stream is opened but not progressed (no DATA) within a short window, close it.
5. **Deploy upstream protections** – Cloudflare, AWS WAF, etc., have released specific rules to detect rapid reset patterns (excessive RST_STREAM).
6. **Upgrade libraries** – Use patched versions of HTTP/2 libraries (e.g., golang.org/x/net/http2 v0.13.0+, nginx 1.25.2, etc.).

### Detection (Network‑Side)
- Monitor for high ratio of `RST_STREAM` frames to `HEADERS` frames per connection.
- Alert when a single connection opens > N streams (e.g., 1000) within a short time window (<10s) and sends RST_STREAM for most of them.
- Use Zeek/Bro scripts or Suricata rules to detect abnormal HTTP/2 frame patterns.

## Go Implementation Notes
The `golang.org/x/net/http2` package (prior to the fix) allocated request data structures upon receiving `HEADERS` and performed HPACK decoding. Sending an `RST_STREAM` shortly after would stop further processing, but the initial allocation and header decode still occurred.

A simple proof‑of‑concept in Go:
```go
import (
    "golang.org/x/net/http2"
    "golang.org/x/net/http2/hpack"
)

// Create a HEADERS frame (using hpack encoder)
// Immediately follow with an RST_STREAM frame with stream ID same as headers.
// Repeat rapidly on the same connection.
```
After the fix (CL: https://go.dev/cl/xxxx), the http2 server now discards incoming streams faster and does not allocate request state for streams that are reset before any meaningful processing.

## References
1. CVE-2023-44487 – https://nvd.nist.gov/vuln/detail/CVE-2023-44487
2. Cloudflare Blog: “HTTP/2 Rapid Reset” – https://blog.cloudflare.com/ http2-rapid-reset/
3. Google oss-security: “HTTP/2 Rapid Reset (CVE-2023-44487)” – https://security.googleblog.com/2023/10/http2-rapid-reset-cve-2023-44487.html
4. Envoy proxy issue: https://github.com/envoyproxy/envoy/issues/xxxx
5. nginx security advisory: http://nginx.org/en/security_advisories.html
6. golang.org/x/net/http2 changelog: https://pkg.go.dev/golang.org/x/net/http2#pkg-notes

## Lab Setup for Testing (Authorized)
1. Run a vulnerable HTTP/2 server (e.g., nginx <1.25.2 with HTTP/2 enabled) in a Docker container.
2. Use the Go tool from `golang-ddos-tool/main.go` (rapidreset mode) against the server.
3. Monitor server CPU/memory usage (e.g., via `docker stats` or `top`).
4. Verify that after applying mitigation (e.g., lowering `max_concurrent_streams` or patching), the attack effect diminishes.

## Conclusion
HTTP/2 Rapid Reset demonstrates how abuse of legitimate protocol features can lead to high‑impact DoS. Defenses must focus on per‑connection stream management, rapid detection of anomalous RST_STREAM behavior, and keeping HTTP/2 libraries up to date. Ongoing research should explore automated detection via machine learning on frame timing and consider protocol‑level enhancements (e.g., mandatory stream‑level ratelimiting).

