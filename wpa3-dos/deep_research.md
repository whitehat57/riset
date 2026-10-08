# Deep Research: WPA3‑SAE Denial of Service (Resource Exhaustion)

**Source**: NCC Group Whitepaper – “WPA3 Denial of Service: SAE Resource Exhaustion”  
**URL**: https://www.nccgroup.com/research/wpa3-denial-of-service-sae-resource-exhaustion  
**Fetched**: 2025‑09‑16 via r.jina.ai (markdown conversion)  
**Local file**: `~/riset/wpa3-dos/article.md`

---

## 1. Executive Summary

WPA3‑Personal replaces the PSK‑based authentication of WPA2 with **Simultaneous Authentication of Equals (SAE)**, a Dragonfly‑based password‑authenticated key exchange. While SAE eliminates offline password cracking, it introduces a new **availability attack surface**: an unauthenticated client can force the Access Point (AP) to perform costly cryptographic operations and maintain state before the peer is authenticated.

The paper surveys two families of attacks:

| Attack | Core Idea | Target |
|--------|-----------|--------|
| **Dragon Drain** | Flood AP with forged SAE Commit frames → expensive processing | SAE Commit validation & cryptographic workload |
| **Cookie Guzzler** (Muted Peer / Hasty Peer) | Reuse valid SAE Scalar/Element from a failed authentication to bypass early validation, then keep AP engaged via Anti‑Clogging Mechanism (ACM) | SAE ACM and state‑management logic |
| **Other generic attacks** (Doppelganger, PMK Gobbler, Memory Omnivore, Double‑Decker, Amplification, Open Auth abuse) | Various state‑handling, retransmission, and resource‑management flaws | AP SAE implementation specifics |

The research shows that while **Dragon Drain** is largely mitigated on maintained hardware (patches, firmware updates), **Cookie Guzzler** and related generic attacks remain **under‑addressed** because they exploit defensive mechanisms (the ACM) rather than raw cryptographic cost. The availability of easy‑to‑use plugins (airgeddon) has lowered the exploitation barrier, making renewed vendor attention essential.

---

## 2. Technical Background

### 2.1 SAE Handshake Overview
1. **Commit Exchange** – Each peer sends a scalar and an elliptic‑curve element (or finite‑field element) derived from the password and the selected group.
2. **Confirm Exchange** – Proof that both peers derived the same shared secret.

Processing of the Commit requires:
- Group validation (point‑on‑curve, scalar range)
- Elliptic‑curve scalar multiplication (expensive)
- Hash‑to‑curve and derivation of the secret

### 2.2 Anti‑Clogging Mechanism (ACM)
- When an AP detects a high number of pending SAE exchanges, it stops accepting new expensive Commit frames.
- Instead, it requires the client to return an **anti‑clogging token** (a lightweight challenge) before continuing.
- Intended to limit unauthenticated resource consumption, but introduces its own state, validation, and retransmission logic — new attack surface.

---

## 3. Attack Details

### 3.1 Dragon Drain
- **Method**: Spoofed MAC addresses send malformed or randomly crafted SAE Commit frames.
- **Effect**: Forces AP to perform point validation and scalar multiplication for each frame.
- **Outcome**: High CPU usage, possible service degradation.
- **Limitations**: Originally required `ath_masker` kernel module (Atheros). Later adapted via airgeddon plugin to support more chipsets.
- **Current Status**: Most modern, maintained APs have patched or changed SAE implementation to limit work per connection; still viable on legacy or poorly maintained devices.

### 3.2 Cookie Guzzler
- **Core Insight**: Reuse a **valid** SAE Commit (correct scalar & element) obtained from a legitimate but failed authentication (wrong password). This passes early validation, pushing the AP deeper into SAE processing.
- **Two Variants**:
  1. **Muted Peer** – After sending the Commit, the attacker goes silent; the AP may retransmit and retain state, amplifying work per attacker packet.
  2. **Hasty Peer** – Attacker continues protocol interaction (e.g., sends Confirm or reacts to ACM) to drive extra work.
- **Why it beats ACM**: The ACM sees the Commit as valid (not “clogging”) and proceeds with token exchange or state maintenance, consuming resources.
- **Tooling**: Public airgeddon plugin automates Muted Peer capture/reuse and packet generation.
- **Mitigation Gap**: No widespread vendor‑specific patch noted as of 2026; defenses rely on generic resource limits or higher‑end hardware.

### 3.3 Other Generic Attacks (from Chatzoglou *et al.*)
- **Doppelganger** – Duplicate SAE state to cause confusion.
- **PMK Gobbler** – Exhaust PMK cache by forcing many distinct SAE sessions.
- **Memory Omnivore** – Allocate large buffers via malformed fragments.
- **Double‑Decker** – Two‑stage attack that first triggers ACM then exploits its state.
- **Amplification** – Small attacker packet generates large AP response (e.g., via retransmissions).
- **Open Authentication abuse** – Legacy open‑auth still present on some APs, used as a stepping stone.

---

## 4. Impact Assessment

| Metric | Dragon Drain | Cookie Guzzler | Other Generic |
|--------|--------------|----------------|---------------|
| **Required knowledge** | Low (packet forge) | Medium (understand SAE & ACM) | Medium‑High (protocol nuances) |
| **Hardware dependency** | Originally Atheros, now broader | Any Wi‑Fi card capable of monitoring/injecting | Varies |
| **Amplification** | 1:1 (each forged Commit = AP work) | >1 (AP does extra work per Commit due to state/ACM) | Variable; some >1 |
| **Detection** | High CPU, many SAE Commit frames | High CPU + many SAE exchanges + ACM token exchanges | Depends on specific flaw |
| **Current mitigation** | Patches, firmware updates, rate‑limit SAE | Largely unmitigated; rely on general load‑balancing | Patch‑specific per vendor |

---

## 5. Mitigation Strategies

### 5.1 AP‑Side (Vendor/Administrator)
1. **Rate‑limit SAE Commit attempts per MAC/IP** (e.g., max X Commit/sec) before ACM engages.
2. **Strict validation** of scalar/element *before* allocating heavy crypto objects; reject early if out‑of‑range.
3. **Limit pending SAE state**: timeout half‑opened exchanges quickly (e.g., <200 ms).
4. **ACM hardening**:
   - Ensure token generation/validation is cheap and does not allocate large structures.
   - Log and rate‑limit token requests.
   - Consider disabling ACM for troubleshooting (if safe) and replace with explicit connection limits.
5. **Monitoring & Alerts**:
   - Track ratio of `SAE Commit` to `SAE Confirm` or `EAPOL‑Start`.
   - Alert on spikes in SAE state table size or ACM token issuance.
   - Use SNMP/Telemetry or AP‑provided stats (e.g., hostapd `sae_query_count`).
6. **Firmware Hygiene**:
   - Keep AP firmware updated; prioritize patches that address SAE DoS (check vendor release notes for CVE‑like IDs).
   - For open‑source APs (hostapd, OpenWrt), apply latest commits from the `hostapd` tree (see `wpa_supplicant`/`hostapd` SAE hardening patches).

### 5.2 Client‑Side (Defensive)
- Not directly applicable; mitigation lies on AP/infrastructure.
- For network operators, consider **client isolation** and **VLAN segregation** to limit impact of a compromised client.

### 5.3 Research / Testing
- Use **airgeddon** plugins (`dragon-drain-wpa3-airgeddon-plugin`, `cookie-guzzler`) for controlled lab testing.
- Verify that AP drops or rate‑limits excessive SAE Commit after a threshold.
- Test with both **Atheros** and **non‑Atheros** adapters to confirm broad applicability.

---

## 6. Lab Setup (Authorized Testing)

1. **Equipment**:
   - Laptop with dual Wi‑Fi adapters (one for injection/monitoring, one for normal connection).
   - Compatible drivers supporting monitor mode and packet injection (e.g., ath9k, rtl88xx, or use a USB‑NIC with appropriate driver).
   - Target AP running WPA3‑Personal (preferably a device you own or have permission to test).
2. **Software**:
   - `airgeddon` (latest) from https://github.com/v1s1t0r1sh3r3/airgeddon
   - Plugins:
     - `dragon-drain-wpa3-airgeddon-plugin`
     - `cookie-guzzler` (Muted Peer) from https://github.com/OscarAkaElvis/airgeddon-plugins
   - Optional: `tshark` / `Wireshark` for traffic inspection.
3. **Procedure**:
   - Put adapter into monitor mode.
   - Launch airgeddon → select “WPA3 Attacks” → choose Dragon Drain or Cookie Guzzler.
   - For Cookie Guzzler, first capture a valid SAE Commit from a legitimate (wrong‑password) attempt using the second adapter, then replay.
   - Observe AP CPU usage (via `top`, `htop`, or AP’s built‑in stats).
   - Record number of SAE Commit frames vs. AP responses.
4. **Safety**:
   - Limit test duration to avoid disrupting neighboring networks.
   - Perform in a Faraday cage or isolated test environment if possible.
   - Ensure you have explicit permission from the AP owner/administrator.

---

## 7. References & Further Reading

- NCC Group Whitepaper: **WPA3 Denial of Service: SAE Resource Exhaustion** (source article).  
- Chatzoglou, E., Kambourakis, G., Kolias, C. – *“How is your Wi‑Fi connection today? DoS attacks on WPA3‑SAE”*, *Computers & Security*, 2022. DOI: 10.1016/j.cose.2021.10243X.  
- Vanhoef, M., Ronen, E. – *“Dragonblood: A Security Analysis of WPA3’s SAE Handshake”*, 2019. https://papers.mathyvanhoef.com/dragonblood.pdf  
- Original Dragon Drain implementation: https://github.com/vanhoefm/dragondrain-and-time  
- airgeddon project: https://github.com/v1s1t0r1sh3r3/airgeddon  
- Dragon Drain airgeddon plugin: https://github.com/Janek79ax/dragon-drain-wpa3-airgeddon-plugin  
- Cookie Guzzler airgeddon plugin: https://github.com/OscarAkaElvis/airgeddon-plugins#airgeddon-wpa3-cookie-guzzler  
- hostapd/wpa_supplicant SAE hardening commits (search for “SAE DoS” or “anti‑clogging” in the mailing list).  
- CVE‑2023‑44487 (HTTP/2 Rapid Reset) – unrelated but useful as an example of protocol‑level DoS for cross‑reference.  

---

## 8. Conclusion

WPA3‑SAE’s design goal of thwarting offline password cracking succeeded, yet it shifted the security burden from confidentiality to **availability**. Early attacks like Dragon Drain showed that merely increasing computational work could destabilize an AP. Later research revealed that defensive mechanisms—most notably the **Anti‑Clogging Mechanism**—can be subverted to amplify resource consumption with minimal attacker effort.

The current landscape is uneven: well‑maintained, newer APs have largely patched the low‑hanging fruit (Dragon Drain), whereas attacks that exploit the ACM or intricate state handling (Cookie Guzzler and peers) remain **under‑defended**. The emergence of user‑friendly tooling (airgeddon plugins) lowers the exploitation barrier, increasing the likelihood that these issues will be encountered in real‑world deployments.

For defenders, the prescribed actions are:
- Keep AP firmware current and monitor vendor release notes for SAE‑specific fixes.
- Implement per‑client/per‑MAC SAE Commit rate limits and aggressive timeout of half‑opened states.
- Monitor SAE‑related metrics (commit/confirm ratios, ACM token issuance) for anomalies.
- Consider lab validation with airgeddon before trusting a device in a production environment.

Continued research, responsible disclosure, and vendor engagement are essential to ensure that the cryptographic gains of WPA3 are not undermined by easily‑executable denial‑of‑service vectors.

--- 

*Last updated: 2025‑09‑16*  
*Author: [Your Name / Research Team]*  