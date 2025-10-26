# White Paper (Lite): Estimating WAF Presence from Captured HTTP Responses

**Status:** Informational.  
**Scope:** Offline analysis only. This document avoids scanning and evasion advice.

## 1. Motivation

Before running intrusive tests, teams often want a quick sense of whether a target’s traffic transits a **web application firewall (WAF)** or edge security layer. That knowledge informs test plans, risk discussions, and communications with the client’s blue team. This project offers a conservative, offline-only estimator based on captured HTTP responses (e.g., `curl -i`, HAR files).

## 2. Definitions

- **WAF/Edge Firewall**: An intermediary that inspects and controls HTTP(S) requests/responses against policies (bot management, L7 DDoS, OWASP rules, custom whitelists).  
- **Indicator**: An observable hint associated with WAF presence (header name/value, cookie prefix, status text, or body phrase on error pages).  
- **Confidence**: A normalized 0–1 score derived from multiple indicators. It is not a probability and should be interpreted as a heuristic strength, not a guarantee.

## 3. Design Principles

1. **Offline-first**: The tool only analyzes files you supply. This reduces misuse and allows audits.  
2. **Transparency**: Each indicator carries a weight and a note; the report lists them all.  
3. **Conservatism**: Vendor “guesses” are hints, not declarations. Many CDNs and WAFs allow fully custom headers that remove fingerprints.  
4. **No evasion**: The project intentionally avoids advising on bypass or stealth.

## 4. Signals and Heuristics

We consider three classes of signals, each treated as **evidence**, not proof:

- **Header and cookie names/values**: For example, public header names associated with well-known providers (e.g., `cf-ray`, `x-sucuri-id`, `x-iinfo`). Weights are modest to limit false positives.  
- **Server identity hints**: Tokens like `server: cloudflare` or `server: akamai` add weight, recognizing that organizations may mask or alter them.  
- **Body phrases on error pages**: Some providers inject branded phrases on block pages. Only short, generic phrases are used here to avoid overfitting.

These are combined into a **confidence score** by summing capped weights. Above ~0.60 we return “likely present.”

## 5. Data Sources

Artifacts suitable for analysis include:
- `curl -i` output (`-I` for headers-only or full headers with `-i`), saved to a file.  
- Browser HAR exports (e.g., DevTools > Network > Save all as HAR with content).  
- JSON “observations” produced by your internal tooling.

## 6. Validation Approach (Recommended)

- **Lab validation**: Generate observations from known demo properties in your lab where WAFs are explicitly enabled/disabled. Check that the tool’s confidence changes in the expected direction.  
- **Cross-check**: Compare with server-side telemetry (e.g., reverse proxy logs) to confirm intermediaries.  
- **Negative controls**: Observe responses from minimal origin servers with no intermediaries to measure base false positive rate.

## 7. Limitations and Edge Cases

- **Header normalization**: Case folding mitigates but doesn’t eliminate variability.  
- **Header stripping**: Many enterprises strip or rename identifying headers. Absence of a fingerprint does **not** prove there is no WAF.  
- **Shared controls**: A CDN may front only certain paths, hosts, or times of day. A single response can’t capture dynamic routing.  
- **Block-page ambiguity**: Phrases like “request blocked” may come from custom middleware.

## 8. Ethical & Legal Considerations

- Always obtain **written authorization** with a clear **Rules of Engagement (ROE)**.  
- Prefer **offline** analysis first; then, if needed, implement a **rate-limited, auditable collector** inside your environment that enforces ROE.  
- Coordinate with the blue team and change management to avoid false alarms.  
- Respect privacy and data minimization; never store full sensitive payloads in analysis artifacts.

> This document is informational and not legal advice. Consult counsel for your jurisdiction.

## 9. Integrating into a Pipeline

- Treat the analyzer as a **pre-flight gate**: if confidence is high, tune subsequent testing plans (notify client, set expectations).  
- Emit machine-readable JSON and attach to ticketing systems.  
- Keep fingerprints and weights in version control. Require peer review for changes.

## 10. Future Work

- Expand fingerprints via peer-reviewed, publicly-documented indicators.  
- Statistical calibration of the confidence threshold on larger corpora.  
- Optional vendor self-identification via the `security.txt` ecosystem when/if standardized for intermediaries.

---

_Authored: 2025-10-21_
