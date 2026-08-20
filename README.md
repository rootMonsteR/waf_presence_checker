# edgeprint

Fingerprints WAF, CDN and edge protection from **HTTP responses you have already captured**. No network traffic, no live target, no rate limits.

Active scanners answer *"what is in front of this one host, right now?"* — and [wafw00f](https://github.com/EnableSecurity/wafw00f) answers it well, across 200+ products. edgeprint answers a different question: *"what is the edge-protection posture across every response in this capture?"* — a HAR export, a proxy log, a recon pipeline's output, an incident-response archive.

That makes it complementary to the active tools, not a replacement for them.

> **Status: early.** 8 vendor fingerprints against wafw00f's 200+. The detection engine is heuristic and uncalibrated. See [Roadmap](#roadmap) for where this is going and [Limits](#limits) for what it cannot do.

## Install

```bash
pip install -e .
```

Python 3.9+. No runtime dependencies.

## Use

```bash
# Capture from an authorized target, or use traffic you already have
curl -i https://example.com > response.txt

edgeprint analyze -i response.txt              # format auto-detected
edgeprint analyze -i capture.har --format har
edgeprint analyze -i response.txt --json
```

```
Edge protection: EDGE/CDN PRESENT, NO WAF EVIDENCE (confidence=0.70)
Layers: cdn=0.70, bot=0.70
Possible vendors: Akamai (edge)
Rationale: Vendor hints: Akamai (edge) (0.70); Headers: server, x-akamai-transformed, x-check-cacheable; Cookies: ak_bmsc
Indicators:
  - [0.25] header:server :: server :: Akamai (edge) hint
  - [0.25] header:x-akamai-transformed :: x-akamai-transformed :: Akamai (edge) hint
  - [0.25] header:x-check-cacheable :: x-check-cacheable :: Akamai (edge) hint
  - [0.20] cookie :: ak_bmsc :: Akamai (edge) cookie hint
```

**Layers are reported separately, because a CDN is not a WAF.** Akamai serving your traffic proves a CDN edge and, via `ak_bmsc`, bot management — it does not prove request filtering. Most tools collapse all of this into "WAF detected"; edgeprint does not.

**Input formats:** raw `curl -i` dumps, JSON observations, HAR exports (Burp, ZAP, browser DevTools).

**Exit codes:** `0` nothing detected · `1` nothing analyzable · `2` WAF likely present · `3` edge/CDN present, no WAF evidence.

## Detected

| Layer | Vendors |
|---|---|
| CDN | Cloudflare · Akamai · AWS CloudFront · Fastly |
| WAF | Imperva/Incapsula · Sucuri · ModSecurity · F5 BIG-IP ASM · AWS WAF |
| Bot management | Akamai Bot Manager |

Every fingerprint is backed by a capture in [`tests/fixtures/`](tests/fixtures/) and asserted in CI. Coverage is deliberately narrow and verified rather than broad and untested — that ratio is the point, and it will change as the fingerprint database lands.

## How it works

Headers, cookies and body markers are matched against the fingerprint database; matches accumulate into a per-vendor score.

Three properties worth knowing, because most tools in this space have none of them:

- **Layers are separated.** CDN, WAF and bot management are distinct controls. A Fastly-cached host reports `cdn`, not `waf`, and exits 3 rather than 2.
- **Generic block pages need corroboration.** `request blocked` / `access denied` / `forbidden` count only when a vendor has been *independently identified* — and a phrase that generic is never itself treated as vendor evidence, or it would corroborate itself.
- **No single vendor can saturate the score.** Each vendor's contribution is capped, so a vendor matching four header signals does not automatically produce total confidence.

## Limits

Passive analysis reads what the edge already told you. It cannot see rule sets, rate-limit thresholds, bot-management configuration, or whether a WAF is in block or detect-only mode — those need active probing, and [wafw00f](https://github.com/EnableSecurity/wafw00f) or [identYwaf](https://github.com/stamparm/identYwaf) are the right tools for it.

Confidence scores are currently **hand-assigned, not measured**. Treat `0.70` as "several signals agreed", not as a 70% probability. Fixing this is the main point of the roadmap.

## Roadmap

1. ~~Credibility: verified fixtures, CI, honest scope~~ ✅
2. ~~**Fingerprint database** — per-vendor files with per-signal weights, layers and provenance, in a language-neutral format~~ ✅ *(aggregation from upstream databases still to come)*
3. **WAF lab** — Docker stack running real WAFs (ModSecurity, Coraza, SafeLine, BunkerWeb…) to generate ground truth with *known* labels rather than inferred ones
4. **Benchmark** — the first published precision/recall figures for WAF detection, scoring edgeprint against wafw00f, wafme0w and identYwaf on a labelled corpus. Existing WAF benchmarks measure whether a WAF blocks attacks; none measure whether detection tools are correct
5. **Calibrated engine** — replace hand-assigned weights with likelihood ratios measured from lab and corpus data

## The fingerprint database

Fingerprints live in [`edgeprint/data/fingerprints/`](edgeprint/data/fingerprints/) as one plain JSON file per vendor, each signal carrying a weight, layer tag, provenance `source` and a required `verified_against` fixture path.

No build step and no compiled artifact: the files are read directly at import, so what you review is what ships. JSON rather than YAML keeps the runtime at **zero dependencies**, and a `notes` field carries what comments would have. The format is language-neutral by design — other tools can consume the database without depending on this package.

Validation runs as part of the test suite rather than a separate build command, so `pytest` alone rejects the mistakes past bugs came from: generic block phrases used as vendor signals, cookie prefixes short enough to match opaque session values, and any signal without an existing fixture. See [`docs/FINGERPRINT_SCHEMA.md`](docs/FINGERPRINT_SCHEMA.md).

```bash
./check.sh   # tests, types, lint, format — everything CI would run
```

## Contributing

New fingerprints are welcome and must arrive with a capture: add the response to `tests/fixtures/`, a row to `tests/fixtures/manifest.json`, and a signal to the vendor's JSON file. The test suite is generated from the manifest, so there is no test code to write. Fingerprints without a fixture will not be merged — that rule is what keeps the database honest.

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Attribution and licensing

Engine: MIT (see [LICENSE](LICENSE)). Fingerprint database (`edgeprint/fingerprints.py`): Apache-2.0 (see [LICENSE-APACHE](LICENSE-APACHE)), because it aggregates BSD-3-Clause, MIT and Apache-2.0 material and Apache-2.0 is the only one of the three that absorbs the others coherently.

Upstream projects and their attribution requirements are recorded in [NOTICE](NOTICE), including two deliberate exclusions: **WhatWaf** (GPL — cannot be relicensed into this compilation) and **JA4S** (FoxIO License 1.1 — not permissive for monetization).

## Responsible use

Analyze only traffic you are authorized to possess. This tool reads files you give it and makes no requests of its own, but that does not make the underlying capture lawful — authorization is your responsibility.
