# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-08-20

### Added
- **Fingerprint database extracted from code into data.** Fingerprints now live in
  `fingerprints/*.yaml`, one file per vendor, carrying per-signal weights, layer
  tags, provenance (`source`) and a required `verified_against` fixture path.
- `tools/build_fingerprints.py` compiles the YAML to `edgeprint/data/fingerprints.json`,
  which is what the engine loads. The runtime keeps zero dependencies (PyYAML is a
  dev dependency only) while contributors get a format with comments. `--check`
  fails if the compiled output is stale, and CI runs it.
- The build step doubles as a validator enforcing the rules that previous bugs came
  from: generic block phrases are rejected as vendor signals, cookie prefixes under
  three characters are rejected, and every signal must name a fixture that exists.
- `fingerprints/SCHEMA.md` documents the format and the reasoning behind each rule.
- Per-signal weights are read from the database with type defaults as fallback, so
  replacing hand-assigned weights with measured likelihood ratios becomes a data
  change rather than a code change.

### Changed
- `edgeprint/fingerprints.py` is now a loader rather than the database itself; it
  exposes `FINGERPRINTS`, `SCHEMA_VERSION`, `vendor_count()` and `signal_count()`.
- The compiled JSON ships in the wheel and is language-neutral, so other tools can
  consume the database without depending on this package.

## [0.2.0] - 2026-08-19

Renamed to **edgeprint** and repositioned from "offline WAF presence checker" to
passive edge fingerprinting over already-captured traffic.

### Fixed
- **Akamai was undetectable.** Fingerprints used exact header keys, so `x-akamai`
  never matched the real `x-akamai-transformed` / `x-akamai-request-id` headers.
  Prefix matching (`x-akamai*`) is now used where vendors suffix their headers.
- **False positives on unprotected origins.** Generic block phrases (`forbidden`,
  `access denied`, `request blocked`) scored as WAF evidence on stock nginx, Apache
  and IIS error pages. They now require an independent corroborating vendor signal.
- **Confidence saturated.** Scores were a raw sum of all indicator weights clamped
  to 1.0; a single vendor matching several signals reached the ceiling immediately.
  Each vendor's contribution is now capped.
- **Incorrect fingerprints.** `visid_incap` was listed as a header (it is a cookie);
  F5 `ts01`/`ts02` were arbitrary instances rather than real cookie patterns
  (BIG-IP ASM does set `TS<hex>` cookies, but `ts` is too short to use as a name
  prefix safely); replaced with `BIGipServer`, `MRHSession`, `LastMRH_Session`.
- Reports named the wildcard pattern (`x-akamai*`) instead of the header actually
  matched.
- Exit codes conflated "no WAF found" with "nothing analyzable"; a parsed response
  with no indicators now exits 0, and only an unusable observation exits 1.

### Fixed in review

Findings from the review of #5, all reproduced before fixing:

- **The block-page corroboration gate could be bypassed.** `request blocked` was
  listed as an Imperva and AWS body signal while also being a generic
  BLOCK_PATTERN, so the phrase corroborated itself: a plain nginx origin serving
  "Request Blocked" reached confidence 0.65 and exited 2. Corroboration now
  requires a vendor above the naming threshold, and generic phrases are no longer
  vendor signals.
- **Repeated headers were overwritten.** Only the last `Set-Cookie` survived, so
  the Imperva fixture's `incap_ses` cookie never matched and real Cloudflare
  responses lost one of `__cf_bm` / `cf_clearance`. Repeats are now joined.
- **The header/body boundary was guessed.** Blank lines were stripped and the
  boundary inferred from the first colon-free line, so a body containing CSS or a
  quoted header was parsed into the header map. The blank line per RFC 7230 is
  now the delimiter.
- **Cookie needles matched values, not names.** Short needles such as `_abck`
  fired on any opaque session value containing them. Cookie names are now parsed
  and matched as name prefixes.
- **`x-waf` was scored twice**, by both the F5 fingerprint and the generic hint,
  letting one header produce a verdict with no vendor named.
- **CDN was reported as WAF.** Fastly and CloudFront caching headers produced
  "WAF LIKELY PRESENT" and exit 2. Detection is now layered (`cdn` / `waf` /
  `bot`) with per-layer confidence, `likely_waf` separate from `likely_edge`, and
  a new exit code 3 for edge presence without WAF evidence.
- **Indicator values were lowercased**, so reported evidence was not verbatim.
- **Apache-2.0 was declared without shipping the license text.** `LICENSE-APACHE`
  and an SPDX header on the fingerprint module now back the claim.
- Tests ignored the manifest's `format` field; `cli.py` and `reporters.py` had no
  coverage at all. Coverage is now 87% with CLI exit codes asserted per fixture.

### Added
- Vendor coverage for AWS CloudFront/WAF and Fastly (8 vendors total).
- `tests/fixtures/` capture corpus with a manifest, covering every supported vendor
  plus negative cases. The test suite is generated from the manifest, and the
  manifest schema is shared with the planned lab and CNAME-labelled corpora.
- CI across Python 3.9-3.13: pytest, mypy, ruff, black.
- `NOTICE` recording upstream attribution, plus two deliberate exclusions:
  WhatWaf (GPL) and JA4S (FoxIO License 1.1).

### Changed
- Package `waf_presence_checker` -> `edgeprint`; command `wafpc` -> `edgeprint`.
- Fingerprint database will ship Apache-2.0; the engine stays MIT.
- README rewritten: roughly half the length, disclaimer bloat removed, honest
  comparison against wafw00f, and explicit limits.

### Known limitations
- HAR parsing still reads only the first entry. Multi-entry and streaming input
  arrive with the corpus-scale engine.
- Confidence weights remain hand-assigned rather than measured.

## [0.1.0] - 2025-01-XX

### Added
- Initial release of edgeprint (Offline)
- Core analysis engine with heuristic-based WAF detection
- Support for multiple input formats (raw headers, JSON, HAR)
- CLI interface with `edgeprint` command
- Fingerprint database for common WAF vendors:
  - Cloudflare (CDN/Edge Firewall)
  - Akamai (Edge Security)
  - Imperva/Incapsula
  - Sucuri Website Firewall
  - ModSecurity
  - F5 ASM/Advanced WAF
- Confidence scoring system (0.0-1.0)
- Multiple output formats (human-readable text, JSON)
- Comprehensive error handling and validation
- Type hints throughout codebase
- Logging support with verbose mode
- Complete documentation:
  - Detailed README with usage examples
  - White paper on methodology
  - Rules of Engagement (ROE) template
  - Contributing guidelines
  - Code of Conduct
  - Security policy
- Development tooling:
  - Black formatter configuration
  - Ruff linter configuration
  - MyPy type checking
  - Pytest configuration
  - Comprehensive .gitignore

### Features
- Offline-only operation (no network requests)
- Deterministic and auditable results
- Exit codes for automation (0=no WAF, 1=indeterminate, 2=WAF detected)
- Transparent rationale for detection decisions
- Vendor guess ordering by confidence
- Support for wildcard header matching
- Body excerpt analysis (limited for safety)
- Auto-format detection based on file extension

### Security
- Input validation for all parsers
- Resource limits (body excerpt size limits)
- Safe error handling without information disclosure
- No external dependencies (Python stdlib only)

### Documentation
- Comprehensive README with:
  - Installation instructions
  - Usage examples
  - Exit code documentation
  - FAQ section
  - Legal disclaimers
- CONTRIBUTING.md with contribution guidelines
- CODE_OF_CONDUCT.md for community standards
- SECURITY.md with responsible disclosure process
- Example input files

---

## Release Notes

### v0.1.0 - Initial Public Release

This is the first public release of edgeprint, an offline-only tool for analyzing HTTP responses to detect potential WAF/CDN presence.

**Key Highlights:**
- ✅ Completely offline operation
- ✅ Zero external dependencies
- ✅ Comprehensive documentation
- ✅ Production-ready code quality
- ✅ Strong ethical and legal guidelines

**Important:** This tool is designed for authorized security testing only. Always obtain proper authorization before collecting or analyzing HTTP traffic.

**Next Steps:**
- Review the README.md for usage instructions
- Read SECURITY.md for responsible disclosure guidelines
- Check CONTRIBUTING.md if you'd like to contribute
- Review docs/ROE_TEMPLATE.md for engagement planning

---

## Version History

- **0.1.0** (2025-01-XX) - Initial public release
