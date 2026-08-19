# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
  F5 cookies `ts01`/`ts02` never existed and are replaced with `BIGipServer`,
  `MRHSession` and `LastMRH_Session`.
- Reports named the wildcard pattern (`x-akamai*`) instead of the header actually
  matched.
- Exit codes conflated "no WAF found" with "nothing analyzable"; a parsed response
  with no indicators now exits 0, and only an unusable observation exits 1.

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
- Initial release of WAF Presence Checker (Offline)
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

This is the first public release of WAF Presence Checker, an offline-only tool for analyzing HTTP responses to detect potential WAF/CDN presence.

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
