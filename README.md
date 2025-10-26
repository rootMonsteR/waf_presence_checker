# WAF Presence Checker (Lite, Offline)

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

**Purpose:** Estimate whether a captured HTTP response likely came from an origin protected by a **Web Application Firewall (WAF)**, CDN edge firewall, or similar security control — *without sending any network traffic*.

This project is intentionally **offline-only** to support:
- 🔍 Forensic analysis of captured traffic
- 📋 Pre-engagement reconnaissance planning
- 🛡️ Security posture assessment
- 📊 Compliance documentation

By design, this tool **does not** send network requests, helping to minimize misuse and encourage compliance with **Rules of Engagement (ROE)**.

---

## ⚠️ IMPORTANT DISCLAIMER

### Legal and Ethical Use Only

**USE THIS TOOL ONLY WITH EXPLICIT AUTHORIZATION.**

- ✅ **Authorized Use:** Security testing with written permission, CTF competitions, research on systems you own, educational purposes
- ❌ **Prohibited Use:** Unauthorized testing, malicious reconnaissance, evasion of security controls without permission
- 📜 **Your Responsibility:** You are solely responsible for ensuring you have proper authorization before collecting or analyzing HTTP traffic
- ⚖️ **Legal Notice:** Unauthorized access to computer systems may violate laws including the Computer Fraud and Abuse Act (CFAA) and similar laws in other jurisdictions

This tool analyzes files you provide. **Do not collect files from systems you are not authorized to test.**

---

## Features

- ✨ **Multiple Input Formats:** Parse raw `curl -i` dumps, JSON observations, or HAR (HTTP Archive) files
- 🎯 **Heuristic Analysis:** Signature and pattern-based scoring with transparent rationale
- 🔒 **Offline Only:** No network access; completely deterministic and auditable
- 📊 **Detailed Reports:** Human-readable text or machine-readable JSON output
- 🏷️ **Vendor Detection:** Identifies potential WAF vendors (Cloudflare, Akamai, Imperva, F5, etc.)
- 🔍 **Confidence Scoring:** Clear confidence levels (0.0-1.0) for detection decisions
- 📝 **Forensic Ready:** Generate reports suitable for documentation and compliance artifacts

## Installation

### From Source (Recommended)

```bash
# Clone the repository
git clone https://github.com/yourusername/waf-presence-checker.git
cd waf-presence-checker

# Install in editable mode
pip install -e .

# Or install with development dependencies
pip install -e ".[dev]"
```

### Requirements

- Python 3.9 or higher
- No external runtime dependencies (pure Python standard library)

## Quick Start

### 1. Capture HTTP Response (Authorized Target Only)

```bash
# Using curl to capture headers from an authorized target
curl -I -sD headers.txt https://example.com

# Or save full response including body
curl -i https://example.com > response.txt

# Using browser DevTools: Export as HAR file
# Chrome/Edge: DevTools → Network → Right-click → "Save all as HAR"
```

### 2. Analyze Offline

```bash
# Analyze captured headers
wafpc analyze -i headers.txt --format raw

# Analyze HAR file
wafpc analyze -i capture.har --format har

# Auto-detect format
wafpc analyze -i response.txt

# Get JSON output for automation
wafpc analyze -i headers.txt --json
```

## Usage Examples

### Basic Analysis

```bash
wafpc analyze -i examples/sample_headers.txt
```

**Output:**
```
WAF Presence: LIKELY PRESENT (confidence=0.70)
Possible vendors: Cloudflare (edge firewall/CDN)
Rationale: Vendor hints: Cloudflare (edge firewall/CDN) (0.70); Headers: cf-ray, server

Indicators:
  - [0.25] header:server :: server :: Cloudflare (edge firewall/CDN) hint
  - [0.25] header:cf-ray :: cf-ray :: Cloudflare (edge firewall/CDN) hint
  - [0.20] cookie :: __cfduid :: Cloudflare (edge firewall/CDN) cookie hint
```

### JSON Output for Automation

```bash
wafpc analyze -i response.har --json > report.json
```

**Output:**
```json
{
  "likely_waf": true,
  "confidence": 0.70,
  "vendor_guesses": ["Cloudflare (edge firewall/CDN)"],
  "rationale": "Vendor hints: Cloudflare (0.70); Headers: cf-ray, server",
  "indicators": [
    {
      "source": "header:server",
      "key": "server",
      "value": "cloudflare",
      "weight": 0.25,
      "note": "Cloudflare (edge firewall/CDN) hint"
    }
  ]
}
```

### Verbose Logging

```bash
wafpc analyze -i headers.txt --verbose
```

## Exit Codes

The CLI returns different exit codes for automation:

- **0**: No WAF detected (low confidence)
- **1**: Indeterminate result or error
- **2**: WAF likely present (medium-high confidence)

**Example Script:**
```bash
#!/bin/bash
wafpc analyze -i target_headers.txt
case $? in
    0) echo "No WAF detected" ;;
    2) echo "WAF detected - proceed with caution" ;;
    *) echo "Analysis inconclusive" ;;
esac
```

## Supported Input Formats

### Raw HTTP Headers (`--format raw`)

```
HTTP/1.1 200 OK
Server: cloudflare
CF-Ray: 1234567890abc
Content-Type: text/html

<html>...</html>
```

### JSON Observation (`--format json`)

```json
{
  "url": "https://example.com",
  "method": "GET",
  "status_code": 200,
  "headers": {
    "Server": "cloudflare",
    "CF-Ray": "1234567890abc"
  },
  "body_excerpt": "<html>..."
}
```

### HAR File (`--format har`)

Standard HAR format exported from browser DevTools or proxy tools like Burp Suite, OWASP ZAP.

## Detected WAF Vendors

Current fingerprint database includes (but is not limited to):

- ☁️ Cloudflare (CDN/Edge Firewall)
- 🌐 Akamai (Edge Security)
- 🛡️ Imperva/Incapsula
- 🔐 Sucuri Website Firewall
- ⚙️ ModSecurity (various vendors)
- 🔧 F5 ASM/Advanced WAF

**Note:** Fingerprints are based on publicly documented patterns and should not be considered exhaustive or authoritative.

## How It Works

1. **Input Parsing:** Reads HTTP observations from files (no network activity)
2. **Normalization:** Normalizes headers for case-insensitive comparison
3. **Pattern Matching:** Checks against vendor fingerprints and generic WAF indicators
4. **Scoring:** Calculates confidence based on weighted indicators
5. **Reporting:** Generates human-readable or JSON output with rationale

## Why Offline?

- 🔒 **Security:** Prevents accidental unauthorized testing
- 📋 **Compliance:** Encourages proper ROE and authorization
- 🔍 **Forensics:** Analyze historical captures without re-requesting
- 🎯 **Precision:** Deterministic results for documentation
- 🚫 **No Evasion:** Does not provide active scanning or bypass capabilities

## Documentation

- 📄 [White Paper](docs/WHITEPAPER.md) - Technical methodology and design decisions
- 📋 [ROE Template](docs/ROE_TEMPLATE.md) - Rules of Engagement template for authorized testing
- 📖 [Usage Guide](docs/USAGE.md) - Detailed usage examples and workflows

## Development

### Setting Up Development Environment

```bash
# Install with development dependencies
pip install -e ".[dev]"

# Run type checking
mypy waf_presence_checker/

# Format code
black waf_presence_checker/

# Lint code
ruff check waf_presence_checker/
```

### Project Structure

```
waf_presence_checker/
├── waf_presence_checker/
│   ├── __init__.py       # Package initialization
│   ├── analyzer.py       # Core analysis engine
│   ├── cli.py           # Command-line interface
│   ├── fingerprints.py  # WAF fingerprint database
│   ├── models.py        # Data models
│   ├── parsers.py       # Input format parsers
│   └── reporters.py     # Output formatters
├── tests/               # Test suite
├── docs/                # Documentation
├── examples/            # Example input files
└── pyproject.toml       # Project configuration
```

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

Areas where contributions are especially welcome:
- Additional WAF fingerprints (with documentation)
- Improved detection heuristics
- Additional input format parsers
- Documentation improvements

## Security

For security issues, please see [SECURITY.md](SECURITY.md) for responsible disclosure guidelines.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Responsible Use Statement

This tool is designed for **defensive security** purposes and **authorized security testing only**. The authors:

- ✅ Support authorized penetration testing and security research
- ✅ Encourage responsible disclosure and ethical security practices
- ❌ Do not condone unauthorized access or malicious use
- ❌ Are not responsible for misuse of this tool

**By using this tool, you agree to use it only for authorized and legal purposes.**

## Acknowledgments

- Inspired by the need for safe, offline security analysis tools
- Built with Python's excellent standard library
- Community fingerprint contributions welcome

## FAQ

**Q: Does this tool actively scan websites?**
A: No. This tool only analyzes files you provide. It makes zero network requests.

**Q: Is this tool 100% accurate?**
A: No. WAF detection is heuristic-based and may have false positives/negatives. Use as one data point in your analysis.

**Q: Can I use this for bug bounty programs?**
A: Yes, if the program's scope permits. Always follow the program's rules and only analyze authorized targets.

**Q: Will this help me bypass WAFs?**
A: No. This tool is for detection only and does not provide evasion techniques.

**Q: How can I add new WAF fingerprints?**
A: See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on submitting fingerprints.

---

**Remember: Always obtain proper authorization before security testing. When in doubt, ask for permission first.**
