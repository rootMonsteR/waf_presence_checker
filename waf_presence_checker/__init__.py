"""WAF Presence Checker - Offline analyzer for WAF detection.

This package provides tools to analyze HTTP responses and detect potential
Web Application Firewall (WAF) or CDN edge firewall presence without sending
any network traffic. It's designed for forensic analysis and authorized security testing.

IMPORTANT: Use only with explicit authorization. This tool analyzes files you provide;
do not collect files from systems you are not authorized to test.
"""

__all__ = ["analyzer", "parsers", "reporters", "fingerprints", "models"]
__version__ = "0.1.0"
__author__ = "WAF Presence Checker Contributors"
__license__ = "MIT"
