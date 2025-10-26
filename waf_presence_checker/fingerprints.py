"""WAF fingerprint database.

This module contains fingerprint patterns for various WAF vendors.
These are minimal, public-pattern-based hints and are intentionally kept small
to avoid misuse and false certainty. This is not exhaustive and not vendor-endorsed.

IMPORTANT: These fingerprints are based on publicly documented patterns and
should not be considered authoritative or comprehensive.
"""

from typing import List, Dict, Any

# Fingerprint database
FINGERPRINTS: List[Dict[str, Any]] = [
    {
        "vendor": "Cloudflare (edge firewall/CDN)",
        "header_contains": [
            ("server", "cloudflare"),
            ("cf-ray", ""),
            ("cf-cache-status", ""),
        ],
        "cookie_contains": ["__cfduid", "cf_ob_info", "cf_use_ob"],
        "body_contains": ["cloudflare", "attention required", "checking your browser"]
    },
    {
        "vendor": "Akamai (edge)",
        "header_contains": [
            ("server", "akamai"),
            ("x-akamai", ""),
        ],
        "cookie_contains": ["aka_", "ak_bmsc", "bm_sv"],
        "body_contains": ["akamai"]
    },
    {
        "vendor": "Imperva/Incapsula",
        "header_contains": [
            ("x-iinfo", ""),
            ("x-cdn", "incapsula"),
            ("visid_incap", ""),
        ],
        "cookie_contains": ["incap_ses", "visid_incap"],
        "body_contains": ["incapsula", "request blocked"]
    },
    {
        "vendor": "Sucuri",
        "header_contains": [
            ("x-sucuri-id", ""),
            ("x-sucuri-cache", ""),
        ],
        "cookie_contains": ["sucuri_cloudproxy_uuid"],
        "body_contains": ["sucuri website firewall"]
    },
    {
        "vendor": "ModSecurity (various vendors)",
        "header_contains": [
            ("x-modsecurity", ""),
            ("x-powered-by", "mod_security"),
        ],
        "cookie_contains": [],
        "body_contains": ["mod_security", "modsecurity"]
    },
    {
        "vendor": "F5 (ASM/Advanced WAF)",
        "header_contains": [
            ("x-asm", ""),
            ("x-waf", "f5"),
        ],
        "cookie_contains": ["ts01", "ts02", "f5avr"],
        "body_contains": ["the requested url was rejected"]
    },
]
