"""Core analysis engine for WAF presence detection.

This module contains the main analysis logic that examines HTTP observations
and determines the likelihood of WAF presence based on various indicators.
"""

import logging
import re
from typing import Dict, List, Tuple

from .fingerprints import FINGERPRINTS
from .models import DetectionReport, HttpObservation, Indicator

logger = logging.getLogger(__name__)

def _norm_headers(h: Dict[str, str]) -> Dict[str, str]:
    """Normalize header keys and values to lowercase for case-insensitive comparison.

    Args:
        h: Dictionary of HTTP headers

    Returns:
        Dictionary with normalized (lowercase, stripped) keys and values
    """
    if not h:
        return {}
    return {str(k).lower().strip(): str(v).lower().strip() for k, v in h.items()}


def _header_has(headers: Dict[str, str], key: str, needle: str) -> bool:
    """Check if a header key contains a specific value.

    Supports wildcard matching with trailing asterisk (e.g., 'x-cf-*').

    Args:
        headers: Normalized headers dictionary
        key: Header key to search for (supports trailing * for wildcard)
        needle: Value to search for within the header (empty string matches presence only)

    Returns:
        True if the header is found with the specified value
    """
    key = key.lower()
    for k, v in headers.items():
        if k == key or (key.endswith('*') and k.startswith(key[:-1])):
            if needle == '':
                return True
            if needle in v:
                return True
    return False


def _cookie_hits(headers: Dict[str, str], needles: List[str]) -> List[str]:
    """Find which cookie names from a list are present in Set-Cookie headers.

    Args:
        headers: Normalized headers dictionary
        needles: List of cookie names to search for

    Returns:
        List of cookie names that were found
    """
    hv = headers.get('set-cookie', '')
    hits = []
    for n in needles:
        if n.lower() in hv:
            hits.append(n)
    return hits

# Generic patterns indicating potential blocking/filtering
BLOCK_PATTERNS: List[Tuple[str, re.Pattern, float, str]] = [
    ('body', re.compile(r'request\s+blocked', re.I), 0.35, 'Generic block message'),
    ('body', re.compile(r'access\s+denied', re.I), 0.25, 'Generic access denied'),
    ('body', re.compile(r'forbidden', re.I), 0.15, '403 forbidden page'),
]

# Generic headers that may indicate WAF presence
GENERIC_HEADER_HINTS: List[Tuple[str, str, str, float, str]] = [
    ('header', 'x-waf', '', 0.35, 'Explicit WAF header present'),
    ('header', 'x-firewall', '', 0.25, 'Explicit firewall header'),
]


def analyze(ob: HttpObservation) -> DetectionReport:
    """Analyze an HTTP observation for WAF presence indicators.

    This function examines HTTP headers, cookies, and response body for patterns
    that suggest the presence of a Web Application Firewall or CDN edge protection.

    Args:
        ob: HttpObservation object containing the HTTP response data to analyze

    Returns:
        DetectionReport with findings, confidence score, and vendor guesses

    Raises:
        ValueError: If the observation is invalid or missing required data
    """
    if not ob:
        raise ValueError("HttpObservation cannot be None")

    logger.info("Starting WAF presence analysis")
    headers = _norm_headers(ob.headers)
    indicators: List[Indicator] = []
    vendor_votes: Dict[str, float] = {}

    # Vendor fingerprints
    for fp in FINGERPRINTS:
        vendor = fp['vendor']
        vote = 0.0

        for k, v in fp.get('header_contains', []):
            if _header_has(headers, k, v.lower() if v else ''):
                indicators.append(Indicator(f'header:{k}', k, headers.get(k if not k.endswith('*') else k[:-1], ''), 0.25, f'{vendor} hint'))
                vote += 0.25

        # cookies
        cookie_hits = _cookie_hits(headers, fp.get('cookie_contains', []))
        for ch in cookie_hits:
            indicators.append(Indicator('cookie', ch, ch, 0.2, f'{vendor} cookie hint'))
            vote += 0.2

        # body patterns (excerpt only; offline-safe)
        body = (ob.body_excerpt or '').lower()
        for b in fp.get('body_contains', []):
            if b in body and b.strip():
                indicators.append(Indicator('body', 'contains', b, 0.15, f'{vendor} body hint'))
                vote += 0.15

        if vote >= 0.4:
            vendor_votes[vendor] = vendor_votes.get(vendor, 0.0) + min(vote, 0.7)

    # Generic headers
    for src, key, needle, w, note in GENERIC_HEADER_HINTS:
        if _header_has(headers, key, needle):
            indicators.append(Indicator(f'{src}:{key}', key, headers.get(key, ''), w, note))

    # Generic body blocks
    body_lower = (ob.body_excerpt or '')
    for src, pat, w, note in BLOCK_PATTERNS:
        if pat.search(body_lower):
            indicators.append(Indicator(src, 'pattern', pat.pattern, w, note))

    # Confidence calculation
    confidence = sum(i.weight for i in indicators)
    confidence = max(0.0, min(confidence, 1.0))

    likely = confidence >= 0.6 or (confidence >= 0.45 and len(vendor_votes) >= 1)

    # Compose rationale
    reasons = []
    if vendor_votes:
        top = sorted(vendor_votes.items(), key=lambda kv: kv[1], reverse=True)[:3]
        reasons.append('Vendor hints: ' + ', '.join([f'{v} ({score:.2f})' for v, score in top]))
    header_keys = ', '.join(sorted(set(i.key for i in indicators if i.source.startswith('header'))))
    if header_keys:
        reasons.append(f'Headers: {header_keys}')
    cookie_keys = ', '.join(sorted(set(i.key for i in indicators if i.source == 'cookie')))
    if cookie_keys:
        reasons.append(f'Cookies: {cookie_keys}')
    body_notes = ', '.join(sorted(set(i.note for i in indicators if i.source == 'body')))
    if body_notes:
        reasons.append(f'Body: {body_notes}')

    vendor_guesses = [v for v, _ in sorted(vendor_votes.items(), key=lambda kv: kv[1], reverse=True)]
    rationale = '; '.join(reasons) if reasons else 'No strong indicators found.'

    return DetectionReport(
        likely_waf=likely,
        confidence=round(confidence, 2),
        indicators=indicators,
        vendor_guesses=vendor_guesses,
        rationale=rationale
    )
