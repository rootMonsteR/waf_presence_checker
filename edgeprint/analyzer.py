"""Core analysis engine for WAF presence detection.

This module contains the main analysis logic that examines HTTP observations
and determines the likelihood of WAF presence based on various indicators.
"""

import logging
import re
from typing import Optional

from .fingerprints import FINGERPRINTS
from .models import DetectionReport, HttpObservation, Indicator

logger = logging.getLogger(__name__)


def _norm_headers(h: dict[str, str]) -> dict[str, str]:
    """Normalize header keys and values to lowercase for case-insensitive comparison.

    Args:
        h: Dictionary of HTTP headers

    Returns:
        Dictionary with normalized (lowercase, stripped) keys and values
    """
    if not h:
        return {}
    return {str(k).lower().strip(): str(v).lower().strip() for k, v in h.items()}


def _header_match(headers: dict[str, str], key: str, needle: str) -> Optional[str]:
    """Find the header matching a fingerprint key, returning its real name.

    Supports prefix matching with a trailing asterisk (e.g. ``x-akamai*``, which
    matches ``x-akamai-transformed``). Returning the matched key rather than a
    boolean lets reports name the header actually observed instead of echoing
    the wildcard pattern back at the reader.

    Args:
        headers: Normalized headers dictionary
        key: Header key to search for (trailing ``*`` makes it a prefix match)
        needle: Substring the header value must contain; ``""`` matches on
            presence alone

    Returns:
        The matched header name, or None if no header matched
    """
    key = key.lower()
    prefix = key[:-1] if key.endswith("*") else None
    for k, v in headers.items():
        if k == key or (prefix is not None and k.startswith(prefix)):
            if needle == "" or needle in v:
                return k
    return None


def _header_has(headers: dict[str, str], key: str, needle: str) -> bool:
    """Boolean form of :func:`_header_match`, kept for callers that only test."""
    return _header_match(headers, key, needle) is not None


def _cookie_hits(headers: dict[str, str], needles: list[str]) -> list[str]:
    """Find which cookie names from a list are present in Set-Cookie headers.

    Args:
        headers: Normalized headers dictionary
        needles: List of cookie names to search for

    Returns:
        List of cookie names that were found
    """
    hv = headers.get("set-cookie", "")
    hits = []
    for n in needles:
        if n.lower() in hv:
            hits.append(n)
    return hits


# Maximum confidence any single vendor's signals may contribute.
VENDOR_WEIGHT_CAP: float = 0.7

# Generic patterns indicating potential blocking/filtering
BLOCK_PATTERNS: list[tuple[str, re.Pattern, float, str]] = [
    ("body", re.compile(r"request\s+blocked", re.I), 0.35, "Generic block message"),
    ("body", re.compile(r"access\s+denied", re.I), 0.25, "Generic access denied"),
    ("body", re.compile(r"forbidden", re.I), 0.15, "403 forbidden page"),
]

# Generic headers that may indicate WAF presence
GENERIC_HEADER_HINTS: list[tuple[str, str, str, float, str]] = [
    ("header", "x-waf", "", 0.35, "Explicit WAF header present"),
    ("header", "x-firewall", "", 0.25, "Explicit firewall header"),
]


def analyze(ob: HttpObservation) -> DetectionReport:
    """Analyze an HTTP observation for WAF presence indicators.

    Examines HTTP headers, cookies, and response body for patterns that suggest
    a Web Application Firewall or CDN edge protection sits in front of the origin.

    Generic block-page patterns (``request blocked``, ``access denied``,
    ``forbidden``) are only counted when some independent vendor or WAF signal
    corroborates them. On their own they are indistinguishable from an ordinary
    origin returning 403, and counting them unconditionally produced false
    positives on stock nginx/Apache error pages.

    Args:
        ob: HttpObservation containing the HTTP response data to analyze

    Returns:
        DetectionReport with findings, confidence score, and vendor guesses

    Raises:
        ValueError: If the observation is None
    """
    if not ob:
        raise ValueError("HttpObservation cannot be None")

    logger.info("Starting WAF presence analysis")
    headers = _norm_headers(ob.headers)
    indicators: list[Indicator] = []
    vendor_votes: dict[str, float] = {}
    # Raw per-vendor weight, before the per-vendor cap is applied to confidence.
    vendor_weight: dict[str, float] = {}
    body = (ob.body_excerpt or "").lower()

    # Vendor fingerprints
    for fp in FINGERPRINTS:
        vendor = fp["vendor"]
        vote = 0.0

        for k, v in fp.get("header_contains", []):
            matched = _header_match(headers, k, v.lower() if v else "")
            if matched is not None:
                indicators.append(
                    Indicator(
                        f"header:{matched}", matched, headers[matched], 0.25, f"{vendor} hint"
                    )
                )
                vote += 0.25

        for ch in _cookie_hits(headers, fp.get("cookie_contains", [])):
            indicators.append(Indicator("cookie", ch, ch, 0.2, f"{vendor} cookie hint"))
            vote += 0.2

        # body patterns (excerpt only; offline-safe)
        for b in fp.get("body_contains", []):
            if b.strip() and b in body:
                indicators.append(Indicator("body", "contains", b, 0.15, f"{vendor} body hint"))
                vote += 0.15

        if vote > 0.0:
            vendor_weight[vendor] = vendor_weight.get(vendor, 0.0) + vote
        if vote >= 0.4:
            vendor_votes[vendor] = vendor_votes.get(vendor, 0.0) + min(vote, VENDOR_WEIGHT_CAP)

    # Generic headers
    generic_weight = 0.0
    for src, key, needle, w, note in GENERIC_HEADER_HINTS:
        matched = _header_match(headers, key, needle)
        if matched is not None:
            indicators.append(Indicator(f"{src}:{matched}", matched, headers[matched], w, note))
            generic_weight += w

    # Generic block pages only count when something independent corroborates them.
    corroborated = bool(vendor_weight) or generic_weight > 0.0
    block_weight = 0.0
    for src, pat, w, note in BLOCK_PATTERNS:
        if pat.search(ob.body_excerpt or ""):
            if not corroborated:
                logger.debug("Ignoring uncorroborated block pattern: %s", pat.pattern)
                continue
            indicators.append(Indicator(src, "pattern", pat.pattern, w, note))
            block_weight += w

    # Confidence: cap each vendor's contribution so a single vendor with many
    # matching signals cannot saturate the score on its own.
    confidence = sum(min(w, VENDOR_WEIGHT_CAP) for w in vendor_weight.values())
    confidence += generic_weight + block_weight
    confidence = max(0.0, min(confidence, 1.0))

    likely = confidence >= 0.6 or (confidence >= 0.45 and len(vendor_votes) >= 1)

    # Compose rationale
    reasons = []
    if vendor_votes:
        top = sorted(vendor_votes.items(), key=lambda kv: kv[1], reverse=True)[:3]
        reasons.append("Vendor hints: " + ", ".join([f"{v} ({score:.2f})" for v, score in top]))
    header_keys = ", ".join(sorted({i.key for i in indicators if i.source.startswith("header")}))
    if header_keys:
        reasons.append(f"Headers: {header_keys}")
    cookie_keys = ", ".join(sorted({i.key for i in indicators if i.source == "cookie"}))
    if cookie_keys:
        reasons.append(f"Cookies: {cookie_keys}")
    body_notes = ", ".join(sorted({i.note for i in indicators if i.source == "body"}))
    if body_notes:
        reasons.append(f"Body: {body_notes}")

    vendor_guesses = [
        v for v, _ in sorted(vendor_votes.items(), key=lambda kv: kv[1], reverse=True)
    ]
    rationale = "; ".join(reasons) if reasons else "No strong indicators found."

    return DetectionReport(
        likely_waf=likely,
        confidence=round(confidence, 2),
        indicators=indicators,
        vendor_guesses=vendor_guesses,
        rationale=rationale,
    )
