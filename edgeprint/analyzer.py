"""Core analysis engine for edge-protection detection.

Examines a captured HTTP observation and estimates which edge products sit in
front of the origin, separating the layers involved: CDN caching, WAF filtering,
and bot management are different controls and are reported separately.
"""

import logging
import re
from typing import Optional

from .fingerprints import FINGERPRINTS
from .models import DetectionReport, HttpObservation, Indicator

logger = logging.getLogger(__name__)

# Maximum confidence any single vendor's signals may contribute.
VENDOR_WEIGHT_CAP: float = 0.7

# Weight a vendor must reach before it is named as a guess.
VENDOR_VOTE_THRESHOLD: float = 0.4

WEIGHT_HEADER: float = 0.25
WEIGHT_COOKIE: float = 0.20
WEIGHT_BODY: float = 0.15


def _weight(fp: dict, kind: str, key: str, default: float) -> float:
    """Per-signal weight from the database, falling back to the type default.

    Weights are currently hand-assigned placeholders. Replacing them with
    likelihood ratios measured against a labelled corpus is the point of the
    roadmap, and routing every lookup through here is what makes that a data
    change rather than a code change.
    """
    weights = fp.get("weights") or {}
    value = weights.get(f"{kind}:{key}")
    return float(value) if value is not None else default


def _norm_headers(h: dict[str, str]) -> tuple[dict[str, str], dict[str, str]]:
    """Build the lowercased map used for matching, and a raw map for reporting.

    Matching needs case-insensitive values; reports need what was actually on the
    wire, since a lowercased ``X-Amz-Cf-Id`` is no longer quotable evidence.

    Args:
        h: Dictionary of HTTP headers as parsed

    Returns:
        (normalized, raw) — both keyed by lowercased header name; ``normalized``
        has lowercased values, ``raw`` preserves them
    """
    if not h:
        return {}, {}
    norm = {str(k).lower().strip(): str(v).lower().strip() for k, v in h.items()}
    raw = {str(k).lower().strip(): str(v).strip() for k, v in h.items()}
    return norm, raw


def _header_match(headers: dict[str, str], key: str, needle: str) -> Optional[str]:
    """Find the header matching a fingerprint key, returning its real name.

    Supports prefix matching with a trailing asterisk (``x-akamai*`` matches
    ``x-akamai-transformed``). Returning the matched key rather than a boolean
    lets reports name the header actually observed instead of echoing the
    wildcard pattern back at the reader.

    Args:
        headers: Normalized headers dictionary
        key: Header key to search for; a trailing ``*`` makes it a prefix match
        needle: Substring the value must contain; ``""`` matches on presence

    Returns:
        The matched header name, or None
    """
    key = key.lower()
    prefix = key[:-1] if key.endswith("*") else None
    for k, v in headers.items():
        if k == key or (prefix is not None and k.startswith(prefix)):
            if needle == "" or needle in v:
                return k
    return None


def _cookie_names(headers: dict[str, str]) -> list[str]:
    """Extract cookie names from the Set-Cookie header(s).

    Parsers join repeated Set-Cookie fields with newlines. Only the first
    ``name=value`` pair of each line is the cookie itself; the rest are
    attributes (``path``, ``Expires``, ``SameSite``) and must not be treated
    as cookie names.
    """
    raw = headers.get("set-cookie", "")
    names = []
    for line in raw.split("\n"):
        first = line.split(";", 1)[0].strip()
        if "=" in first:
            names.append(first.split("=", 1)[0].strip().lower())
    return names


def _cookie_hits(cookie_names: list[str], needles: list[str]) -> list[tuple[str, str]]:
    """Match fingerprint needles against cookie *names*, returning names found.

    Matching against the whole Set-Cookie header instead of the parsed names made
    short needles such as ``_abck`` fire on any opaque session value that happened
    to contain them. Needles are treated as name prefixes, since several vendors
    suffix an instance id (``incap_ses_123_456``, ``akaalb_ExampleName``).

    Args:
        cookie_names: Cookie names observed in the response
        needles: Cookie name prefixes to search for

    Returns:
        (needle, observed_name) pairs. The needle is returned alongside so the
        caller can resolve that signal's weight and layer override.
    """
    hits = []
    for name in cookie_names:
        for n in needles:
            if name.startswith(n.lower()):
                hits.append((n, name))
                break
    return hits


# Generic block-page patterns. These are not vendor evidence on their own — an
# ordinary origin returning 403 says the same things — so they only score when a
# vendor has independently been identified.
BLOCK_PATTERNS: list[tuple[str, re.Pattern, float, str]] = [
    ("body", re.compile(r"request\s+blocked", re.I), 0.35, "Generic block message"),
    ("body", re.compile(r"access\s+denied", re.I), 0.25, "Generic access denied"),
    ("body", re.compile(r"forbidden", re.I), 0.15, "403 forbidden page"),
]

# Generic headers that indicate a filtering layer without naming a vendor.
# Keys here must not also appear in a vendor fingerprint, or one header scores twice.
GENERIC_HEADER_HINTS: list[tuple[str, str, str, float, str]] = [
    ("header", "x-waf", "", 0.35, "Explicit WAF header present"),
    ("header", "x-firewall", "", 0.25, "Explicit firewall header"),
]


def analyze(ob: HttpObservation) -> DetectionReport:
    """Analyze an HTTP observation for edge-protection indicators.

    Args:
        ob: HttpObservation containing the HTTP response data to analyze

    Returns:
        DetectionReport with findings, per-layer confidence, and vendor guesses

    Raises:
        ValueError: If the observation is None
    """
    if not ob:
        raise ValueError("HttpObservation cannot be None")

    logger.info("Starting edge-protection analysis")
    headers, raw_headers = _norm_headers(ob.headers)
    cookie_names = _cookie_names(headers)
    indicators: list[Indicator] = []
    vendor_weight: dict[str, float] = {}
    vendor_layers: dict[str, list[str]] = {}
    body = (ob.body_excerpt or "").lower()

    for fp in FINGERPRINTS:
        vendor = fp["vendor"]
        vote = 0.0
        matched_signals: list[str] = []

        for k, v in fp.get("header_contains", []):
            matched = _header_match(headers, k, v.lower() if v else "")
            if matched is not None:
                indicators.append(
                    Indicator(
                        f"header:{matched}",
                        matched,
                        raw_headers[matched],
                        _weight(fp, "header", k, WEIGHT_HEADER),
                        f"{vendor} hint",
                    )
                )
                vote += _weight(fp, "header", k, WEIGHT_HEADER)
                # Record the fingerprint key, not the observed name: signal_layers
                # is keyed by pattern, so a wildcard signal's layer override would
                # otherwise never resolve.
                matched_signals.append(k)

        for needle, name in _cookie_hits(cookie_names, fp.get("cookie_contains", [])):
            w = _weight(fp, "cookie", needle, WEIGHT_COOKIE)
            indicators.append(Indicator("cookie", name, name, w, f"{vendor} cookie hint"))
            vote += w
            matched_signals.append(needle)

        # body patterns (excerpt only; offline-safe)
        for b in fp.get("body_contains", []):
            if b.strip() and b in body:
                indicators.append(
                    Indicator("body", "contains", b, WEIGHT_BODY, f"{vendor} body hint")
                )
                vote += WEIGHT_BODY

        if vote > 0.0:
            vendor_weight[vendor] = vendor_weight.get(vendor, 0.0) + vote
            found_layers = list(fp.get("layers", ["cdn"]))
            # Some signals prove more than the vendor's baseline layer: a
            # cf-mitigated header shows filtering acted, not merely that the CDN
            # served the response.
            signal_layers = fp.get("signal_layers", {})
            for sig in matched_signals:
                extra = signal_layers.get(sig)
                if extra and extra not in found_layers:
                    found_layers.append(extra)
            vendor_layers[vendor] = found_layers

    # Vendors confident enough to name. Generic block pages are only evidence
    # once one of these exists: gating on any non-zero weight would let a vendor
    # whose sole match was the same generic phrase corroborate itself.
    vendor_votes = {
        v: min(w, VENDOR_WEIGHT_CAP) for v, w in vendor_weight.items() if w >= VENDOR_VOTE_THRESHOLD
    }

    generic_weight = 0.0
    for src, key, needle, w, note in GENERIC_HEADER_HINTS:
        matched = _header_match(headers, key, needle)
        if matched is not None:
            indicators.append(Indicator(f"{src}:{matched}", matched, raw_headers[matched], w, note))
            generic_weight += w

    corroborated = bool(vendor_votes) or generic_weight > 0.0
    # The block patterns overlap - one page routinely says "request blocked",
    # "access denied" and "forbidden" - and they describe the same single fact.
    # Summing them let generic phrasing outweigh the actual vendor evidence, so
    # only the strongest match scores.
    block_weight = 0.0
    for src, pat, w, note in BLOCK_PATTERNS:
        found = pat.search(ob.body_excerpt or "")
        if found:
            if not corroborated:
                logger.debug("Ignoring uncorroborated block pattern: %s", pat.pattern)
                continue
            indicators.append(Indicator(src, "pattern", found.group(0), w, note))
            block_weight = max(block_weight, w)

    # Confidence: cap each vendor's contribution so one vendor matching many
    # signals cannot saturate the score on its own. Only vendors above the naming
    # threshold count - otherwise two unrelated vendors at 0.35 apiece produce a
    # verdict with an empty vendor list and nothing to justify it.
    confidence = sum(vendor_votes.values())
    confidence += generic_weight + block_weight
    confidence = max(0.0, min(confidence, 1.0))

    # Per-layer confidence. A CDN is not a WAF: reporting Fastly or CloudFront
    # as "WAF present" overstates what the response actually showed.
    layers: dict[str, float] = {}
    for vendor, weight in vendor_votes.items():
        for layer in vendor_layers.get(vendor, []):
            layers[layer] = min(1.0, layers.get(layer, 0.0) + weight)
    if generic_weight or block_weight:
        layers["waf"] = min(1.0, layers.get("waf", 0.0) + generic_weight + block_weight)

    # Threshold on the unrounded values; rounding is presentation only. Comparing
    # a rounded score against the threshold let 0.596 display as 0.60 and cross it.
    waf_confidence = layers.get("waf", 0.0)
    likely_waf = waf_confidence >= 0.6 or (
        waf_confidence >= 0.45 and any("waf" in vendor_layers.get(v, []) for v in vendor_votes)
    )
    likely_edge = confidence >= 0.6 or (confidence >= 0.45 and bool(vendor_votes))
    layers = {k: round(v, 2) for k, v in layers.items()}

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
        likely_waf=likely_waf,
        likely_edge=likely_edge,
        confidence=round(confidence, 2),
        layers=layers,
        indicators=indicators,
        vendor_guesses=vendor_guesses,
        rationale=rationale,
    )
