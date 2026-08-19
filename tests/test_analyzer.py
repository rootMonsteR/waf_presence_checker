"""Analyzer tests, driven from the fixture manifest.

The manifest is the seed of the benchmark corpus, so tests read from it rather
than hard-coding cases: adding a capture and a manifest row is all it takes to
extend coverage.
"""

import json
import pathlib

import pytest

from edgeprint.analyzer import analyze
from edgeprint.models import HttpObservation
from edgeprint.parsers import parse_raw_headers

FIXTURES = pathlib.Path(__file__).parent / "fixtures"
MANIFEST = json.loads((FIXTURES / "manifest.json").read_text(encoding="utf-8"))
CASES = MANIFEST["fixtures"]

POSITIVE = [c for c in CASES if c["expect_waf"]]
NEGATIVE = [c for c in CASES if not c["expect_waf"]]


def _analyze(case):
    return analyze(parse_raw_headers((FIXTURES / case["file"]).read_text(encoding="utf-8")))


@pytest.mark.parametrize("case", POSITIVE, ids=[c["file"] for c in POSITIVE])
def test_positive_fixture_detected(case):
    """Every protected fixture is flagged, with the right vendor on top."""
    report = _analyze(case)
    assert report.likely_waf, f"{case['file']} not detected (confidence={report.confidence})"
    assert report.vendor_guesses, f"{case['file']} produced no vendor guess"
    assert report.vendor_guesses[0] == case["expect_vendor"]


@pytest.mark.parametrize("case", NEGATIVE, ids=[c["file"] for c in NEGATIVE])
def test_negative_fixture_not_detected(case):
    """Unprotected origins stay clean: no verdict, and no stray indicators."""
    report = _analyze(case)
    assert not report.likely_waf, (
        f"{case['file']} false-positived (confidence={report.confidence}, "
        f"indicators={[i.note for i in report.indicators]})"
    )
    assert report.indicators == [], (
        f"{case['file']} produced indicators with no WAF present: "
        f"{[(i.source, i.note) for i in report.indicators]}"
    )


def test_confidence_never_exceeds_one():
    """A vendor matching on every signal must not push confidence out of range."""
    for case in CASES:
        report = _analyze(case)
        assert 0.0 <= report.confidence <= 1.0


def test_single_vendor_cannot_saturate_confidence():
    """CloudFront matches four header signals; the per-vendor cap must hold."""
    report = _analyze({"file": "positive/cloudfront_200.txt"})
    assert len([i for i in report.indicators if i.source.startswith("header")]) >= 4
    assert report.confidence <= 0.7


def test_uncorroborated_block_page_is_ignored():
    """A block phrase alone, with no vendor signal, is not evidence."""
    report = analyze(
        HttpObservation(
            url="https://example.com",
            status_code=403,
            headers={"server": "nginx/1.24.0"},
            body_excerpt="<h1>403 Forbidden</h1><p>Access denied.</p>",
        )
    )
    assert report.indicators == []
    assert not report.likely_waf


def test_block_page_counts_when_corroborated():
    """The same phrase does count once a vendor signal is present."""
    report = analyze(
        HttpObservation(
            url="https://example.com",
            status_code=403,
            headers={"server": "cloudflare", "cf-ray": "8b2f1e4c9a7d3f21-LHR"},
            body_excerpt="<h1>Access denied</h1>",
        )
    )
    assert any(i.source == "body" and i.key == "pattern" for i in report.indicators)
    assert report.likely_waf


def test_analyze_rejects_none():
    with pytest.raises(ValueError):
        analyze(None)
