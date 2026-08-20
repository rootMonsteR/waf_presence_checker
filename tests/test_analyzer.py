"""Analyzer and CLI tests, driven from the fixture manifest.

The manifest is the seed of the benchmark corpus, so tests read from it rather
than hard-coding cases: adding a capture and a manifest row is all it takes to
extend coverage.
"""

import json
import pathlib

import pytest

from edgeprint.analyzer import analyze
from edgeprint.cli import EXIT_EDGE_ONLY, EXIT_INDETERMINATE, EXIT_OK, EXIT_WAF_LIKELY, main
from edgeprint.models import HttpObservation
from edgeprint.parsers import parse_har, parse_json_obs, parse_raw_headers

FIXTURES = pathlib.Path(__file__).parent / "fixtures"
MANIFEST = json.loads((FIXTURES / "manifest.json").read_text(encoding="utf-8"))
CASES = MANIFEST["fixtures"]

PARSERS = {"raw": parse_raw_headers, "json": parse_json_obs, "har": parse_har}

POSITIVE = [c for c in CASES if c["expect_layers"]]
NEGATIVE = [c for c in CASES if not c["expect_layers"]]


def _analyze(case):
    """Parse a fixture with the parser its manifest row declares, then analyze."""
    parser = PARSERS[case["format"]]
    return analyze(parser((FIXTURES / case["file"]).read_text(encoding="utf-8")))


@pytest.mark.parametrize("case", POSITIVE, ids=[c["file"] for c in POSITIVE])
def test_positive_fixture_detected(case):
    """Every protected fixture is flagged, with the right vendor on top."""
    report = _analyze(case)
    assert report.likely_edge, f"{case['file']} not detected (confidence={report.confidence})"
    assert report.vendor_guesses, f"{case['file']} produced no vendor guess"
    assert report.vendor_guesses[0] == case["expect_vendor"]


@pytest.mark.parametrize("case", POSITIVE, ids=[c["file"] for c in POSITIVE])
def test_positive_fixture_layers(case):
    """Detected layers cover what the capture actually proves.

    A CDN edge is not a WAF: Fastly and CloudFront must not report a waf layer
    from caching headers alone.
    """
    report = _analyze(case)
    for layer in case["expect_layers"]:
        assert (
            layer in report.layers
        ), f"{case['file']} missing layer '{layer}' (got {report.layers})"
    if "waf" not in case["expect_layers"]:
        assert not report.likely_waf, (
            f"{case['file']} claims a WAF from {case['expect_layers']} signals only "
            f"(layers={report.layers})"
        )


@pytest.mark.parametrize("case", NEGATIVE, ids=[c["file"] for c in NEGATIVE])
def test_negative_fixture_not_detected(case):
    """Unprotected origins stay clean: no verdict, and no stray indicators."""
    report = _analyze(case)
    assert not report.likely_edge, (
        f"{case['file']} false-positived (confidence={report.confidence}, "
        f"indicators={[i.note for i in report.indicators]})"
    )
    assert report.indicators == [], (
        f"{case['file']} produced indicators with nothing present: "
        f"{[(i.source, i.note) for i in report.indicators]}"
    )


@pytest.mark.parametrize("case", CASES, ids=[c["file"] for c in CASES])
def test_cli_exit_code(case, capsys):
    """The documented exit-code contract holds for every fixture."""
    code = main(["analyze", "-i", str(FIXTURES / case["file"]), "--format", case["format"]])
    capsys.readouterr()
    assert code == case["expect_exit"], f"{case['file']} exited {code}"


@pytest.mark.parametrize("case", CASES, ids=[c["file"] for c in CASES])
def test_confidence_in_range(case):
    report = _analyze(case)
    assert 0.0 <= report.confidence <= 1.0
    assert all(0.0 <= v <= 1.0 for v in report.layers.values())


def test_single_vendor_cannot_saturate_confidence():
    """CloudFront matches four header signals; the per-vendor cap must hold."""
    case = next(c for c in CASES if c["file"] == "positive/cloudfront_200.txt")
    report = _analyze(case)
    assert len([i for i in report.indicators if i.source.startswith("header")]) >= 4
    assert report.confidence <= 0.7


def test_uncorroborated_block_page_is_ignored():
    """A block phrase alone, with no vendor signal, is not evidence."""
    report = analyze(
        HttpObservation(
            status_code=403,
            headers={"server": "nginx/1.24.0"},
            body_excerpt="<h1>403 Forbidden</h1><p>Access denied.</p>",
        )
    )
    assert report.indicators == []
    assert not report.likely_edge


def test_generic_block_phrase_cannot_corroborate_itself():
    """A generic phrase must not double as vendor evidence for its own gate.

    'request blocked' was listed as an Imperva and AWS body signal while also
    being a generic BLOCK_PATTERN, so an unprotected origin serving that phrase
    reached 0.65 confidence and exited 2.
    """
    report = analyze(
        HttpObservation(
            status_code=403,
            headers={"Server": "nginx/1.24.0"},
            body_excerpt="<h1>Request Blocked</h1>",
        )
    )
    assert report.indicators == []
    assert not report.likely_waf
    assert report.confidence == 0.0


def test_block_page_counts_when_corroborated():
    """The same phrase does count once a vendor signal is present."""
    report = analyze(
        HttpObservation(
            status_code=403,
            headers={"x-sucuri-id": "12345", "server": "Sucuri/Cloudproxy"},
            body_excerpt="<h1>Access denied</h1>",
        )
    )
    assert any(i.source == "body" and i.key == "pattern" for i in report.indicators)
    assert report.likely_waf


def test_repeated_set_cookie_is_preserved():
    """Repeated Set-Cookie lines must not overwrite each other."""
    ob = parse_raw_headers(
        "HTTP/1.1 200 OK\nSet-Cookie: a=1; path=/\nSet-Cookie: b=2; path=/\n\nbody\n"
    )
    assert "a=1" in ob.headers["Set-Cookie"]
    assert "b=2" in ob.headers["Set-Cookie"]


def test_cookie_needles_match_names_not_values():
    """Short needles must not fire inside opaque session values."""
    report = analyze(HttpObservation(headers={"Set-Cookie": "sessionid=xx_abckyy; path=/"}))
    assert report.indicators == []


def test_header_body_boundary_is_the_blank_line():
    """A colon in the body must not be parsed as a header."""
    ob = parse_raw_headers(
        "HTTP/1.1 403 Forbidden\n"
        "Server: nginx/1.24.0\n"
        "\n"
        "<style>h1{color: red}</style>\n"
        "<p>Server: cloudflare</p>\n"
    )
    assert set(ob.headers) == {"Server"}
    assert "cloudflare" in (ob.body_excerpt or "")


def test_indicator_values_are_verbatim():
    """Reported evidence keeps original casing, so it stays quotable."""
    case = next(c for c in CASES if c["file"] == "positive/cloudfront_200.txt")
    report = _analyze(case)
    values = [i.value for i in report.indicators]
    assert "AbCdEfGhIjKlMnOpQrStUvWxYz" in values


def test_cli_missing_file_is_indeterminate(capsys):
    code = main(["analyze", "-i", str(FIXTURES / "does_not_exist.txt")])
    capsys.readouterr()
    assert code == EXIT_INDETERMINATE


def test_cli_json_output_is_valid(capsys):
    code = main(["analyze", "-i", str(FIXTURES / "positive/imperva_200.txt"), "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert code == EXIT_WAF_LIKELY
    assert payload["likely_waf"] is True
    assert payload["layers"]["waf"] > 0
    assert payload["vendor_guesses"][0] == "Imperva/Incapsula"


def test_exit_codes_are_distinct():
    assert len({EXIT_OK, EXIT_INDETERMINATE, EXIT_WAF_LIKELY, EXIT_EDGE_ONLY}) == 4


def test_analyze_rejects_none():
    with pytest.raises(ValueError):
        analyze(None)
