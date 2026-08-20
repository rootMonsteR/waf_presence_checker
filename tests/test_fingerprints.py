"""Validation of the fingerprint database.

These rules were previously enforced by a build script that only CI ran. They live
in the test suite instead, so a single local `pytest` catches a bad fingerprint
without needing CI to be available.

Each rule exists because a real defect came from breaking it — the failure it
prevents is named in the test's docstring.
"""

import json
import pathlib

import pytest

from edgeprint.analyzer import _cookie_hits, _cookie_names, _header_match, _norm_headers
from edgeprint.fingerprints import (
    FINGERPRINTS,
    SCHEMA_VERSION,
    WEIGHT_DEFAULTS,
    load_vendor_files,
    signal_count,
    vendor_count,
)
from edgeprint.parsers import parse_har, parse_json_obs, parse_raw_headers

PARSERS = {".txt": parse_raw_headers, ".json": parse_json_obs, ".har": parse_har}

ROOT = pathlib.Path(__file__).resolve().parent.parent

VALID_LAYERS = {"cdn", "waf", "bot", "ddos"}
VALID_TYPES = {"header", "cookie", "body"}

# Phrases generic enough that an unprotected origin emits them. They belong to the
# analyzer's BLOCK_PATTERNS, which score only once a vendor is independently
# identified. Listing one as a vendor signal lets it corroborate itself.
GENERIC_BLOCK_PHRASES = {
    "request blocked",
    "access denied",
    "forbidden",
    "not acceptable",
    "blocked",
}

VENDORS = load_vendor_files()
VENDOR_IDS = [v.get("vendor", v["_file"]) for v in VENDORS]
SIGNALS = [(v, i, s) for v in VENDORS for i, s in enumerate(v.get("signals", []))]
SIGNAL_IDS = [f"{v.get('vendor')}[{i}]:{s.get('type')}" for v, i, s in SIGNALS]


def _of_type(kind):
    """Signals of one type, with matching ids, so type-specific tests do not skip."""
    rows = [(v, i, s) for v, i, s in SIGNALS if s.get("type") == kind]
    ids = [f"{v.get('vendor')}[{i}]" for v, i, _ in rows]
    return rows, ids


BODY_SIGNALS, BODY_IDS = _of_type("body")
COOKIE_SIGNALS, COOKIE_IDS = _of_type("cookie")
HEADER_SIGNALS, HEADER_IDS = _of_type("header")


@pytest.mark.parametrize("vendor", VENDORS, ids=VENDOR_IDS)
def test_vendor_file_is_well_formed(vendor):
    assert vendor.get("vendor"), f"{vendor['_file']}: missing 'vendor'"
    layers = vendor.get("layers") or []
    assert layers, f"{vendor['_file']}: 'layers' is required"
    assert set(layers) <= VALID_LAYERS, f"{vendor['_file']}: unknown layer in {layers}"
    assert vendor.get("signals"), f"{vendor['_file']}: no signals"


def test_vendor_names_are_unique():
    names = [v["vendor"] for v in VENDORS]
    assert len(names) == len(set(names)), f"duplicate vendor names in {names}"


@pytest.mark.parametrize("vendor,index,signal", SIGNALS, ids=SIGNAL_IDS)
def test_signal_is_well_formed(vendor, index, signal):
    where = f"{vendor['_file']} signal[{index}]"
    assert signal.get("type") in VALID_TYPES, f"{where}: unknown type {signal.get('type')!r}"
    assert signal.get("source"), f"{where}: missing 'source' (provenance)"
    if signal.get("layer"):
        assert signal["layer"] in VALID_LAYERS, f"{where}: unknown layer {signal['layer']!r}"
    weight = signal.get("weight", WEIGHT_DEFAULTS[signal["type"]])
    assert 0.0 < weight <= 1.0, f"{where}: weight {weight} out of range"


@pytest.mark.parametrize("vendor,index,signal", SIGNALS, ids=SIGNAL_IDS)
def test_every_signal_matches_its_declared_fixture(vendor, index, signal):
    """`verified_against` must be replayed, not merely present.

    An earlier version of this test only asserted the file existed, which let 31
    of 60 signals name a capture they did not match — the dead-fingerprint defect
    this rule exists to prevent, still shippable. The signal is now replayed
    through the same matchers the analyzer uses.
    """
    where = f"{vendor['_file']} signal[{index}]"
    path = signal.get("verified_against")
    assert path, f"{where}: missing 'verified_against'; every signal needs a fixture"
    fixture = ROOT / path
    assert fixture.exists(), f"{where}: fixture {path} does not exist"

    observation = PARSERS[fixture.suffix](fixture.read_text(encoding="utf-8"))
    norm, _raw = _norm_headers(observation.headers)
    kind = signal["type"]

    if kind == "header":
        matched = _header_match(norm, signal["key"], (signal.get("contains") or "").lower())
        assert matched is not None, f"{where}: header {signal['key']!r} does not match {path}"
    elif kind == "cookie":
        hits = _cookie_hits(_cookie_names(norm), [signal["name_prefix"]])
        assert hits, f"{where}: cookie {signal['name_prefix']!r} does not match {path}"
    else:
        body = (observation.body_excerpt or "").lower()
        assert (
            signal["contains"].lower() in body
        ), f"{where}: body {signal['contains']!r} does not match {path}"


@pytest.mark.parametrize("vendor,index,signal", BODY_SIGNALS, ids=BODY_IDS)
def test_body_signals_are_not_generic_block_phrases(vendor, index, signal):
    """A generic phrase as a vendor signal lets a block page corroborate itself.

    'request blocked' was listed for Imperva and AWS while also being a generic
    BLOCK_PATTERN, so plain nginx serving that phrase reached confidence 0.65.
    """
    phrase = (signal.get("contains") or "").strip().lower()
    assert phrase, f"{vendor['_file']} signal[{index}]: body signal needs 'contains'"
    assert phrase not in GENERIC_BLOCK_PHRASES, (
        f"{vendor['_file']} signal[{index}]: {phrase!r} is a generic block phrase, "
        f"not vendor evidence"
    )


@pytest.mark.parametrize("vendor,index,signal", COOKIE_SIGNALS, ids=COOKIE_IDS)
def test_cookie_prefixes_are_long_enough(vendor, index, signal):
    """Short needles match inside opaque session values; `_abck` did exactly that."""
    prefix = signal.get("name_prefix") or ""
    assert len(prefix) >= 3, (
        f"{vendor['_file']} signal[{index}]: cookie prefix {prefix!r} is too short "
        f"and will match unrelated cookie names"
    )


@pytest.mark.parametrize("vendor,index,signal", HEADER_SIGNALS, ids=HEADER_IDS)
def test_header_signals_have_a_key(vendor, index, signal):
    assert signal.get("key"), f"{vendor['_file']} signal[{index}]: header signal needs 'key'"


def test_all_vendor_files_are_valid_json():
    """A malformed file would break import, not just detection."""
    directory = ROOT / "edgeprint" / "data" / "fingerprints"
    files = sorted(directory.glob("*.json"))
    assert files, "no fingerprint files found"
    for path in files:
        json.loads(path.read_text(encoding="utf-8"))


def test_compiled_view_matches_source_files():
    """Every vendor file reaches FINGERPRINTS with its signals intact."""
    assert len(FINGERPRINTS) == len(VENDORS)
    for src, compiled in zip(VENDORS, FINGERPRINTS):
        assert src["vendor"] == compiled["vendor"]
        expected = len(src["signals"])
        actual = (
            len(compiled["header_contains"])
            + len(compiled["cookie_contains"])
            + len(compiled["body_contains"])
        )
        assert actual == expected, f"{src['vendor']}: {expected} signals, {actual} compiled"


@pytest.mark.parametrize("vendor", VENDORS, ids=VENDOR_IDS)
def test_vendor_file_declares_schema_and_license(vendor):
    """Terms and format version travel with the data, which is vendored on its own."""
    assert vendor.get("schema_version") == SCHEMA_VERSION, (
        f"{vendor['_file']}: schema_version {vendor.get('schema_version')!r} "
        f"does not match loader version {SCHEMA_VERSION}"
    )
    assert vendor.get("license") == "Apache-2.0", f"{vendor['_file']}: missing Apache-2.0 marker"


def test_counts_match_loaded_database():
    assert vendor_count() == len(VENDORS)
    assert signal_count() == sum(len(v["signals"]) for v in VENDORS)
