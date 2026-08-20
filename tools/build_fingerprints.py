#!/usr/bin/env python3
"""Compile the YAML fingerprint sources into the JSON the engine loads.

YAML is the authoring format because fingerprints need comments and provenance
notes. JSON is what ships, so the runtime keeps zero dependencies. Run this after
editing anything in ``fingerprints/``; CI fails if the compiled output drifts.

    python tools/build_fingerprints.py           # write edgeprint/data/fingerprints.json
    python tools/build_fingerprints.py --check   # exit 1 if the output is stale
"""

import argparse
import json
import pathlib
import sys

try:
    import yaml
except ImportError:  # pragma: no cover
    sys.exit("PyYAML is required to build fingerprints: pip install -e '.[dev]'")

ROOT = pathlib.Path(__file__).resolve().parent.parent
SOURCE_DIR = ROOT / "fingerprints"
OUTPUT = ROOT / "edgeprint" / "data" / "fingerprints.json"

VALID_LAYERS = {"cdn", "waf", "bot", "ddos"}
VALID_TYPES = {"header", "cookie", "body"}

# Phrases generic enough that an unprotected origin emits them. They belong to
# the analyzer's BLOCK_PATTERNS, which require independent vendor corroboration.
# Allowing one as a vendor body signal lets it corroborate itself.
FORBIDDEN_BODY_PHRASES = {
    "request blocked",
    "access denied",
    "forbidden",
    "not acceptable",
    "blocked",
}


def load_sources() -> list:
    vendors = []
    for path in sorted(SOURCE_DIR.glob("*.yaml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        data["_file"] = path.name
        vendors.append(data)
    return vendors


def validate(vendors: list) -> list:
    """Return a list of human-readable problems; empty means the database is sound."""
    problems = []
    seen = set()
    for v in vendors:
        where = v.get("_file", "?")
        name = v.get("vendor")
        if not name:
            problems.append(f"{where}: missing 'vendor'")
            continue
        if name in seen:
            problems.append(f"{where}: duplicate vendor name {name!r}")
        seen.add(name)

        layers = v.get("layers") or []
        if not layers:
            problems.append(f"{where}: 'layers' is required")
        for layer in layers:
            if layer not in VALID_LAYERS:
                problems.append(f"{where}: unknown layer {layer!r} (valid: {sorted(VALID_LAYERS)})")

        signals = v.get("signals") or []
        if not signals:
            problems.append(f"{where}: no signals")

        for i, sig in enumerate(signals):
            at = f"{where} signal[{i}]"
            stype = sig.get("type")
            if stype not in VALID_TYPES:
                problems.append(f"{at}: unknown type {stype!r}")
                continue
            if sig.get("layer") and sig["layer"] not in VALID_LAYERS:
                problems.append(f"{at}: unknown layer {sig['layer']!r}")
            if not sig.get("verified_against"):
                problems.append(f"{at}: missing 'verified_against'; every signal needs a fixture")
            elif not (ROOT / sig["verified_against"]).exists():
                problems.append(f"{at}: fixture {sig['verified_against']} does not exist")
            if not sig.get("source"):
                problems.append(f"{at}: missing 'source'")

            if stype == "header" and not sig.get("key"):
                problems.append(f"{at}: header signal needs 'key'")
            if stype == "cookie":
                prefix = sig.get("name_prefix", "")
                if not prefix:
                    problems.append(f"{at}: cookie signal needs 'name_prefix'")
                elif len(prefix) < 3:
                    problems.append(
                        f"{at}: cookie prefix {prefix!r} is too short and will match "
                        f"unrelated cookie names"
                    )
            if stype == "body":
                phrase = (sig.get("contains") or "").strip().lower()
                if not phrase:
                    problems.append(f"{at}: body signal needs 'contains'")
                elif phrase in FORBIDDEN_BODY_PHRASES:
                    problems.append(
                        f"{at}: {phrase!r} is a generic block phrase, not vendor evidence. "
                        f"Generic phrases belong to BLOCK_PATTERNS, which require independent "
                        f"corroboration; listing one here lets it corroborate itself."
                    )
    return problems


def compile_db(vendors: list) -> dict:
    """Flatten the YAML sources into the runtime shape the analyzer consumes."""
    out = []
    for v in sorted(vendors, key=lambda d: d["vendor"]):
        entry = {
            "vendor": v["vendor"],
            "layers": list(v["layers"]),
            "signal_layers": {},
            "header_contains": [],
            "cookie_contains": [],
            "body_contains": [],
            "weights": {},
        }
        for sig in v.get("signals", []):
            stype = sig["type"]
            weight = sig.get("weight")
            if stype == "header":
                key = sig["key"]
                entry["header_contains"].append([key, sig.get("contains", "") or ""])
                if sig.get("layer"):
                    entry["signal_layers"][key] = sig["layer"]
                if weight is not None:
                    entry["weights"][f"header:{key}"] = weight
            elif stype == "cookie":
                name = sig["name_prefix"]
                entry["cookie_contains"].append(name)
                if sig.get("layer"):
                    entry["signal_layers"][name] = sig["layer"]
                if weight is not None:
                    entry["weights"][f"cookie:{name}"] = weight
            elif stype == "body":
                phrase = sig["contains"]
                entry["body_contains"].append(phrase)
                if weight is not None:
                    entry["weights"][f"body:{phrase}"] = weight
        out.append(entry)

    return {
        "schema_version": 1,
        "note": (
            "Generated from fingerprints/*.yaml by tools/build_fingerprints.py. "
            "Do not edit by hand. Licensed Apache-2.0; see LICENSE-APACHE and NOTICE."
        ),
        "vendors": out,
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true", help="verify the compiled output is current")
    args = ap.parse_args(argv)

    vendors = load_sources()
    problems = validate(vendors)
    if problems:
        print("Fingerprint database validation failed:", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        return 1

    rendered = json.dumps(compile_db(vendors), indent=2, sort_keys=False) + "\n"

    if args.check:
        current = OUTPUT.read_text(encoding="utf-8") if OUTPUT.exists() else ""
        if current != rendered:
            print(
                "edgeprint/data/fingerprints.json is stale.\n"
                "Run: python tools/build_fingerprints.py",
                file=sys.stderr,
            )
            return 1
        print(f"fingerprints.json is current ({len(vendors)} vendors)")
        return 0

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(rendered, encoding="utf-8")
    signals = sum(
        len(v["header_contains"]) + len(v["cookie_contains"]) + len(v["body_contains"])
        for v in compile_db(vendors)["vendors"]
    )
    print(f"Wrote {OUTPUT.relative_to(ROOT)}: {len(vendors)} vendors, {signals} signals")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
