# SPDX-License-Identifier: MIT
#
# This module is loader code and is MIT like the rest of the package. The data it
# loads is not: edgeprint/data/fingerprints/*.json is Apache-2.0, because that
# compilation aggregates BSD-3-Clause, MIT and Apache-2.0 material and only
# Apache-2.0 absorbs all three coherently. Each data file declares its own
# license so the terms travel with the data when it is vendored on its own.
# See edgeprint/data/fingerprints/NOTICE.md, LICENSE-APACHE and NOTICE.
"""Loader for the WAF / CDN / edge-protection fingerprint database.

The database is plain JSON under ``edgeprint/data/fingerprints/`` — one file per
vendor, hand-edited, no build step. Files are read directly at import, so what you
review is what ships and drift between source and artifact is impossible.

Per-vendor files rather than one large file: fingerprint changes arrive as small
reviewable diffs and rarely conflict. JSON rather than YAML: the runtime keeps
zero dependencies, and a ``notes`` field carries what comments would have.

The format is language-neutral by design, so other tools can consume the database
without depending on this package. See ``docs/FINGERPRINT_SCHEMA.md``.
"""

import json
from importlib.resources import files as _resource_files
from typing import Any

#: Format version of the vendor files. Each file declares its own; a mismatch
#: means the database and this loader disagree about the schema.
SCHEMA_VERSION: int = 1

WEIGHT_DEFAULTS = {"header": 0.25, "cookie": 0.20, "body": 0.15}


def _source_dir() -> Any:
    return _resource_files("edgeprint").joinpath("data").joinpath("fingerprints")


def load_vendor_files() -> list[dict[str, Any]]:
    """Read every vendor file, newest schema shape, sorted by vendor name."""
    vendors = []
    for entry in _source_dir().iterdir():
        if not entry.name.endswith(".json"):
            continue
        data: dict[str, Any] = json.loads(entry.read_text(encoding="utf-8"))
        data["_file"] = entry.name
        vendors.append(data)
    return sorted(vendors, key=lambda d: d.get("vendor", ""))


def _compile(vendors: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Flatten vendor files into the shape the analyzer matches against."""
    out = []
    for v in vendors:
        entry: dict[str, Any] = {
            "vendor": v["vendor"],
            "layers": list(v.get("layers", ["cdn"])),
            "signal_layers": {},
            "header_contains": [],
            "cookie_contains": [],
            "body_contains": [],
            "weights": {},
        }
        for sig in v.get("signals", []):
            stype = sig.get("type")
            weight = sig.get("weight", WEIGHT_DEFAULTS.get(stype))
            if stype == "header":
                key = sig["key"]
                entry["header_contains"].append((key, sig.get("contains", "") or ""))
                target = key
            elif stype == "cookie":
                target = sig["name_prefix"]
                entry["cookie_contains"].append(target)
            elif stype == "body":
                target = sig["contains"]
                entry["body_contains"].append(target)
            else:
                continue
            if sig.get("layer"):
                entry["signal_layers"][target] = sig["layer"]
            if weight is not None:
                entry["weights"][f"{stype}:{target}"] = weight
        out.append(entry)
    return out


#: Vendor fingerprints in the shape the analyzer consumes. Not exhaustive and not
#: vendor-endorsed. Header keys ending in ``*`` are prefix matches; a ``contains``
#: of ``""`` matches on header presence alone. Cookie entries are matched against
#: parsed cookie *names*, never values.
FINGERPRINTS: list[dict[str, Any]] = _compile(load_vendor_files())


def vendor_count() -> int:
    """Number of vendors in the loaded database."""
    return len(FINGERPRINTS)


def signal_count() -> int:
    """Total number of signals across all vendors."""
    return sum(
        len(v["header_contains"]) + len(v["cookie_contains"]) + len(v["body_contains"])
        for v in FINGERPRINTS
    )
