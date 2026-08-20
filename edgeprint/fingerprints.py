# SPDX-License-Identifier: Apache-2.0
#
# The fingerprint database is licensed Apache-2.0 rather than MIT (which covers
# the rest of edgeprint), because it is a compilation that aggregates material
# under BSD-3-Clause, MIT and Apache-2.0 terms. Apache-2.0 absorbs all three
# coherently; MIT cannot relabel Apache-2.0 material. See LICENSE-APACHE and NOTICE.
"""Loader for the WAF / CDN / edge-protection fingerprint database.

The database is authored as YAML in ``fingerprints/`` — one file per vendor, with
comments and per-signal provenance — and compiled by ``tools/build_fingerprints.py``
into ``edgeprint/data/fingerprints.json``, which is what ships and what this module
reads. The split keeps the runtime free of dependencies while leaving contributors
a format worth reviewing; CI fails if the two drift apart.

The JSON is deliberately plain and language-neutral so other tools can consume the
database without depending on this package.
"""

import json
from typing import Any

try:  # Python 3.9+
    from importlib.resources import files as _resource_files
except ImportError:  # pragma: no cover - unreachable on supported versions
    _resource_files = None  # type: ignore[assignment]

_DATA_FILE = "fingerprints.json"


def _load() -> dict:
    if _resource_files is not None:
        path = _resource_files("edgeprint").joinpath("data").joinpath(_DATA_FILE)
        data: dict = json.loads(path.read_text(encoding="utf-8"))
        return data
    import pathlib  # pragma: no cover

    here = pathlib.Path(__file__).parent / "data" / _DATA_FILE  # pragma: no cover
    return json.loads(here.read_text(encoding="utf-8"))  # pragma: no cover


_DB: dict = _load()

SCHEMA_VERSION: int = _DB["schema_version"]

#: Vendor fingerprints in the shape the analyzer consumes. Not exhaustive and not
#: vendor-endorsed. Header keys ending in ``*`` are prefix matches; a ``contains``
#: of ``""`` matches on header presence alone. Cookie entries are matched against
#: parsed cookie *names*, never values.
FINGERPRINTS: list[dict[str, Any]] = [
    {
        "vendor": v["vendor"],
        "layers": v["layers"],
        "signal_layers": v.get("signal_layers", {}),
        "header_contains": [tuple(pair) for pair in v.get("header_contains", [])],
        "cookie_contains": v.get("cookie_contains", []),
        "body_contains": v.get("body_contains", []),
        "weights": v.get("weights", {}),
    }
    for v in _DB["vendors"]
]


def vendor_count() -> int:
    """Number of vendors in the loaded database."""
    return len(FINGERPRINTS)


def signal_count() -> int:
    """Total number of signals across all vendors."""
    return sum(
        len(v["header_contains"]) + len(v["cookie_contains"]) + len(v["body_contains"])
        for v in FINGERPRINTS
    )
