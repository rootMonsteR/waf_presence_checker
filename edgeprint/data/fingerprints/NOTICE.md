# Fingerprint database — licensing

The `*.json` files in this directory are licensed **Apache-2.0** (see
`LICENSE-APACHE` at the repository root), not MIT like the rest of edgeprint.

The database is a compilation that aggregates material under BSD-3-Clause, MIT
and Apache-2.0 terms. Apache-2.0 absorbs all three coherently; MIT cannot relabel
Apache-2.0 material. Each file declares `"license": "Apache-2.0"` so the terms
travel with the data — this directory is meant to be vendored independently of
the Python package, and unlicensed data files would be the exact inversion of
the intent.

Per-signal provenance is recorded in each signal's `source` field. Upstream
projects, their attribution requirements, and two deliberate exclusions
(WhatWaf, GPL; JA4S, FoxIO License 1.1) are recorded in `NOTICE` at the
repository root.
