#!/usr/bin/env bash
# Everything CI runs, locally, in one command. Use this when CI is unavailable.
#
#   ./check.sh
#
# Fingerprint-database validation lives in the test suite rather than a separate
# build step, so pytest alone catches a malformed or unverified fingerprint.
set -euo pipefail

echo "==> tests"
python -m pytest -q

echo "==> types"
mypy edgeprint/

echo "==> lint"
ruff check edgeprint/ tests/

echo "==> format"
black --check edgeprint/ tests/

echo
echo "All checks passed."
