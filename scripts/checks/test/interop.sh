#!/usr/bin/env bash
# scripts/checks/test/interop.sh — Class N1 interoperability.
#
# Cross-validates Pulsar-produced signatures against the
# cloudflare/circl FIPS 204 verifier — an INDEPENDENT
# implementation of ML-DSA.Verify. If our reference impl's
# bytes verify under circl's verifier for every KAT vector,
# the Class N1 output-interchangeability property holds
# empirically for that vector set.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$REPO_ROOT"

export GOWORK=off

echo "==> Class N1 interoperability"
echo "    cross-validate KAT signatures against cloudflare/circl"
echo "    FIPS 204 verifier (independent of reference impl)"
go test -count=1 ./test/interoperability/...
