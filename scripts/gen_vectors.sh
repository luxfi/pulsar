#!/usr/bin/env bash
# Pulsar-M KAT regeneration.
#
# Regenerates vectors/{keygen,sign,verify,threshold-sign,dkg}.json from
# the reference implementation. Re-running on a clean checkout MUST
# produce byte-identical output — this is the deterministic-fixture
# gate enforced by CI.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

mkdir -p vectors/transcripts

export GOWORK=off

echo "==> Reference KAT generator"
go run ./ref/go/cmd/genkat -out vectors

echo "==> Verifying KAT round-trip via replay tests"
go test -count=1 -run "^TestKAT_" ./ref/go/pkg/pulsarm/

echo "==> done"
