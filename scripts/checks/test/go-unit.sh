#!/usr/bin/env bash
# scripts/checks/test/go-unit.sh — Go unit tests (with -race).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$REPO_ROOT"

export GOWORK=off

echo "==> Go unit tests"
go test -count=1 -race ./ref/go/...
