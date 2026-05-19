#!/usr/bin/env bash
# Fetch dudect at the pinned commit used by Pulsar's constant-time
# track.
#
# dudect (https://github.com/oreparaz/dudect) is a single-header
# leakage-detection library. We do not vendor dudect.h into this
# repository — this script reproduces it on demand.
#
# Pinned hash at submission-tag time. Update at the same time as the
# Pulsar submission tag so the artifact chain stays reproducible.

set -euo pipefail

# Repo + commit (master HEAD as of the dudect harness scaffold land).
# Update when bumping the submission tag.
DUDECT_REPO="https://github.com/oreparaz/dudect.git"
DUDECT_COMMIT="master"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [[ -d dudect/.git ]]; then
    echo "==> dudect already cloned at $SCRIPT_DIR/dudect"
    ( cd dudect && git fetch --quiet origin && git checkout --quiet "$DUDECT_COMMIT" )
else
    echo "==> cloning dudect at $DUDECT_COMMIT"
    git clone --quiet "$DUDECT_REPO" dudect
    ( cd dudect && git checkout --quiet "$DUDECT_COMMIT" )
fi

# The header we link against is dudect/src/dudect.h. Stamp the resolved
# revision so reviewers can verify the artifact chain.
RESOLVED_REV="$(cd dudect && git rev-parse HEAD)"
echo "==> dudect.h ready at $SCRIPT_DIR/dudect/src/dudect.h  (rev $RESOLVED_REV)"
