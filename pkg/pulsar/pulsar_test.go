// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

import "testing"

// TestVersion is a sanity check that the module builds at all and the
// version constant exists. The reference implementation grows from this
// minimum point as the spec freezes.
func TestVersion(t *testing.T) {
	if Version == "" {
		t.Fatalf("Version constant must be set")
	}
}
