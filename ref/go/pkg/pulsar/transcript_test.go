// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

import (
	"bytes"
	"testing"
)

// The SP 800-185 string encoders (left_encode/right_encode/
// encode_string/bytepad) and KMAC256 now live in
// github.com/luxfi/mlwe/transcript and are anchored against the NIST
// worked examples by that module's own test suite. Pulsar no longer
// duplicates either the implementation or its KATs; the tests below
// cover only the Pulsar-specific bindings (the "Pulsar"-pinned cSHAKE
// entry point and the transcriptHash tuple framing).

func TestCSHAKE256_Deterministic(t *testing.T) {
	a := cshake256([]byte("test"), 32, "PULSAR-TEST")
	b := cshake256([]byte("test"), 32, "PULSAR-TEST")
	if !bytes.Equal(a, b) {
		t.Fatalf("cSHAKE256 not deterministic")
	}
	// Different customisation gives different output.
	c := cshake256([]byte("test"), 32, "OTHER-TAG")
	if bytes.Equal(a, c) {
		t.Fatalf("cSHAKE256 customisation has no effect")
	}
}

func TestTranscriptHash_Stable(t *testing.T) {
	a := transcriptHash("PULSAR-TEST", []byte("a"), []byte("b"), []byte("c"))
	b := transcriptHash("PULSAR-TEST", []byte("a"), []byte("b"), []byte("c"))
	if a != b {
		t.Fatalf("transcriptHash not stable")
	}
	// Reordering parts must give different output.
	c := transcriptHash("PULSAR-TEST", []byte("a"), []byte("c"), []byte("b"))
	if a == c {
		t.Fatalf("transcriptHash insensitive to part order")
	}
}

func TestTranscriptHash_BoundaryEncoded(t *testing.T) {
	// (a, b) and (ab, "") should give DIFFERENT digests — boundary
	// encoding makes the part split visible.
	a := transcriptHash("T", []byte("a"), []byte("b"))
	b := transcriptHash("T", []byte("ab"), []byte(""))
	if a == b {
		t.Fatalf("transcriptHash boundary collision")
	}
}
