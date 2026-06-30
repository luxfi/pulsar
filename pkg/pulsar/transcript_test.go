// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

// transcript_test.go — tests for Pulsar's hash entry points
// (cshake256 / kmac256 / transcriptHash). The SP 800-185 string
// encoders and the NIST §A.1 worked-example KATs (LeftEncode /
// RightEncode / EncodeString / BytePad) now live in their single home,
// github.com/luxfi/mlwe/transcript, and are asserted there. This file
// keeps only what is Pulsar-specific: that the Pulsar-named entries are
// deterministic and that transcriptHash's domain/boundary separation
// holds.

import (
	"bytes"
	"testing"
)

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

func TestKMAC256_Deterministic(t *testing.T) {
	key := []byte("a-key-32-bytes-long-for-kmac256-")
	a := kmac256(key, []byte("test"), 32, "PULSAR-TEST")
	b := kmac256(key, []byte("test"), 32, "PULSAR-TEST")
	if !bytes.Equal(a, b) {
		t.Fatalf("KMAC256 not deterministic")
	}
	// Different key → different output.
	c := kmac256([]byte("b-key-32-bytes-long-for-kmac256-"), []byte("test"), 32, "PULSAR-TEST")
	if bytes.Equal(a, c) {
		t.Fatalf("KMAC256 key has no effect")
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
