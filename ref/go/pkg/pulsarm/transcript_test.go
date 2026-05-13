// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsarm

import (
	"bytes"
	"testing"
)

func TestSP800_185_LeftEncode(t *testing.T) {
	// NIST SP 800-185 §A.1 examples.
	for _, tc := range []struct {
		x    uint64
		want []byte
	}{
		{0, []byte{0x01, 0x00}},
		{12 * 8, []byte{0x01, 96}}, // 12 bytes = 96 bits
		{255, []byte{0x01, 0xff}},
		{256, []byte{0x02, 0x01, 0x00}},
		{65535, []byte{0x02, 0xff, 0xff}},
		{65536, []byte{0x03, 0x01, 0x00, 0x00}},
	} {
		got := leftEncode(tc.x)
		if !bytes.Equal(got, tc.want) {
			t.Errorf("leftEncode(%d): got %x want %x", tc.x, got, tc.want)
		}
	}
}

func TestSP800_185_RightEncode(t *testing.T) {
	for _, tc := range []struct {
		x    uint64
		want []byte
	}{
		{0, []byte{0x00, 0x01}},
		{255, []byte{0xff, 0x01}},
		{256, []byte{0x01, 0x00, 0x02}},
	} {
		got := rightEncode(tc.x)
		if !bytes.Equal(got, tc.want) {
			t.Errorf("rightEncode(%d): got %x want %x", tc.x, got, tc.want)
		}
	}
}

func TestSP800_185_EncodeString_EmptyInput(t *testing.T) {
	// encode_string("") = left_encode(0) || "" = 0x0100
	got := encodeString([]byte{})
	if !bytes.Equal(got, []byte{0x01, 0x00}) {
		t.Errorf("encodeString(empty): got %x", got)
	}
}

func TestSP800_185_BytepadAligned(t *testing.T) {
	// bytepad("abc", 4): left_encode(4) || "abc" || padding to multiple of 4.
	// left_encode(4) = 0x0104, then "abc" + 1 zero byte = 6 bytes, padded to 8.
	got := bytepad([]byte("abc"), 4)
	if len(got)%4 != 0 {
		t.Errorf("bytepad not aligned: %d bytes", len(got))
	}
	want := append([]byte{0x01, 0x04}, []byte("abc")...)
	for len(want)%4 != 0 {
		want = append(want, 0x00)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("bytepad: got %x want %x", got, want)
	}
}

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
