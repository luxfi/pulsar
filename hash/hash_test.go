// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package hash

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

// TestSuiteIDs ensures the two suites declare distinct, stable IDs.
func TestSuiteIDs(t *testing.T) {
	sha3 := NewPulsarSHA3()
	bl3 := NewPulsarBLAKE3()

	if sha3.ID() != "Pulsar-SHA3" {
		t.Errorf("SHA3 suite ID: want Pulsar-SHA3, got %q", sha3.ID())
	}
	if bl3.ID() != "Pulsar-BLAKE3" {
		t.Errorf("BLAKE3 suite ID: want Pulsar-BLAKE3, got %q", bl3.ID())
	}
	if sha3.ID() == bl3.ID() {
		t.Error("SHA3 and BLAKE3 suites must declare distinct IDs")
	}
	if Default().ID() != DefaultID {
		t.Errorf("Default ID: want %q got %q", DefaultID, Default().ID())
	}
}

// TestDefaultIsSHA3 — production default must be SHA3.
func TestDefaultIsSHA3(t *testing.T) {
	if Default().ID() != "Pulsar-SHA3" {
		t.Fatalf("production default must be SHA3; got %q", Default().ID())
	}
}

// TestResolveNil — nil resolves to default.
func TestResolveNil(t *testing.T) {
	if Resolve(nil).ID() != DefaultID {
		t.Errorf("Resolve(nil) must return the production default")
	}
	bl3 := NewPulsarBLAKE3()
	if Resolve(bl3).ID() != bl3.ID() {
		t.Errorf("Resolve(suite) must return that suite")
	}
}

// TestSuitesProduceDifferentBytes — two suites with distinct IDs must
// produce distinct bytes for the same input.
func TestSuitesProduceDifferentBytes(t *testing.T) {
	sha3 := NewPulsarSHA3()
	bl3 := NewPulsarBLAKE3()

	t1 := sha3.TranscriptHash([]byte("a"), []byte("b"))
	t2 := bl3.TranscriptHash([]byte("a"), []byte("b"))
	if t1 == t2 {
		t.Errorf("TranscriptHash collision across SHA3/BLAKE3 — wrong domain separation")
	}

	if bytes.Equal(sha3.Hc([]byte("x")), bl3.Hc([]byte("x"))) {
		t.Errorf("Hc collision across SHA3/BLAKE3")
	}
	if bytes.Equal(sha3.Hu([]byte("x"), 32), bl3.Hu([]byte("x"), 32)) {
		t.Errorf("Hu collision across SHA3/BLAKE3")
	}
	if bytes.Equal(sha3.PRF([]byte("k"), []byte("m"), 32), bl3.PRF([]byte("k"), []byte("m"), 32)) {
		t.Errorf("PRF collision across SHA3/BLAKE3")
	}
	if bytes.Equal(sha3.MAC([]byte("k"), []byte("m"), 32), bl3.MAC([]byte("k"), []byte("m"), 32)) {
		t.Errorf("MAC collision across SHA3/BLAKE3")
	}
}

// TestPRFAndMACDifferByCustomization — same suite, same key, same
// message, but PRF and MAC must produce distinct bytes.
func TestPRFAndMACDifferByCustomization(t *testing.T) {
	for _, s := range []HashSuite{NewPulsarSHA3(), NewPulsarBLAKE3()} {
		key := []byte("00000000000000000000000000000000") // 32 bytes
		msg := []byte("same-message")
		prf := s.PRF(key, msg, 32)
		mac := s.MAC(key, msg, 32)
		if bytes.Equal(prf, mac) {
			t.Errorf("%s: PRF and MAC must differ by customization tag", s.ID())
		}
	}
}

// TestHcAndHuDifferByCustomization — same suite, same input, different
// tags → different bytes.
func TestHcAndHuDifferByCustomization(t *testing.T) {
	for _, s := range []HashSuite{NewPulsarSHA3(), NewPulsarBLAKE3()} {
		hc := s.Hc([]byte("transcript"))
		hu := s.Hu([]byte("transcript"), 32)
		if bytes.Equal(hc, hu) {
			t.Errorf("%s: Hc and Hu must differ by tag", s.ID())
		}
	}
}

// TestTranscriptHashAvoidsConcatenationCollisions — TupleHash framing
// must reject two distinct lists whose naive concatenation is identical.
func TestTranscriptHashAvoidsConcatenationCollisions(t *testing.T) {
	for _, s := range []HashSuite{NewPulsarSHA3(), NewPulsarBLAKE3()} {
		a := s.TranscriptHash([]byte("abc"), []byte(""))
		b := s.TranscriptHash([]byte("a"), []byte("bc"))
		if a == b {
			t.Errorf("%s: TranscriptHash collided on different field splits — framing broken", s.ID())
		}
		c := s.TranscriptHash([]byte("ab"), []byte("c"))
		if a == c || b == c {
			t.Errorf("%s: TranscriptHash collided on different field splits", s.ID())
		}
	}
}

// TestPairwiseCanonicalOrdering — DerivePairwise must produce the same
// bytes for (i, j) and (j, i).
func TestPairwiseCanonicalOrdering(t *testing.T) {
	for _, s := range []HashSuite{NewPulsarSHA3(), NewPulsarBLAKE3()} {
		kex := []byte("0123456789abcdef0123456789abcdef")
		ab := s.DerivePairwise(kex, []byte("chain"), []byte("group"), 7, 3, 2, 5, 32)
		ba := s.DerivePairwise(kex, []byte("chain"), []byte("group"), 7, 3, 5, 2, 32)
		if !bytes.Equal(ab, ba) {
			t.Errorf("%s: DerivePairwise must be symmetric in (i, j)", s.ID())
		}
	}
}

// TestPairwiseDistinctEras — different (era, generation) MUST yield
// different pairwise material.
func TestPairwiseDistinctEras(t *testing.T) {
	for _, s := range []HashSuite{NewPulsarSHA3(), NewPulsarBLAKE3()} {
		kex := []byte("0123456789abcdef0123456789abcdef")
		base := s.DerivePairwise(kex, []byte("chain"), []byte("group"), 7, 3, 2, 5, 32)
		era2 := s.DerivePairwise(kex, []byte("chain"), []byte("group"), 8, 3, 2, 5, 32)
		gen2 := s.DerivePairwise(kex, []byte("chain"), []byte("group"), 7, 4, 2, 5, 32)
		ch2 := s.DerivePairwise(kex, []byte("CHAIN"), []byte("group"), 7, 3, 2, 5, 32)
		if bytes.Equal(base, era2) {
			t.Errorf("%s: era change did not affect pairwise output", s.ID())
		}
		if bytes.Equal(base, gen2) {
			t.Errorf("%s: generation change did not affect pairwise output", s.ID())
		}
		if bytes.Equal(base, ch2) {
			t.Errorf("%s: chain_id change did not affect pairwise output", s.ID())
		}
	}
}

// ─── NIST SP 800-185 vector smoke tests ─────────────────────────────

func TestLeftEncode(t *testing.T) {
	cases := []struct {
		x    uint64
		want string
	}{
		{0, "0100"},
		{12, "010c"},
		{255, "01ff"},
		{256, "020100"},
		{65535, "02ffff"},
		{65536, "03010000"},
	}
	for _, c := range cases {
		got := hex.EncodeToString(leftEncode(c.x))
		if got != c.want {
			t.Errorf("leftEncode(%d): want %s got %s", c.x, c.want, got)
		}
	}
}

func TestRightEncode(t *testing.T) {
	cases := []struct {
		x    uint64
		want string
	}{
		{0, "0001"},
		{12, "0c01"},
		{256, "010002"},
	}
	for _, c := range cases {
		got := hex.EncodeToString(rightEncode(c.x))
		if got != c.want {
			t.Errorf("rightEncode(%d): want %s got %s", c.x, c.want, got)
		}
	}
}

// TestKMAC256NISTVector — Sample #4 from NIST SP 800-185 KMAC-Samples.
func TestKMAC256NISTVector(t *testing.T) {
	K, _ := hex.DecodeString("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F")
	X, _ := hex.DecodeString("00010203")
	S := "My Tagged Application"
	want := "20C570C31346F703C9AC36C61C03CB64C3970D0CFC787E9B79599D273A68D2F7" +
		"F69D4CC3DE9D104A351689F27CF6F5951F0103F33F4F24871024D9C27773A8DD"

	got := hex.EncodeToString(kmac256(K, X, 64, S))
	wantLower := strings.ToLower(want[:128])
	if got != wantLower {
		t.Errorf("KMAC256: \nwant %s\n got %s", wantLower, got)
	}
}

// TestTupleHash256NISTVector — Sample #4 from NIST SP 800-185 TupleHash-Samples.
func TestTupleHash256NISTVector(t *testing.T) {
	x1, _ := hex.DecodeString("000102")
	x2, _ := hex.DecodeString("101112131415")
	x3, _ := hex.DecodeString("202122232425262728")
	S := "My Tuple App"
	want := "45000BE63F9B6BFD89F54717670F69A9BC763591A4F05C50D68891A744BCC6E7" +
		"D6D5B5E82C018DA999ED35B0BB49C9678E526ABD8E85C13ED254021DB9E790CE"

	got := hex.EncodeToString(tupleHash256([][]byte{x1, x2, x3}, 64, S))
	wantLower := strings.ToLower(want[:128])
	if got != wantLower {
		t.Errorf("TupleHash256:\nwant %s\n got %s", wantLower, got)
	}
}

// TestSuiteDeterminism — same input, two calls, identical bytes.
func TestSuiteDeterminism(t *testing.T) {
	for _, s := range []HashSuite{NewPulsarSHA3(), NewPulsarBLAKE3()} {
		a := s.TranscriptHash([]byte("a"), []byte("b"))
		b := s.TranscriptHash([]byte("a"), []byte("b"))
		if a != b {
			t.Errorf("%s: TranscriptHash not deterministic", s.ID())
		}
		if !bytes.Equal(s.Hc([]byte("x")), s.Hc([]byte("x"))) {
			t.Errorf("%s: Hc not deterministic", s.ID())
		}
		if !bytes.Equal(s.Hu([]byte("x"), 32), s.Hu([]byte("x"), 32)) {
			t.Errorf("%s: Hu not deterministic", s.ID())
		}
	}
}
