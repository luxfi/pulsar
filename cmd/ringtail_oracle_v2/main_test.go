package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestEmitDeterministic runs emitAll twice into separate dirs and asserts
// byte-equality across all seven files. This is the core invariant: the C++
// and GPU ports validate against these JSONs, so they must be reproducible.
func TestEmitDeterministic(t *testing.T) {
	d1 := t.TempDir()
	d2 := t.TempDir()
	if err := emitAll(d1); err != nil {
		t.Fatalf("first emit: %v", err)
	}
	if err := emitAll(d2); err != nil {
		t.Fatalf("second emit: %v", err)
	}
	for _, name := range []string{
		"prng_blake2_xof.json",
		"discrete_gaussian.json",
		"montgomery_ntt.json",
		"structs_matrix_wire.json",
		"transcript_hash.json",
		"shamir_share.json",
		"sign_verify_e2e.json",
	} {
		b1, err := os.ReadFile(filepath.Join(d1, name))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		b2, err := os.ReadFile(filepath.Join(d2, name))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !bytes.Equal(b1, b2) {
			h1 := sha256.Sum256(b1)
			h2 := sha256.Sum256(b2)
			t.Fatalf("%s not deterministic: run1=%x run2=%x", name, h1, h2)
		}
	}
}

// TestSignVerifyEntries asserts every entry in sign_verify_e2e.json has
// verify=true. The emitter already guards Verify with an error return, but
// we re-read the JSON to make sure no entry slipped through with a bad bool.
func TestSignVerifyEntries(t *testing.T) {
	d := t.TempDir()
	if err := emitSignVerify(d); err != nil {
		t.Fatalf("emitSignVerify: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(d, "sign_verify_e2e.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Entries []struct {
			T      int  `json:"t"`
			N      int  `json:"n"`
			Verify bool `json:"verify"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Entries) != 16 {
		t.Fatalf("expected 16 entries, got %d", len(doc.Entries))
	}
	for i, e := range doc.Entries {
		if !e.Verify {
			t.Fatalf("entry %d (t=%d, n=%d): Verify=false", i, e.T, e.N)
		}
	}
}

// TestShamirRoundTrip asserts every Shamir entry self-recovered.
func TestShamirRoundTrip(t *testing.T) {
	d := t.TempDir()
	if err := emitShamir(d); err != nil {
		t.Fatalf("emitShamir: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(d, "shamir_share.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Entries []struct {
			T     int  `json:"t"`
			N     int  `json:"n"`
			Match bool `json:"match"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Entries) == 0 {
		t.Fatal("no entries")
	}
	for i, e := range doc.Entries {
		if !e.Match {
			t.Fatalf("entry %d (t=%d, n=%d): Match=false", i, e.T, e.N)
		}
	}
}
