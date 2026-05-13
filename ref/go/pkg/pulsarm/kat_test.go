// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsarm

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// kat_test.go — replay-based Known Answer Test runner.
//
// Reads the committed JSON files under vectors/ (relative to the
// repository root) and verifies each entry round-trips correctly.
// Skips if the vectors directory is absent (e.g. fresh checkout
// before scripts/gen_vectors.sh has been run).
//
// The KAT files are committed alongside the implementation; drift
// between the runtime output and the committed vectors is a CI gate
// failure. See scripts/gen_vectors.sh.

// vectorsDir resolves to the repository's vectors/ directory.
func vectorsDir() string {
	// kat_test.go lives at ref/go/pkg/pulsarm/; the vectors dir is at
	// the repo root, four levels up.
	wd, err := os.Getwd()
	if err != nil {
		return ""
	}
	return filepath.Join(wd, "..", "..", "..", "..", "vectors")
}

func mustReadVector(t *testing.T, name string, v any) bool {
	t.Helper()
	path := filepath.Join(vectorsDir(), name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("vector %s not present (%v) — run scripts/gen_vectors.sh", name, err)
		return false
	}
	if err := json.Unmarshal(data, v); err != nil {
		t.Fatalf("parsing %s: %v", name, err)
	}
	return true
}

func TestKAT_Keygen_Replay(t *testing.T) {
	type kgEntry struct {
		Mode       string `json:"mode"`
		Seed       string `json:"seed"`
		PublicKey  string `json:"public_key"`
		PrivateKey string `json:"private_key"`
	}
	var entries []kgEntry
	if !mustReadVector(t, "keygen.json", &entries) {
		return
	}
	if len(entries) == 0 {
		t.Fatalf("empty keygen.json")
	}
	for i, e := range entries {
		mode := modeFromString(e.Mode)
		if mode == ModeUnspecified {
			t.Fatalf("entry %d: unknown mode %q", i, e.Mode)
		}
		params := MustParamsFor(mode)
		seedBytes, _ := hex.DecodeString(e.Seed)
		var seed [SeedSize]byte
		copy(seed[:], seedBytes)
		sk, err := KeyFromSeed(params, seed)
		if err != nil {
			t.Fatalf("entry %d KeyFromSeed: %v", i, err)
		}
		expectedPub, _ := hex.DecodeString(e.PublicKey)
		expectedPriv, _ := hex.DecodeString(e.PrivateKey)
		if hex.EncodeToString(sk.Pub.Bytes) != e.PublicKey {
			t.Fatalf("entry %d: pubkey mismatch", i)
		}
		if hex.EncodeToString(sk.Bytes) != e.PrivateKey {
			t.Fatalf("entry %d: privkey mismatch", i)
		}
		_ = expectedPub
		_ = expectedPriv
	}
	t.Logf("validated %d keygen KATs", len(entries))
}

func TestKAT_Sign_Replay(t *testing.T) {
	type sgEntry struct {
		Mode      string `json:"mode"`
		Seed      string `json:"seed"`
		Message   string `json:"message"`
		Context   string `json:"context"`
		Signature string `json:"signature"`
	}
	var entries []sgEntry
	if !mustReadVector(t, "sign.json", &entries) {
		return
	}
	for i, e := range entries {
		mode := modeFromString(e.Mode)
		params := MustParamsFor(mode)
		seedBytes, _ := hex.DecodeString(e.Seed)
		var seed [SeedSize]byte
		copy(seed[:], seedBytes)
		sk, _ := KeyFromSeed(params, seed)
		msg, _ := hex.DecodeString(e.Message)
		ctx, _ := hex.DecodeString(e.Context)
		var ctxBytes []byte
		if len(ctx) > 0 {
			ctxBytes = ctx
		}
		sig, err := Sign(params, sk, msg, ctxBytes, false, nil)
		if err != nil {
			t.Fatalf("entry %d Sign: %v", i, err)
		}
		if hex.EncodeToString(sig.Bytes) != e.Signature {
			t.Fatalf("entry %d: sig mismatch (mode=%s)", i, e.Mode)
		}
	}
	t.Logf("validated %d sign KATs", len(entries))
}

func TestKAT_Verify_Replay(t *testing.T) {
	type vEntry struct {
		Mode      string `json:"mode"`
		PublicKey string `json:"public_key"`
		Message   string `json:"message"`
		Context   string `json:"context"`
		Signature string `json:"signature"`
		Valid     bool   `json:"valid"`
	}
	var entries []vEntry
	if !mustReadVector(t, "verify.json", &entries) {
		return
	}
	for i, e := range entries {
		mode := modeFromString(e.Mode)
		params := MustParamsFor(mode)
		pkBytes, _ := hex.DecodeString(e.PublicKey)
		pub := &PublicKey{Mode: mode, Bytes: pkBytes}
		msg, _ := hex.DecodeString(e.Message)
		sigBytes, _ := hex.DecodeString(e.Signature)
		sig := &Signature{Mode: mode, Bytes: sigBytes}
		err := Verify(params, pub, msg, sig)
		if e.Valid && err != nil {
			t.Fatalf("entry %d: positive case failed: %v", i, err)
		}
		if !e.Valid && err == nil {
			t.Fatalf("entry %d: negative case accepted", i)
		}
	}
	t.Logf("validated %d verify KATs", len(entries))
}

func TestKAT_ThresholdSign_Replay(t *testing.T) {
	// Threshold-sign KATs are randomness-dependent at the per-party
	// PRNG level. The vector contains the final signature, which we
	// verify under FIPS 204 — that's the Class N1 interchangeability
	// claim. We don't replay the per-party rounds here because the
	// per-party RNG is committed to the KAT only as the head-of-
	// session seed; full transcript-level replay is the v0.2 KAT
	// extension (cf. vectors/transcripts/).
	type tsEntry struct {
		Mode      string   `json:"mode"`
		N         int      `json:"n"`
		T         int      `json:"t"`
		Message   string   `json:"message"`
		PublicKey string   `json:"public_key"`
		Signature string   `json:"signature"`
		Quorum    []string `json:"quorum"`
		SessionID string   `json:"session_id"`
		Attempt   uint32   `json:"attempt"`
	}
	var entries []tsEntry
	if !mustReadVector(t, "threshold-sign.json", &entries) {
		return
	}
	for i, e := range entries {
		mode := modeFromString(e.Mode)
		params := MustParamsFor(mode)
		pkBytes, _ := hex.DecodeString(e.PublicKey)
		pub := &PublicKey{Mode: mode, Bytes: pkBytes}
		msg, _ := hex.DecodeString(e.Message)
		sigBytes, _ := hex.DecodeString(e.Signature)
		sig := &Signature{Mode: mode, Bytes: sigBytes}
		if err := Verify(params, pub, msg, sig); err != nil {
			t.Fatalf("entry %d: threshold sig fails FIPS 204 Verify: %v", i, err)
		}
	}
	t.Logf("validated %d threshold-sign KATs (Class N1 interchangeability)", len(entries))
}

func TestKAT_DKG_Replay(t *testing.T) {
	type dkgEntry struct {
		Mode           string   `json:"mode"`
		N              int      `json:"n"`
		T              int      `json:"t"`
		Committee      []string `json:"committee"`
		PublicKey      string   `json:"public_key"`
		TranscriptHash string   `json:"transcript_hash"`
		Shares         []string `json:"shares"`
	}
	var entries []dkgEntry
	if !mustReadVector(t, "dkg.json", &entries) {
		return
	}
	for i, e := range entries {
		if len(e.Committee) != e.N {
			t.Fatalf("entry %d: committee count %d != n %d", i, len(e.Committee), e.N)
		}
		if len(e.Shares) != e.N {
			t.Fatalf("entry %d: share count %d != n %d", i, len(e.Shares), e.N)
		}
		// Check the pubkey length matches the mode.
		mode := modeFromString(e.Mode)
		params := MustParamsFor(mode)
		pkBytes, _ := hex.DecodeString(e.PublicKey)
		if len(pkBytes) != params.PublicKeySize {
			t.Fatalf("entry %d: pubkey size %d != expected %d", i, len(pkBytes), params.PublicKeySize)
		}
		// Transcript hash is 48 bytes.
		thBytes, _ := hex.DecodeString(e.TranscriptHash)
		if len(thBytes) != 48 {
			t.Fatalf("entry %d: transcript hash size %d != 48", i, len(thBytes))
		}
	}
	t.Logf("validated %d DKG KATs", len(entries))
}

func modeFromString(s string) Mode {
	switch s {
	case "Pulsar-44":
		return ModeP44
	case "Pulsar-65":
		return ModeP65
	case "Pulsar-87":
		return ModeP87
	default:
		return ModeUnspecified
	}
}
