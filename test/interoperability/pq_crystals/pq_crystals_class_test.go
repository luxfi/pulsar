// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Cross-validation of every Pulsar KAT signature against the
// pq-crystals/dilithium reference FIPS 204 verifier.
//
// This file mirrors test/interoperability/n1_class_test.go subtest
// for subtest. The only difference is the verifier under test: every
// test here dispatches to pq_crystals.Verify* (a cgo binding to the
// upstream reference verifier) instead of cloudflare/circl. Both
// verifiers must accept the same KAT vectors for the cross-validation
// gate to pass.
//
// Tagged build constraint: `pulsar_pqcrystals`. The default Pulsar
// build does not have the static archive available; the cross-
// validation gate sets the tag and runs fetch.sh first.

//go:build pulsar_pqcrystals

package pq_crystals

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	// Public-key derivation from KAT seed uses cloudflare/circl's
	// deterministic keygen — the same convention as n1_class_test.go.
	// This is NOT a violation of "independent verifier" because the
	// VERIFICATION uses pq-crystals; circl is only used here to
	// reproduce the (deterministic) seed → pk mapping the reference
	// impl used at vector-generation time.
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

// katVector mirrors the schema in n1_class_test.go. We deliberately
// duplicate the struct rather than import — the cross-validation
// suites are independently buildable, and this binding sits behind
// a build tag.
type katVector struct {
	Mode      string `json:"mode"`
	Seed      string `json:"seed"`
	PublicKey string `json:"public_key,omitempty"`
	Message   string `json:"message"`
	Context   string `json:"context,omitempty"`
	Signature string `json:"signature"`
}

// vectorsDir is the canonical KAT directory under the repo root.
// From test/interoperability/pq_crystals/ it is three levels up.
const vectorsDir = "../../../vectors"

// TestN1_PqCrystals_SinglePartySignatures_VerifyUnderRef asserts
// every single-party signature in vectors/sign.json verifies under
// the pq-crystals/dilithium reference FIPS 204 verifier — the
// SECOND independent verifier the Pulsar submission cross-validates
// against (the first being cloudflare/circl in n1_class_test.go).
//
// Both verifiers must accept the same KAT. A disagreement is
// either (a) a Pulsar bug that one verifier catches and the other
// misses, or (b) a verifier disagreement worth tracking upstream.
// Either way it is a release blocker — see scripts/checks/test/
// interop.sh.
func TestN1_PqCrystals_SinglePartySignatures_VerifyUnderRef(t *testing.T) {
	signs := loadVectors(t, filepath.Join(vectorsDir, "sign.json"))
	if len(signs) == 0 {
		t.Fatal("vectors/sign.json is empty — run scripts/gen_vectors.sh")
	}

	for i, v := range signs {
		t.Run(fmt.Sprintf("%s/%d", v.Mode, i), func(t *testing.T) {
			seed := mustHex(t, v.Seed)
			pk, err := derivePublicKeyFromSeed(v.Mode, seed)
			if err != nil {
				t.Fatalf("derive pk from seed: %v", err)
			}

			msg := mustHex(t, v.Message)
			sig := mustHex(t, v.Signature)
			ctx := mustHex(t, v.Context)

			if err := verifyUnderPqCrystals(v.Mode, pk, msg, sig, ctx); err != nil {
				t.Fatalf("pq-crystals verify failed: %v\n"+
					"  mode    = %s\n  seed    = %s\n  msg len = %d\n  sig len = %d",
					err, v.Mode, v.Seed, len(msg), len(sig))
			}
		})
	}
}

// TestN1_PqCrystals_ThresholdSignatures_VerifyUnderRef is the
// headline Class N1 cross-validation: every threshold-produced
// signature in vectors/threshold-sign.json verifies under the
// pq-crystals reference verifier. If any KAT here is rejected,
// the byte-equality claim has broken under an independent verifier.
func TestN1_PqCrystals_ThresholdSignatures_VerifyUnderRef(t *testing.T) {
	tsigns := loadVectors(t, filepath.Join(vectorsDir, "threshold-sign.json"))
	if len(tsigns) == 0 {
		t.Fatal("vectors/threshold-sign.json is empty — run scripts/gen_vectors.sh")
	}

	for i, v := range tsigns {
		t.Run(fmt.Sprintf("%s/%d", v.Mode, i), func(t *testing.T) {
			if v.PublicKey == "" {
				t.Fatalf("threshold-sign.json entry %d missing public_key field", i)
			}
			pk := mustHex(t, v.PublicKey)
			msg := mustHex(t, v.Message)
			sig := mustHex(t, v.Signature)
			ctx := mustHex(t, v.Context)

			if err := verifyUnderPqCrystals(v.Mode, pk, msg, sig, ctx); err != nil {
				t.Fatalf(
					"CRITICAL: threshold-produced signature did NOT verify under "+
						"pq-crystals/dilithium reference verifier.\n"+
						"This breaks Class N1 byte-equality under an independent verifier.\n"+
						"  err     = %v\n  mode    = %s\n  seed    = %s\n  pk len  = %d\n  sig len = %d",
					err, v.Mode, v.Seed, len(pk), len(sig))
			}
		})
	}
}

// TestN1_PqCrystals_TamperedSignatures_Rejected guards against the
// "verifier always accepts" vacuous pass — exactly mirrors the
// circl-side test in n1_class_test.go.
func TestN1_PqCrystals_TamperedSignatures_Rejected(t *testing.T) {
	signs := loadVectors(t, filepath.Join(vectorsDir, "sign.json"))
	if len(signs) == 0 {
		t.Fatal("vectors/sign.json is empty")
	}

	seen := map[string]bool{}
	for _, v := range signs {
		if seen[v.Mode] {
			continue
		}
		seen[v.Mode] = true

		t.Run(v.Mode, func(t *testing.T) {
			seed := mustHex(t, v.Seed)
			pk, err := derivePublicKeyFromSeed(v.Mode, seed)
			if err != nil {
				t.Fatalf("derive pk: %v", err)
			}
			msg := mustHex(t, v.Message)
			sig := mustHex(t, v.Signature)
			ctx := mustHex(t, v.Context)

			tampered := append([]byte(nil), sig...)
			tampered[len(tampered)/2] ^= 0x01

			if err := verifyUnderPqCrystals(v.Mode, pk, msg, tampered, ctx); err == nil {
				t.Fatal("tampered signature verified successfully under pq-crystals — verifier is broken (vacuous pass)")
			}
		})
	}
}

// TestN1_PqCrystals_WrongMessage_Rejected asserts joint
// (pk, message, signature) binding under the pq-crystals verifier.
func TestN1_PqCrystals_WrongMessage_Rejected(t *testing.T) {
	signs := loadVectors(t, filepath.Join(vectorsDir, "sign.json"))

	seen := map[string]bool{}
	for _, v := range signs {
		if seen[v.Mode] {
			continue
		}
		seen[v.Mode] = true

		t.Run(v.Mode, func(t *testing.T) {
			seed := mustHex(t, v.Seed)
			pk, err := derivePublicKeyFromSeed(v.Mode, seed)
			if err != nil {
				t.Fatalf("derive pk: %v", err)
			}
			sig := mustHex(t, v.Signature)
			ctx := mustHex(t, v.Context)
			wrongMsg := []byte("not the original message")

			if err := verifyUnderPqCrystals(v.Mode, pk, wrongMsg, sig, ctx); err == nil {
				t.Fatal("pq-crystals verifier accepted signature against unrelated message — joint binding broken")
			}
		})
	}
}

// derivePublicKeyFromSeed mirrors n1_class_test.go. We use circl's
// deterministic keygen to obtain the public key bytes — pq-crystals
// uses an internal randombytes path for keygen which our binding
// deliberately does not link, so circl is the deterministic
// substitute. The keygen output is FIPS 204 §3.5.5 byte-for-byte
// identical to pq-crystals' keygen on the same seed (this is
// itself one of the cross-validation invariants Pulsar relies on;
// see ref/go/pkg/pulsar/keygen.go).
func derivePublicKeyFromSeed(mode string, seedBytes []byte) ([]byte, error) {
	if len(seedBytes) != 32 {
		return nil, fmt.Errorf("seed must be 32 bytes, got %d", len(seedBytes))
	}
	var seed [32]byte
	copy(seed[:], seedBytes)

	switch mode {
	case "Pulsar-44", "ML-DSA-44":
		pk, _ := mldsa44.NewKeyFromSeed(&seed)
		return pk.MarshalBinary()
	case "Pulsar-65", "ML-DSA-65":
		pk, _ := mldsa65.NewKeyFromSeed(&seed)
		return pk.MarshalBinary()
	case "Pulsar-87", "ML-DSA-87":
		pk, _ := mldsa87.NewKeyFromSeed(&seed)
		return pk.MarshalBinary()
	default:
		return nil, fmt.Errorf("unknown mode %q", mode)
	}
}

// verifyUnderPqCrystals dispatches to the cgo binding for the
// named ML-DSA parameter set.
func verifyUnderPqCrystals(mode string, pk, msg, sig, ctx []byte) error {
	switch mode {
	case "Pulsar-44", "ML-DSA-44":
		return VerifyMLDSA44(pk, msg, sig, ctx)
	case "Pulsar-65", "ML-DSA-65":
		return VerifyMLDSA65(pk, msg, sig, ctx)
	case "Pulsar-87", "ML-DSA-87":
		return VerifyMLDSA87(pk, msg, sig, ctx)
	default:
		return fmt.Errorf("unknown mode %q (expect Pulsar-{44,65,87} or ML-DSA-{44,65,87})", mode)
	}
}

// loadVectors reads a JSON array of katVector.
func loadVectors(t *testing.T, path string) []katVector {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v\n(hint: run scripts/gen_vectors.sh)", path, err)
	}
	var out []katVector
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return out
}

// mustHex decodes a hex string or fails the test.
func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	if s == "" {
		return nil
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode hex %q: %v", s, err)
	}
	return b
}
