// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package interoperability exercises the Class N1 manifesto end-to-
// end. Each test in this file loads a KAT vector produced by the
// reference threshold implementation, then verifies the signature
// through an INDEPENDENT FIPS 204 ML-DSA verifier — Cloudflare's
// crypto/sign/mldsa — to demonstrate that the threshold-produced
// signature is admissible by an unmodified FIPS 204 verifier.
//
// This is the load-bearing evidence for the Class N1 output-
// interchangeability claim. If any test in this file fails, the
// submission's headline property has broken: threshold-produced
// signatures must verify under FIPS 204 verification verbatim.
//
// The reference impl's pulsar.Verify() also dispatches to
// cloudflare/circl/sign/mldsa internally (see ref/go/pkg/pulsar/
// verify.go), so the FIPS 204 verifier path is exercised on every
// unit test. This package adds the EXPLICIT acceptance test against
// vectors loaded as opaque bytes — it does not import pulsar.Verify
// at all, only the third-party FIPS 204 verifier. That is the
// independent-verifier discipline NIST asks for.
package interoperability

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

// katVector is the schema of an entry in vectors/{sign,threshold-sign}.json.
// Loaded as opaque bytes — this package deliberately does not import
// the reference implementation. The point is to prove that an
// independent verifier accepts the signature.
type katVector struct {
	Mode      string `json:"mode"`
	Seed      string `json:"seed"`
	PublicKey string `json:"public_key,omitempty"`
	Message   string `json:"message"`
	Context   string `json:"context,omitempty"`
	Signature string `json:"signature"`
}

// vectorsDir is the canonical KAT directory under the repo root.
const vectorsDir = "../../vectors"

// TestN1_SinglePartySignatures_VerifyUnderFIPS204 asserts every
// signature in vectors/sign.json verifies under cloudflare/circl's
// independent FIPS 204 implementation. This is the baseline KAT
// gate: if the reference impl's single-party Sign output does NOT
// verify under circl, the submission is broken before the threshold
// path is even exercised.
//
// vectors/sign.json carries (mode, seed, message, signature). The
// public key is *derived* from the seed by calling circl's
// NewKeyFromSeed directly — circl + ML-DSA keygen is deterministic
// over the 32-byte seed, so this is the exact same pk that the
// reference impl produced.
//
// Doing the derivation here, not loading the pk from keygen.json,
// proves the seed → (pk, sig) chain reaches circl without the
// reference impl in scope. That is the independent-verifier
// discipline at its tightest.
func TestN1_SinglePartySignatures_VerifyUnderFIPS204(t *testing.T) {
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

			if err := verifyUnderFIPS204(v.Mode, pk, msg, sig, ctx); err != nil {
				t.Fatalf("FIPS 204 verify failed under independent verifier: %v\n"+
					"  mode    = %s\n  seed    = %s\n  msg len = %d\n  sig len = %d",
					err, v.Mode, v.Seed, len(msg), len(sig))
			}
		})
	}
}

// TestN1_ThresholdSignatures_VerifyUnderFIPS204 is the *headline*
// Class N1 test: every signature produced by the threshold ceremony
// (DKG → Round-1 → Round-2 → Combine) verifies under the same
// unmodified FIPS 204 verifier used for single-party signatures.
//
// vectors/threshold-sign.json carries (mode, seed, public_key, msg,
// signature). The public_key field is the group public key emitted
// by DKG, NOT a per-party shard. Verify uses it verbatim.
//
// A failure here breaks the headline submission property.
func TestN1_ThresholdSignatures_VerifyUnderFIPS204(t *testing.T) {
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

			if err := verifyUnderFIPS204(v.Mode, pk, msg, sig, ctx); err != nil {
				t.Fatalf(
					"CRITICAL: threshold-produced signature did NOT verify under FIPS 204 verifier.\n"+
						"This breaks the Class N1 output-interchangeability claim.\n"+
						"  err     = %v\n  mode    = %s\n  seed    = %s\n  pk len  = %d\n  sig len = %d",
					err, v.Mode, v.Seed, len(pk), len(sig))
			}
		})
	}
}

// TestN1_TamperedSignatures_Rejected asserts the verifier rejects
// bit-flipped signatures. Closes the trivial "verify always accepts"
// vacuous-pass failure mode: if a flipped-bit signature also
// verified, the test above would be meaningless.
func TestN1_TamperedSignatures_Rejected(t *testing.T) {
	signs := loadVectors(t, filepath.Join(vectorsDir, "sign.json"))
	if len(signs) == 0 {
		t.Fatal("vectors/sign.json is empty")
	}

	// Pick the first vector per mode and flip a byte in the
	// signature. The flipped signature MUST be rejected by the
	// verifier; if it accepts, the verifier itself is broken (or
	// the KAT has an undetected collision).
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

			// Flip one bit roughly in the middle so the tamper is
			// not on a padding byte.
			tampered := append([]byte(nil), sig...)
			tampered[len(tampered)/2] ^= 0x01

			if err := verifyUnderFIPS204(v.Mode, pk, msg, tampered, ctx); err == nil {
				t.Fatal("tampered signature verified successfully — verifier is broken (vacuous pass)")
			}
		})
	}
}

// TestN1_WrongMessage_Rejected asserts that swapping the message
// under a fixed signature is rejected. The verifier MUST bind
// (pk, message, signature) jointly.
func TestN1_WrongMessage_Rejected(t *testing.T) {
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

			if err := verifyUnderFIPS204(v.Mode, pk, wrongMsg, sig, ctx); err == nil {
				t.Fatal("verifier accepted signature against unrelated message — joint binding broken")
			}
		})
	}
}

// derivePublicKeyFromSeed runs circl's deterministic keygen on the
// 32-byte seed and returns the marshalled public key bytes. This is
// the seed → pk mapping that the reference impl uses internally;
// running it here proves the public key the verifier consumes is
// derived by circl alone, with no reference-impl code in scope.
//
// Seed size for ML-DSA is 32 bytes (FIPS 204 §3.3).
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

// verifyUnderFIPS204 dispatches to cloudflare/circl's FIPS 204
// reference verifier for the named ML-DSA mode. This is the
// independent third-party verifier the submission claims byte-
// equality against. Returns nil iff the signature verifies.
//
// circl's API takes (publicKey, message, context, signature) for
// Verify — context may be empty for vectors generated with no
// domain-separation tag.
func verifyUnderFIPS204(mode string, pkBytes, msg, sig, ctx []byte) error {
	switch mode {
	case "Pulsar-44", "ML-DSA-44":
		var pk mldsa44.PublicKey
		if err := pk.UnmarshalBinary(pkBytes); err != nil {
			return fmt.Errorf("mldsa44 unmarshal pk: %w", err)
		}
		if ok := mldsa44.Verify(&pk, msg, ctx, sig); !ok {
			return errors.New("mldsa44.Verify returned false")
		}
		return nil
	case "Pulsar-65", "ML-DSA-65":
		var pk mldsa65.PublicKey
		if err := pk.UnmarshalBinary(pkBytes); err != nil {
			return fmt.Errorf("mldsa65 unmarshal pk: %w", err)
		}
		if ok := mldsa65.Verify(&pk, msg, ctx, sig); !ok {
			return errors.New("mldsa65.Verify returned false")
		}
		return nil
	case "Pulsar-87", "ML-DSA-87":
		var pk mldsa87.PublicKey
		if err := pk.UnmarshalBinary(pkBytes); err != nil {
			return fmt.Errorf("mldsa87 unmarshal pk: %w", err)
		}
		if ok := mldsa87.Verify(&pk, msg, ctx, sig); !ok {
			return errors.New("mldsa87.Verify returned false")
		}
		return nil
	default:
		return fmt.Errorf("unknown mode %q (expect Pulsar-{44,65,87} or ML-DSA-{44,65,87})", mode)
	}
}

// loadVectors reads a JSON array of katVector. Fails the test with a
// descriptive error if the file is missing or malformed — KAT
// regeneration is a deterministic gate; missing vectors mean the
// reproducibility property is broken.
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

// mustHex decodes a hex string or fails the test. KAT vector fields
// are hex-encoded by convention (see vectors/README.md).
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
