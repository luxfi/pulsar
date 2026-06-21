// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build pulsar_pqcrystals

package pulsar

import (
	"errors"
	"testing"

	pqcrystals "github.com/luxfi/pulsar/test/interoperability/pq_crystals"
)

// bcc_sign_pqcrystals_test.go — the pq-crystals leg of the BCC/CEF
// round-trip crown jewel. Built only under the `pulsar_pqcrystals` tag
// (cgo binding to the pq-crystals/dilithium reference FIPS 204 verifier;
// run test/interoperability/pq_crystals/fetch.sh first to build the
// static archive).
//
// This is the SECOND fully-independent FIPS 204 verifier (the first
// being cloudflare/circl). A BCC no-leak signature — whose hint was
// recovered from PUBLIC w' = A·z − c·t1·2^d via FindHint, never from the
// secret residual — must verify under the upstream Dilithium reference
// implementation byte-for-byte. If it does, the carry-elimination claim
// holds under two disjoint verifier codebases.
//
// Run:
//
//	bash test/interoperability/pq_crystals/fetch.sh
//	CGO_ENABLED=1 go test -tags pulsar_pqcrystals ./ref/go/pkg/pulsar/ \
//	    -run BCCSignRoundTripVerifiesPQCrystals -v

// TestBCCSignRoundTripVerifiesPQCrystals runs the full BCC/CEF sign and
// verifies the resulting signature under THREE independent FIPS 204
// verifiers in one shot: (a) the package's own Verify (circl), (b)
// cloudflare/circl directly, and (c) the pq-crystals/dilithium reference
// verifier via cgo. It also runs the no-leak debug oracle on the
// transcript. Byte-for-byte acceptance under both circl and pq-crystals
// is the strongest evidence that the no-leak boundary path yields a
// genuine FIPS 204 ML-DSA signature.
func TestBCCSignRoundTripVerifiesPQCrystals(t *testing.T) {
	for _, mode := range []Mode{ModeP65, ModeP87} {
		mode := mode
		t.Run(mode.String(), func(t *testing.T) {
			message := []byte("Pulsar BCC/CEF no-leak round-trip — pq-crystals cross-validation")
			var ctx []byte

			sig, tr, km, pub := runBCCSign(t, mode, 0x5A, message, ctx)
			params := MustParamsFor(mode)

			// (a) Package's own Verify.
			pk := &PublicKey{Mode: mode, Bytes: pub}
			if err := Verify(params, pk, message, &Signature{Mode: mode, Bytes: sig}); err != nil {
				t.Fatalf("pulsar.Verify rejected BCC signature: %v", err)
			}

			// (b) cloudflare/circl directly.
			verifyUnderCirclFromSeed(t, mode, bccTestSeed(0x5A), message, ctx, sig)

			// (c) pq-crystals/dilithium reference verifier (cgo). The pk
			// must be the FIPS 204 pk encoding; km.pub is exactly that.
			if err := verifyUnderPqCrystalsMode(mode, pub, message, sig, ctx); err != nil {
				t.Fatalf("CRITICAL: BCC no-leak signature REJECTED by pq-crystals reference verifier "+
					"(mode %v): %v\nThis would break the carry-elimination claim under an "+
					"independent verifier codebase.", mode, err)
			}

			// (d) No-leak oracle.
			assertBCCTranscriptNoLeak(t, mode, km, tr)

			t.Logf("%s BCC signature verified under THREE FIPS 204 verifiers "+
				"(own/circl/pq-crystals) in %d attempt(s)", mode.String(), tr.attempts)
		})
	}
}

// TestBCCSignPqCrystalsTamperRejected guards the vacuous-pass hole for
// the pq-crystals verifier specifically: a flipped byte must be rejected.
func TestBCCSignPqCrystalsTamperRejected(t *testing.T) {
	mode := ModeP65
	message := []byte("pq-crystals tamper-evidence")
	sig, _, _, pub := runBCCSign(t, mode, 0x77, message, nil)

	if err := verifyUnderPqCrystalsMode(mode, pub, message, sig, nil); err != nil {
		t.Fatalf("baseline BCC signature rejected by pq-crystals: %v", err)
	}
	tampered := append([]byte(nil), sig...)
	tampered[len(tampered)/2] ^= 0x01
	if err := verifyUnderPqCrystalsMode(mode, pub, message, tampered, nil); err == nil {
		t.Fatal("tampered BCC signature accepted by pq-crystals — verifier vacuous")
	}
}

// verifyUnderPqCrystalsMode dispatches to the pq-crystals cgo binding for
// the given mode.
func verifyUnderPqCrystalsMode(mode Mode, pk, msg, sig, ctx []byte) error {
	switch mode {
	case ModeP65:
		return pqcrystals.VerifyMLDSA65(pk, msg, sig, ctx)
	case ModeP87:
		return pqcrystals.VerifyMLDSA87(pk, msg, sig, ctx)
	default:
		return errors.New("pulsar: pq-crystals BCC round-trip does not support mode " + mode.String())
	}
}
