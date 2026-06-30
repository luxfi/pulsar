// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// signer_test.go — the fail-closed contract: with the default engine, pulsard
// produces NO signature; and the Signer validates its inputs up front.

package pulsard_test

import (
	"errors"
	"testing"

	"github.com/luxfi/pulsar/pkg/pulsard"
	"github.com/luxfi/warp"
)

// validEra returns a well-formed era (real group key) WITHOUT a usable engine
// attached — for testing the default fail-closed path.
func validEra(t *testing.T) warp.PulsarKeyEra {
	t.Helper()
	_, era, err := pulsard.NewReferenceDealer(
		testID("chain"), testID("signer-set"), 7, 0, 0, testThreshold, nil)
	if err != nil {
		t.Fatalf("NewReferenceDealer: %v", err)
	}
	return era
}

// TestSigner_DefaultEngine_FailsClosed asserts the DEFAULT engine never signs:
// ThresholdSign and Reshare both return ErrThresholdMLDSAUnimplemented. This is
// the core honesty guarantee — no real dealerless engine, no signature.
func TestSigner_DefaultEngine_FailsClosed(t *testing.T) {
	era := validEra(t)
	signer, err := pulsard.New(era) // no WithEngine → Unimplemented()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if signer.Engine() != "talus-unimplemented" {
		t.Errorf("default engine = %q, want talus-unimplemented", signer.Engine())
	}

	_, err = signer.ThresholdSign(subject32("anything"))
	if !errors.Is(err, pulsard.ErrThresholdMLDSAUnimplemented) {
		t.Fatalf("ThresholdSign err = %v, want ErrThresholdMLDSAUnimplemented", err)
	}
	if err := signer.Reshare(); !errors.Is(err, pulsard.ErrThresholdMLDSAUnimplemented) {
		t.Fatalf("Reshare err = %v, want ErrThresholdMLDSAUnimplemented", err)
	}
}

// TestSigner_RejectsBadSubject asserts the subject-width gate fires BEFORE the
// engine: even the reference signer refuses a non-32-byte subject.
func TestSigner_RejectsBadSubject(t *testing.T) {
	signer, _ := newRefSigner(t)
	for _, n := range []int{0, 31, 33, 64} {
		if _, err := signer.ThresholdSign(make([]byte, n)); !errors.Is(err, pulsard.ErrBadSubject) {
			t.Errorf("ThresholdSign(%d bytes) err = %v, want ErrBadSubject", n, err)
		}
	}
}

// TestNew_RejectsMisconfiguredEra asserts New fails closed for a wrong suite or
// a malformed group key — a misconfigured era never yields a Signer.
func TestNew_RejectsMisconfiguredEra(t *testing.T) {
	good := validEra(t)

	wrongSuite := good
	wrongSuite.SchemeID = warp.SuiteCoronaRingtailSHA3
	if _, err := pulsard.New(wrongSuite); err == nil {
		t.Error("New accepted an era with a non-Pulsar suite")
	}

	badKey := good
	badKey.MLDSAPubKey = []byte{0x00, 0x01, 0x02}
	if _, err := pulsard.New(badKey); !errors.Is(err, pulsard.ErrBadGroupKey) {
		t.Errorf("New(malformed key) err = %v, want ErrBadGroupKey", err)
	}
}

// maliciousReshareEngine returns a reshare that CHANGES the group key — which
// the Signer must reject (a reshare must preserve the public key).
type maliciousReshareEngine struct{ pulsard.ThresholdEngine }

func (maliciousReshareEngine) Name() string { return "malicious-reshare" }
func (maliciousReshareEngine) Reshare(era warp.PulsarKeyEra) (warp.PulsarKeyEra, error) {
	era.Generation++
	era.MLDSAPubKey = append([]byte(nil), era.MLDSAPubKey...)
	era.MLDSAPubKey[0] ^= 0xFF // change the key
	return era, nil
}

// TestReshare_RejectsKeyChange asserts Signer.Reshare refuses an engine that
// changes the group public key (that would be a keygen, not a refresh, and would
// break old signatures).
func TestReshare_RejectsKeyChange(t *testing.T) {
	era := validEra(t)
	signer, err := pulsard.New(era, pulsard.WithEngine(maliciousReshareEngine{}))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := signer.Reshare(); err == nil {
		t.Fatal("Reshare accepted a key-changing reshare")
	}
}
