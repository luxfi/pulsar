// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package threshold

import (
	"testing"
)

func TestGenerateKeys(t *testing.T) {
	shares, groupKey, err := GenerateKeys(2, 3, nil)
	if err != nil {
		t.Fatalf("GenerateKeys failed: %v", err)
	}

	if len(shares) != 3 {
		t.Errorf("expected 3 shares, got %d", len(shares))
	}
	if groupKey == nil {
		t.Fatal("groupKey is nil")
	}
	if groupKey.A == nil {
		t.Error("groupKey.A is nil")
	}
	if groupKey.BTilde == nil {
		t.Error("groupKey.BTilde is nil")
	}

	for i, share := range shares {
		if share.Index != i {
			t.Errorf("share %d has index %d", i, share.Index)
		}
		if share.GroupKey != groupKey {
			t.Errorf("share %d has wrong groupKey", i)
		}
	}
}

func TestThresholdSigningFlow(t *testing.T) {
	// Generate 2-of-3 threshold keys
	shares, groupKey, err := GenerateKeys(2, 3, nil)
	if err != nil {
		t.Fatalf("GenerateKeys failed: %v", err)
	}

	// Create signers for all parties
	signers := make([]*Signer, 3)
	for i, share := range shares {
		signers[i] = NewSigner(share)
	}

	// Signing parameters
	sessionID := 1
	prfKey := []byte("test-prf-key-32-bytes-long!!!!!!")
	signerIDs := []int{0, 1, 2}
	message := "test block hash for consensus"

	// Round 1: All parties compute D + MACs
	round1Data := make(map[int]*Round1Data)
	for _, signer := range signers {
		data := signer.Round1(sessionID, prfKey, signerIDs)
		round1Data[data.PartyID] = data
		t.Logf("Party %d: Round1 complete, D size: %d x %d", data.PartyID, len(data.D), len(data.D[0]))
	}

	// Round 2: All parties compute z shares
	round2Data := make(map[int]*Round2Data)
	for _, signer := range signers {
		data, err := signer.Round2(sessionID, message, prfKey, signerIDs, round1Data)
		if err != nil {
			t.Fatalf("Party %d Round2 failed: %v", signer.share.Index, err)
		}
		round2Data[data.PartyID] = data
		t.Logf("Party %d: Round2 complete, z size: %d", data.PartyID, len(data.Z))
	}

	// Finalize: Any party can aggregate
	sig, err := signers[0].Finalize(round2Data)
	if err != nil {
		t.Fatalf("Finalize failed: %v", err)
	}
	t.Logf("Signature: C degree=%d, Z size=%d, Delta size=%d", sig.C.N(), len(sig.Z), len(sig.Delta))

	// Verify
	valid := Verify(groupKey, message, sig)
	if !valid {
		t.Error("signature verification failed")
	}
	t.Log("✓ Signature verified successfully")
}

func TestThresholdWrongMessage(t *testing.T) {
	shares, groupKey, err := GenerateKeys(2, 3, nil)
	if err != nil {
		t.Fatalf("GenerateKeys failed: %v", err)
	}

	signers := make([]*Signer, 3)
	for i, share := range shares {
		signers[i] = NewSigner(share)
	}

	sessionID := 1
	prfKey := []byte("test-prf-key-32-bytes-long!!!!!!")
	signerIDs := []int{0, 1, 2}
	message := "original message"

	// Round 1
	round1Data := make(map[int]*Round1Data)
	for _, signer := range signers {
		data := signer.Round1(sessionID, prfKey, signerIDs)
		round1Data[data.PartyID] = data
	}

	// Round 2
	round2Data := make(map[int]*Round2Data)
	for _, signer := range signers {
		data, _ := signer.Round2(sessionID, message, prfKey, signerIDs, round1Data)
		round2Data[data.PartyID] = data
	}

	// Finalize
	sig, _ := signers[0].Finalize(round2Data)

	// Verify with wrong message should fail
	valid := Verify(groupKey, "wrong message", sig)
	if valid {
		t.Error("verification should fail for wrong message")
	}
}

func TestInvalidThreshold(t *testing.T) {
	// Threshold >= total
	_, _, err := GenerateKeys(3, 3, nil)
	if err != ErrInvalidThreshold {
		t.Errorf("expected ErrInvalidThreshold, got %v", err)
	}

	// Threshold = 0
	_, _, err = GenerateKeys(0, 3, nil)
	if err != ErrInvalidThreshold {
		t.Errorf("expected ErrInvalidThreshold, got %v", err)
	}

	// Too few parties
	_, _, err = GenerateKeys(1, 1, nil)
	if err != ErrInvalidPartyCount {
		t.Errorf("expected ErrInvalidPartyCount, got %v", err)
	}
}
