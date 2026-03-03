// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package keyera

import (
	"io"
	"testing"

	"github.com/luxfi/pulsar/threshold"

	"github.com/zeebo/blake3"
)

// TestBootstrapBuildsAndSigns confirms that Bootstrap returns a complete
// KeyShare set that can produce a verifying signature under the produced
// GroupKey. We exercise t = n (every validator in the active signing
// set) here; pulsar's signing protocol assumes the full committee
// participates in each Sign invocation.
func TestBootstrapBuildsAndSigns(t *testing.T) {
	const tThr, n = 3, 3
	validators := []string{"validator-A", "validator-B", "validator-C"}

	era, err := Bootstrap(tThr, validators, 0, 0, deterministicRand("bootstrap-genesis"))
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	if era.GroupKey == nil {
		t.Fatal("Bootstrap returned nil GroupKey")
	}
	if got := era.State.Threshold; got != tThr {
		t.Fatalf("threshold: want %d got %d", tThr, got)
	}
	if got := len(era.State.Shares); got != n {
		t.Fatalf("share count: want %d got %d", n, got)
	}

	if !signAndVerify(t, era, validators) {
		t.Fatal("genesis signature failed to verify under GroupKey")
	}
}

// TestReshareSameSetPreservesGroupKey runs Bootstrap then Reshare against
// the same validator set with the same threshold. The GroupKey pointer
// is unchanged after Reshare, and the new shares produce a signature
// that verifies under the unchanged GroupKey.
func TestReshareSameSetPreservesGroupKey(t *testing.T) {
	const tThr = 3
	validators := []string{"v1", "v2", "v3"}

	era, err := Bootstrap(tThr, validators, 0, 0, deterministicRand("genesis-A"))
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	gkBefore := era.GroupKey

	if _, err := era.Reshare(validators, tThr, deterministicRand("reshare-1")); err != nil {
		t.Fatalf("Reshare: %v", err)
	}

	if era.GroupKey != gkBefore {
		t.Fatal("GroupKey pointer changed across Reshare; the era invariant is broken")
	}
	if got := era.State.Epoch; got != 1 {
		t.Fatalf("epoch: want 1 got %d", got)
	}

	if !signAndVerify(t, era, validators) {
		t.Fatal("post-reshare signature failed to verify under unchanged GroupKey")
	}
}

// TestReshareNewCommitteePreservesGroupKey rotates onto a different
// validator set with a different threshold. The new committee's shares
// produce a signature that verifies under the unchanged GroupKey.
func TestReshareNewCommitteePreservesGroupKey(t *testing.T) {
	const tOld = 3
	const tNew = 5
	oldSet := []string{"v1", "v2", "v3"}
	newSet := []string{"v4", "v5", "v6", "v7", "v8"}

	era, err := Bootstrap(tOld, oldSet, 0, 0, deterministicRand("genesis-B"))
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	gkBefore := era.GroupKey

	if _, err := era.Reshare(newSet, tNew, deterministicRand("reshare-set-rotation")); err != nil {
		t.Fatalf("Reshare: %v", err)
	}

	if era.GroupKey != gkBefore {
		t.Fatal("GroupKey pointer changed across Reshare; the era invariant is broken")
	}
	if got := len(era.State.Validators); got != len(newSet) {
		t.Fatalf("validator count after reshare: want %d got %d", len(newSet), got)
	}
	if got := era.State.Threshold; got != tNew {
		t.Fatalf("threshold after reshare: want %d got %d", tNew, got)
	}

	if !signAndVerify(t, era, newSet) {
		t.Fatal("new-committee signature failed to verify under unchanged GroupKey")
	}
}

// TestReanchorOpensNewEra verifies Reanchor produces a fresh GroupKey
// while monotonically advancing the epoch and bumping the EraID.
func TestReanchorOpensNewEra(t *testing.T) {
	era, err := Bootstrap(3, []string{"a", "b", "c"}, 0, 1, deterministicRand("era-1"))
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	if _, err := era.Reshare([]string{"a", "b", "c"}, 3, deterministicRand("reshare-x")); err != nil {
		t.Fatalf("Reshare: %v", err)
	}
	prevEpoch := era.State.Epoch
	prevGK := era.GroupKey
	prevEraID := era.EraID

	era2, err := Reanchor(era, 3, []string{"d", "e", "f"}, 0, deterministicRand("era-2"))
	if err != nil {
		t.Fatalf("Reanchor: %v", err)
	}
	if era2.GroupKey == prevGK {
		t.Fatal("Reanchor returned the same GroupKey pointer; expected fresh key")
	}
	if got := era2.GenesisEpoch; got != prevEpoch+1 {
		t.Fatalf("genesis epoch: want %d got %d", prevEpoch+1, got)
	}
	if got := era2.State.Epoch; got != prevEpoch+1 {
		t.Fatalf("state epoch: want %d got %d", prevEpoch+1, got)
	}
	if got := era2.EraID; got != prevEraID+1 {
		t.Fatalf("era id: want %d got %d", prevEraID+1, got)
	}
}

// TestReshareErrors covers the input-validation surface.
func TestReshareErrors(t *testing.T) {
	era, err := Bootstrap(3, []string{"a", "b", "c"}, 0, 0, deterministicRand("err"))
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}

	if _, err := era.Reshare(nil, 2, nil); err == nil {
		t.Error("expected error for empty validators")
	}
	if _, err := era.Reshare([]string{"x", "y"}, 0, nil); err == nil {
		t.Error("expected error for threshold < 1")
	}
	if _, err := era.Reshare([]string{"x", "y"}, 3, nil); err == nil {
		t.Error("expected error for threshold > n")
	}

	var nilEra *KeyEra
	if _, err := nilEra.Reshare([]string{"a", "b"}, 1, nil); err == nil {
		t.Error("expected error for nil receiver")
	}
}

// signAndVerify drives the threshold-signing protocol on the era's
// current state and returns true iff the resulting signature verifies
// under the era's GroupKey.
func signAndVerify(t *testing.T, era *KeyEra, validators []string) bool {
	t.Helper()
	signersByVal := make(map[string]*threshold.Signer, len(validators))
	for _, v := range validators {
		ks := era.State.Shares[v]
		if ks == nil {
			t.Fatalf("missing share for %s", v)
		}
		signersByVal[v] = threshold.NewSigner(ks)
	}

	signerIndices := make([]int, 0, len(validators))
	for _, v := range validators {
		signerIndices = append(signerIndices, era.State.Shares[v].Index)
	}

	const sessionID = 7
	prfKey := []byte("pulsar-keyera-test-prf-key-32-bytes")[:32]
	const message = "pulsar-keyera-test-message"

	round1Data := make(map[int]*threshold.Round1Data, len(validators))
	for _, v := range validators {
		r1 := signersByVal[v].Round1(sessionID, prfKey, signerIndices)
		round1Data[era.State.Shares[v].Index] = r1
	}

	round2Data := make(map[int]*threshold.Round2Data, len(validators))
	for _, v := range validators {
		r2, err := signersByVal[v].Round2(sessionID, message, prfKey, signerIndices, round1Data)
		if err != nil {
			t.Fatalf("Round2 for %s: %v", v, err)
		}
		round2Data[r2.PartyID] = r2
	}

	finalSig, err := signersByVal[validators[0]].Finalize(round2Data)
	if err != nil {
		t.Fatalf("Finalize: %v", err)
	}
	return threshold.Verify(era.GroupKey, message, finalSig)
}

// deterministicRand returns an unbounded byte stream derived from a
// seed string for KAT-replay tests. Backed by BLAKE3-keyed XOF so the
// reshare kernel can pull as many bytes as it needs.
func deterministicRand(seed string) io.Reader {
	h := blake3.New()
	_, _ = h.Write([]byte("pulsar.keyera.test.rng.v1"))
	_, _ = h.Write([]byte(seed))
	return h.Digest()
}
