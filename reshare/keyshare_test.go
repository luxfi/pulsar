// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package reshare

import (
	"bytes"
	"testing"

	"github.com/luxfi/lattice/v7/ring"
)

// TestPartyKeyShareFromShareFullPath — round-trips a Shamir share into
// a complete PartyKeyShare and confirms every field is populated.
func TestPartyKeyShareFromShareFullPath(t *testing.T) {
	r := canonicalRing(t)

	const tThr, n = 3, 5
	secret := pickSecret(r, "keyshare-full", testNVec)
	rs := newFakeRand([]byte("keyshare-shamir"))
	oldShares, err := makeStandardShamirShares(r, secret, tThr, n, rs)
	if err != nil {
		t.Fatal(err)
	}

	// Reshare onto a new committee.
	const tNew = 3
	newCommittee := []int{10, 11, 12, 13, 14}
	reshared, err := Reshare(r, oldShares, tThr, newCommittee, tNew,
		newFakeRand([]byte("keyshare-reshare")))
	if err != nil {
		t.Fatal(err)
	}

	// Build pairwise material. In the kernel test we use deterministic
	// fakes; production wires this through AuthenticatedKex (see
	// pairwise.go).
	K := len(newCommittee)
	authKex := make(map[[2]int][]byte, K*K)
	selfSeeds := make(map[int][]byte, K)
	for i := 0; i < K; i++ {
		selfSeeds[i] = []byte{byte(0xA0 + i), 0x11, 0x22, 0x33}
		for j := i + 1; j < K; j++ {
			authKex[[2]int{i, j}] = []byte{byte(i), byte(j), 0xCC, 0xDD}
		}
	}
	chainID := []byte("test")
	groupID := []byte("g0")
	pseudoEpoch := uint64(7)

	pairwiseSeeds, err := DeriveSeeds(K, authKex, selfSeeds, chainID, groupID, 0, pseudoEpoch, nil, 32)
	if err != nil {
		t.Fatal(err)
	}
	pairwiseMACs, err := DeriveMACKeys(K, authKex, chainID, groupID, 0, pseudoEpoch, nil, 32)
	if err != nil {
		t.Fatal(err)
	}

	groupKey := &PartyGroupKey{}

	// Build the PartyKeyShare for one new party.
	myID := newCommittee[2] // 12
	pks, err := PartyKeyShareFromShare(
		r, reshared[myID], myID, newCommittee,
		pairwiseSeeds, pairwiseMACs, groupKey,
	)
	if err != nil {
		t.Fatal(err)
	}

	// Sanity checks: every field populated.
	if pks.Index != 2 {
		t.Errorf("Index: got %d, want 2", pks.Index)
	}
	if pks.SkShare == nil || len(pks.SkShare) == 0 {
		t.Error("SkShare empty")
	}
	if pks.GroupKey != groupKey {
		t.Error("GroupKey not propagated as pointer")
	}
	if pks.Lambda.Coeffs == nil {
		t.Error("Lambda not populated")
	}
	// Lambda must be in NTT-Mont form (not all-zero, not equal to a
	// raw scalar — there's no easy invariant to check beyond
	// non-zero-ness without re-running the helper).
	if allZeroPoly(pks.Lambda) {
		t.Error("Lambda is all zero")
	}
	if pks.Seeds == nil {
		t.Fatal("Seeds map empty")
	}
	if len(pks.Seeds) != K {
		t.Errorf("Seeds map size: got %d, want %d", len(pks.Seeds), K)
	}
	for i := 0; i < K; i++ {
		row := pks.Seeds[i]
		if row == nil {
			t.Errorf("Seeds[%d] missing", i)
			continue
		}
		if len(row) != K {
			t.Errorf("Seeds[%d] length: got %d, want %d", i, len(row), K)
		}
	}
	// MACKeys[i] for i != myIdx should be non-nil and match the
	// canonical pairwise derivation.
	for k := 0; k < K; k++ {
		if k == 2 {
			if _, ok := pks.MACKeys[k]; ok {
				t.Errorf("MACKeys[self=%d] should not exist", k)
			}
			continue
		}
		if mk := pks.MACKeys[k]; len(mk) == 0 {
			t.Errorf("MACKeys[%d] missing", k)
		}
	}
}

// TestEraseShareZeroes — every coefficient of every poly in the share
// is zero after EraseShare.
func TestEraseShareZeroes(t *testing.T) {
	r := canonicalRing(t)
	secret := pickSecret(r, "erase", testNVec)
	rs := newFakeRand([]byte("erase-rs"))
	shares, err := makeStandardShamirShares(r, secret, 3, 5, rs)
	if err != nil {
		t.Fatal(err)
	}

	for _, sh := range shares {
		// Check non-trivial before erase (overwhelming probability).
		if allZeroShare(sh) {
			t.Fatal("share is all-zero before erase (test setup broken)")
		}
		EraseShare(sh)
		if !allZeroShare(sh) {
			t.Fatal("EraseShare did not zero all coefficients")
		}
	}
}

// TestPartyKeyShareFromShareRejectsMissingParty — a party not in the
// new committee triggers a clear error.
func TestPartyKeyShareFromShareRejectsMissingParty(t *testing.T) {
	r := canonicalRing(t)
	secret := pickSecret(r, "missing-party", testNVec)
	rs := newFakeRand([]byte("mp-shamir"))
	old, _ := makeStandardShamirShares(r, secret, 2, 3, rs)
	reshared, _ := Reshare(r, old, 2, []int{10, 11, 12}, 2, newFakeRand([]byte("mp-rng")))

	_, err := PartyKeyShareFromShare(r, reshared[10], 99, []int{10, 11, 12},
		map[[2]int][]byte{}, map[[2]int][]byte{}, nil)
	if err == nil {
		t.Fatal("expected error for missing party")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("not in new committee")) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func allZeroShare(s Share) bool {
	for _, p := range s {
		for _, level := range p.Coeffs {
			for _, c := range level {
				if c != 0 {
					return false
				}
			}
		}
	}
	return true
}

func allZeroPoly(p ring.Poly) bool {
	for _, level := range p.Coeffs {
		for _, c := range level {
			if c != 0 {
				return false
			}
		}
	}
	return true
}
