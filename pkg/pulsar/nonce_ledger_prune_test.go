// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

// nonce_ledger_prune_test.go — post-merge nit #2 (LOW): epoch-prune the in-memory
// single-use nonce ledger so it cannot grow unbounded over a validator's
// lifetime, WITHOUT reintroducing reuse inside the live (retained) window.

import (
	"encoding/binary"
	"testing"
)

// compile-time: the in-memory ledger is a NoncePruner (the optional capability).
var _ NoncePruner = (*InMemoryNonceLedger)(nil)

func pruneKey(epoch uint64) [32]byte {
	var k [32]byte
	binary.BigEndian.PutUint64(k[:8], epoch)
	k[31] = 0xAA
	return k
}

// PruneBefore frees old entries; reuse inside the retained window is still
// refused (ErrNonceReused); pruned slots are reclaimed.
func TestNonceLedger_EpochPruneFreesOldRetainsWindow(t *testing.T) {
	l := NewInMemoryNonceLedger()

	// Reserve one nonce per epoch 1..10.
	for e := uint64(1); e <= 10; e++ {
		if err := l.Reserve(pruneKey(e), NonceBinding{Epoch: e}); err != nil {
			t.Fatalf("reserve epoch %d: %v", e, err)
		}
	}
	// Single-use holds for ALL of them before pruning.
	for e := uint64(1); e <= 10; e++ {
		if err := l.Reserve(pruneKey(e), NonceBinding{Epoch: e}); err != ErrNonceReused {
			t.Fatalf("pre-prune re-reserve epoch %d: got %v want ErrNonceReused", e, err)
		}
	}

	// Prune everything strictly older than epoch 8 → drops epochs 1..7 (7 entries).
	if dropped := l.PruneBefore(8); dropped != 7 {
		t.Fatalf("PruneBefore(8) dropped %d, want 7", dropped)
	}

	// RETAINED window [8,10]: reuse is STILL refused — pruning must NOT reopen the
	// live window (the nonce-reuse key-recovery vector stays closed).
	for e := uint64(8); e <= 10; e++ {
		if err := l.Reserve(pruneKey(e), NonceBinding{Epoch: e}); err != ErrNonceReused {
			t.Fatalf("retained epoch %d reuse: got %v want ErrNonceReused — pruning REOPENED the live window!", e, err)
		}
	}

	// PRUNED entries (1..7): the slots are freed, so they reserve fresh (memory was
	// genuinely reclaimed). Acceptable: an ancient epoch's nonce is past finality
	// and can no longer be usefully replayed on-chain.
	for e := uint64(1); e <= 7; e++ {
		if err := l.Reserve(pruneKey(e), NonceBinding{Epoch: e}); err != nil {
			t.Fatalf("pruned epoch %d should reserve fresh after prune (slot not freed): %v", e, err)
		}
	}

	// Idempotence / no-op: pruning below the floor drops nothing.
	if dropped := l.PruneBefore(1); dropped != 0 {
		t.Fatalf("PruneBefore(1) dropped %d, want 0 (epoch-0 entries only would qualify; none here)", dropped)
	}
	t.Logf("PASS: PruneBefore(8) freed 7 old entries; reuse within retained window [8,10] still refused (ErrNonceReused); pruned slots reclaimed")
}

// The registry sweep prunes EVERY per-share ledger; retained-window reuse stays
// refused on each. Asserted on this test's own share identities (the registry is
// process-global, so the global dropped count is only sanity-checked >=).
func TestNonceLedger_PruneShareLedgers_SweepsRegistry(t *testing.T) {
	var idA, idB [32]byte
	idA[0], idB[0] = 0x11, 0x22
	la := shareLedgerFor(idA)
	lb := shareLedgerFor(idB)

	mk := func(seed byte, epoch uint64) ([32]byte, NonceBinding) {
		var k [32]byte
		k[0] = seed
		binary.BigEndian.PutUint64(k[8:16], epoch)
		return k, NonceBinding{Epoch: epoch}
	}

	// la: epochs 1, 2 (old) + 9 (retained); lb: epoch 3 (old).
	for _, e := range []uint64{1, 2, 9} {
		k, b := mk(0xA0, e)
		if err := la.Reserve(k, b); err != nil {
			t.Fatalf("la reserve epoch %d: %v", e, err)
		}
	}
	if k, b := mk(0xB0, 3); lb.Reserve(k, b) != nil {
		t.Fatalf("lb reserve epoch 3 failed")
	}

	// Sweep: prune < epoch 8 across the whole registry. At least MY 3 old entries
	// (la{1,2} + lb{3}) drop; other tests' entries may add to the count.
	if dropped := PruneShareLedgers(8); dropped < 3 {
		t.Fatalf("PruneShareLedgers(8) dropped %d, want >= 3 (la{1,2}+lb{3})", dropped)
	}

	// la's retained epoch 9 is STILL refused after the sweep.
	if k9, b9 := mk(0xA0, 9); la.Reserve(k9, b9) != ErrNonceReused {
		t.Fatalf("retained epoch 9 reuse after sweep: want ErrNonceReused")
	}
	// la's pruned epoch 1 reserves fresh (freed by the sweep).
	if k1, b1 := mk(0xA0, 1); la.Reserve(k1, b1) != nil {
		t.Fatalf("pruned epoch 1 should reserve fresh after sweep")
	}
	// lb's pruned epoch 3 reserves fresh too.
	if k3, b3 := mk(0xB0, 3); lb.Reserve(k3, b3) != nil {
		t.Fatalf("lb pruned epoch 3 should reserve fresh after sweep")
	}
	t.Logf("PASS: PruneShareLedgers(8) swept the registry — old entries freed across per-share ledgers, retained-window reuse still refused (ErrNonceReused)")
}
