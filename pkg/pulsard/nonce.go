// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// nonce.go — session/nonce plumbing: deterministic session identifiers and a
// public (secret-free) nonce pool with non-grindable canonical selection. The
// pool holds only nonce IDENTIFIERS and their consumed flags — never nonce
// shares, commitments, or w. Its job is to make nonce selection reproducible
// across all signers and non-grindable by a coordinator, so the challenge
// c = H(μ‖w1) cannot be biased by choosing among prepared nonces after seeing
// the message. This is control-plane state; the actual nonce material lives with
// the signers (engine), keyed by NonceID.

package pulsard

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"

	"github.com/luxfi/warp"
)

// ErrNoncePoolEmpty is returned by SelectCanonical when no unconsumed nonce
// remains: a refill is required before another signature can be produced.
var ErrNoncePoolEmpty = errors.New("pulsard: nonce pool exhausted — refill required before signing")

// DeriveSessionID is the deterministic identifier for a signing session over
// subject under era. It binds the era's identity (signerSet, keyEra, generation)
// and the subject with fixed-width, domain-separated encoding, so every signer
// derives the same session id and a session over one (subject, era) can never
// collide with another. All inputs are fixed width (32+32+8+8 bytes), so the
// preimage is unambiguous.
func DeriveSessionID(subject []byte, era warp.PulsarKeyEra) [32]byte {
	h := sha256.New()
	h.Write([]byte("pulsard/session-id/v1"))
	h.Write(era.SignerSetID[:])
	var u [8]byte
	binary.BigEndian.PutUint64(u[:], era.KeyEraID)
	h.Write(u[:])
	binary.BigEndian.PutUint64(u[:], era.Generation)
	h.Write(u[:])
	// subject is validated to SubjectLen by the caller (NewSession); fixed width.
	h.Write(subject)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// NoncePool is a refillable pool of prepared nonce identifiers feeding the
// one-round online path. It holds no secret.
type NoncePool struct {
	ids      [][32]byte
	consumed map[[32]byte]bool
}

// NewNoncePool returns an empty pool.
func NewNoncePool() *NoncePool {
	return &NoncePool{consumed: make(map[[32]byte]bool)}
}

// Add admits a prepared nonce id (idempotent on duplicates).
func (p *NoncePool) Add(id [32]byte) {
	for _, e := range p.ids {
		if e == id {
			return
		}
	}
	p.ids = append(p.ids, id)
}

// Available reports the number of unconsumed nonce ids.
func (p *NoncePool) Available() int {
	n := 0
	for _, id := range p.ids {
		if !p.consumed[id] {
			n++
		}
	}
	return n
}

// Root commits to the unconsumed nonce ids, in order. It is the second input to
// canonical selection, binding the selectable set so the choice is reproducible
// and a coordinator cannot grind it.
func (p *NoncePool) Root() [32]byte {
	h := sha256.New()
	h.Write([]byte("pulsard/nonce-pool-root/v1"))
	for _, id := range p.ids {
		if !p.consumed[id] {
			h.Write(id[:])
		}
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// SelectCanonical deterministically picks an unconsumed nonce for a session via
// canonicalIndex(sessionID, poolRoot, live). Every signer running this over the
// same pool and session selects the SAME nonce; a non-canonical choice is
// rejected by peers in the consensus layer.
func (p *NoncePool) SelectCanonical(sessionID [32]byte) ([32]byte, error) {
	live := make([][32]byte, 0, len(p.ids))
	for _, id := range p.ids {
		if !p.consumed[id] {
			live = append(live, id)
		}
	}
	if len(live) == 0 {
		return [32]byte{}, ErrNoncePoolEmpty
	}
	idx := canonicalIndex(sessionID, p.Root(), uint64(len(live)))
	return live[idx], nil
}

// Consume marks a nonce one-time-used; SelectCanonical never returns it again.
func (p *NoncePool) Consume(id [32]byte) { p.consumed[id] = true }

// canonicalIndex maps (sessionID, poolRoot) to an index in [0, n) by hashing
// them with a domain tag and reducing the first 8 bytes mod n. It is a fixed
// function of public inputs, so it is reproducible and non-grindable.
func canonicalIndex(sessionID, poolRoot [32]byte, n uint64) uint64 {
	h := sha256.New()
	h.Write([]byte("pulsard/canonical-nonce/v1"))
	h.Write(sessionID[:])
	h.Write(poolRoot[:])
	sum := h.Sum(nil)
	return binary.BigEndian.Uint64(sum[:8]) % n
}
