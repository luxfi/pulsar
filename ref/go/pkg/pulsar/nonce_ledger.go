// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

// nonce_ledger.go — the nonce single-use / anti-replay guard.
//
// THE ATTACK THIS CLOSES (RED finding, HIGH — nonce reuse ⇒ full key recovery).
//
//	The committee response is z = ȳ + c·s1 where c = SampleInBall(H(μ, w1))
//	depends on the message μ but ȳ (hence w1) is the joint nonce. If the SAME
//	joint nonce is consumed for TWO messages A, B, the two public aggregates
//
//	    z_A = ȳ + c_A·s1 ,   z_B = ȳ + c_B·s1
//
//	subtract to the PUBLIC linear relation
//
//	    z_A − z_B = (c_A − c_B)·s1                       (over R_q^L)
//
//	in which EVERYTHING but s1 is public. (c_A − c_B) is invertible in R_q with
//	overwhelming probability, so any observer solves for the WHOLE expanded key
//	s1 and forges at will. This is the textbook Schnorr/FROST nonce-reuse
//	catastrophe carried to the lattice setting — it is intrinsic to the LINEAR
//	response and cannot be patched in the algebra. The defence is the same as
//	FROST's: an HONEST signer MUST consume each nonce AT MOST ONCE.
//
// THE GUARD (this file + Round2 wiring).
//
//	A NonceLedger records, per signer/validator, the nonce material that has
//	already been consumed. Before a signer emits its secret z-partial it
//	RESERVES the nonce; a second reservation of the same material is rejected
//	FAIL-CLOSED (ErrNonceReused) and NO partial is produced. The dedup key is
//	derived from the nonce COMMITMENT w1 (not the nonceID label), so relabeling
//	the same joint nonce under a fresh nonceID does not bypass the guard:
//
//	    key = SHAKE256("PULSAR/nonce-single-use/v1" ‖ committeeID ‖ w1)
//
//	One nonce ⇒ one signature, ever. Even ONE honest member refusing the
//	second use starves the attacker of that member's z_B partial, so the
//	(c_A − c_B)·s1 system can never be assembled. The guard is per-VALIDATOR
//	(per-share), shared across every signer instance that uses the same share —
//	see SetNonceLedger.
//
// FAIL-CLOSED LIFECYCLE. Reservation happens BEFORE the secret is touched and
// is NEVER rolled back: if proof generation later fails, the nonce stays
// burned. An aborted attempt therefore cannot leave a reusable nonce behind
// (the "abort doesn't leak reusable nonce state" property). Re-transmitting a
// dropped partial is the CALLER's job (cache the Round2 output and re-send it);
// re-INVOKING Round2 for the same nonce is correctly refused.

import (
	"errors"
	"sync"

	"golang.org/x/crypto/sha3"
)

var (
	// ErrNonceReused is returned when a signer is asked to consume a nonce
	// whose commitment material has already produced a partial. This is the
	// load-bearing anti-replay refusal (RED nonce-reuse finding).
	ErrNonceReused = errors.New("pulsar: nonce already consumed — single-use guard refuses reuse (key-recovery vector)")

	// ErrNonceBindingMismatch is returned by CheckBinding when a reserved
	// nonce is re-presented under a DIFFERENT domain binding than it was
	// minted for (epoch / committee / policy / message-kind / digest). It is a
	// domain-separation tripwire; the single-use guard itself fires first on
	// any second use.
	ErrNonceBindingMismatch = errors.New("pulsar: nonce binding mismatch — reserved for a different (epoch,committee,policy,kind,digest)")

	// ErrNonceLedgerNil guards a signer constructed without a ledger.
	ErrNonceLedgerNil = errors.New("pulsar: nonce ledger is nil")
)

// NonceBinding is the domain context a nonce is reserved for. It is recorded
// with the reservation for audit and domain-separation. The single-use guard
// keys on the nonce COMMITMENT (committeeID‖w1), not on this binding; the
// binding is the auditable "what was this nonce spent on" record and the
// tripwire CheckBinding uses.
type NonceBinding struct {
	Epoch       uint64
	CommitteeID [32]byte
	Policy      [32]byte // policy / domain tag (e.g. block-cert vs warp-msg domain)
	MessageKind uint32   // caller-defined message-kind discriminator
	Digest      [32]byte // digest of the (ctx,msg) this nonce is reserved for
}

func (a NonceBinding) equal(b NonceBinding) bool {
	return a.Epoch == b.Epoch &&
		a.CommitteeID == b.CommitteeID &&
		a.Policy == b.Policy &&
		a.MessageKind == b.MessageKind &&
		a.Digest == b.Digest
}

// NonceLedger is the single-use store. Implementations MUST be safe for
// concurrent use and MUST be FAIL-CLOSED: Reserve returns ErrNonceReused for
// any key it has already seen, and never forgets a key for the lifetime of the
// share it protects. A production deployment backs this with PERSISTENT storage
// so a crash-and-restart cannot reuse a nonce (the in-memory default does not
// survive restart — flagged residual).
type NonceLedger interface {
	// Reserve records the first use of key with its binding and returns nil.
	// A second Reserve of the same key returns ErrNonceReused — no exceptions,
	// regardless of the binding presented.
	Reserve(key [32]byte, binding NonceBinding) error

	// CheckBinding reports whether key is reserved and, if so, whether it was
	// reserved for the given binding. Returns (true, nil) on a binding match,
	// (true, ErrNonceBindingMismatch) on a mismatch, and (false, nil) if the
	// key is unknown. It never mutates the ledger.
	CheckBinding(key [32]byte, binding NonceBinding) (reserved bool, err error)
}

// InMemoryNonceLedger is the default mutex-guarded in-process ledger. It is
// correct for a single long-lived validator process; it does NOT persist
// across restarts (production must inject a persistent ledger — see residuals).
type InMemoryNonceLedger struct {
	mu   sync.Mutex
	seen map[[32]byte]NonceBinding
}

// NewInMemoryNonceLedger returns an empty in-memory single-use ledger.
func NewInMemoryNonceLedger() *InMemoryNonceLedger {
	return &InMemoryNonceLedger{seen: make(map[[32]byte]NonceBinding)}
}

// Reserve implements NonceLedger.
func (l *InMemoryNonceLedger) Reserve(key [32]byte, binding NonceBinding) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.seen[key]; ok {
		return ErrNonceReused
	}
	l.seen[key] = binding
	return nil
}

// CheckBinding implements NonceLedger.
func (l *InMemoryNonceLedger) CheckBinding(key [32]byte, binding NonceBinding) (bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	got, ok := l.seen[key]
	if !ok {
		return false, nil
	}
	if !got.equal(binding) {
		return true, ErrNonceBindingMismatch
	}
	return true, nil
}

// nonceMaterialKey derives the single-use dedup key from the committee identity
// and the nonce commitment w1 (the packed HighBits(w) carried on the public
// NonceCert). Keying on w1 — NOT on the nonceID label — defeats the relabel
// bypass: the same joint nonce ȳ has the same w1 under any nonceID.
func nonceMaterialKey(committeeID [32]byte, w1Packed []byte) [32]byte {
	h := sha3.NewShake256()
	_, _ = h.Write([]byte("PULSAR/nonce-single-use/v1"))
	_, _ = h.Write(committeeID[:])
	_, _ = h.Write(w1Packed)
	var out [32]byte
	_, _ = h.Read(out[:])
	return out
}

// deriveCommitteeID is the canonical 32-byte identity of a (group key, sorted
// quorum) pair. quorum MUST be the sorted, distinct committee (the constructor
// enforces this). It binds a nonce reservation to THIS committee + key.
func deriveCommitteeID(jointPKID [32]byte, quorum []NodeID) [32]byte {
	h := sha3.NewShake256()
	_, _ = h.Write([]byte("PULSAR/committee-id/v1"))
	_, _ = h.Write(jointPKID[:])
	for i := range quorum {
		_, _ = h.Write(quorum[i][:])
	}
	var out [32]byte
	_, _ = h.Read(out[:])
	return out
}

// nonceBindingDigest derives the 32-byte (ctx,msg) digest recorded in a
// nonce reservation. It binds the reservation to exactly what is being signed.
func nonceBindingDigest(mode Mode, tr [64]byte, ctx, msg []byte) [32]byte {
	var mu [64]byte
	deriveMuCtx(tr, ctx, msg, mu[:])
	h := sha3.NewShake256()
	_, _ = h.Write([]byte("PULSAR/nonce-binding-digest/v1"))
	_, _ = h.Write([]byte{byte(mode)})
	_, _ = h.Write(mu[:])
	var out [32]byte
	_, _ = h.Read(out[:])
	return out
}
