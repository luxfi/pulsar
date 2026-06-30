// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// protocol.go — the TALUS control plane: the phase enumeration, the legal
// phase transitions, and the typed round messages. This is the protocol's
// STRUCTURE, not its cryptography: every message here carries only the public
// transcript of a round (commitment roots, opaque per-engine payloads, blame
// accusations). The secret-bearing math (nonce shares, w0, Beaver triples) is
// the [ThresholdEngine]'s concern and never appears in these types.
//
// Separating the control plane (real, deterministic, unit-tested here) from the
// crypto plane (the engine SPI, fail-closed by default) is the whole point:
// the state machine can be reviewed and tested for soundness — legal
// transitions, quorum counting, identifiable-abort routing — independently of
// whether a real dealerless TALUS engine exists yet.

package pulsard

import "fmt"

// NodeID indexes a member of the signing committee. Production maps validator
// identities (ids.NodeID) to a stable committee index per key era; the offline
// protocol only needs the index to attribute round messages and route blame.
type NodeID uint32

// Phase is a stage of the TALUS offline-then-online protocol. The happy path is
//
//	Init → NonceDKG → BCC → CEF → CSCP → Aggregate → Done
//
// with Blame reachable from any active phase (identifiable abort) and Aborted
// terminal. The four preprocessing phases are OFFLINE (multi-round); Aggregate
// is the single ONLINE broadcast round that produces the signature.
type Phase uint8

const (
	// PhaseInit is the initial state (committee fixed, no round started).
	PhaseInit Phase = iota
	// PhaseNonceDKG is the dealerless one-time joint-nonce DKG (Shamir nonce
	// sharing; no node forms the joint nonce ȳ).
	PhaseNonceDKG
	// PhaseBCC is the Boundary-Clearance-Condition commitment carry: accept only
	// nonces whose commitment keeps ‖r0‖∞ < γ2−β so the hint is public-computable.
	PhaseBCC
	// PhaseCEF is the Carry-Elimination Framework: compute w1 = HighBits(A·ȳ)
	// over the secret-shared nonce without reconstructing ȳ or revealing w0.
	PhaseCEF
	// PhaseCSCP is the secure-comparison sub-protocol realizing the HighBits
	// boundary count without any node forming w0/w (closes the W-LEAK residual).
	PhaseCSCP
	// PhaseAggregate is the one online round: derive c = H(μ‖w1), each signer
	// broadcasts its z-partial, the coordinator sums z, recovers the hint from
	// public data, and assembles a stock FIPS-204 signature.
	PhaseAggregate
	// PhaseBlame is identifiable abort: a detected fault is attributed to a
	// specific node before the session aborts.
	PhaseBlame
	// PhaseDone is terminal success (a verified signature was produced).
	PhaseDone
	// PhaseAborted is terminal failure (timeout or identified fault).
	PhaseAborted
)

// String renders the phase name.
func (p Phase) String() string {
	switch p {
	case PhaseInit:
		return "init"
	case PhaseNonceDKG:
		return "nonce-dkg"
	case PhaseBCC:
		return "bcc"
	case PhaseCEF:
		return "cef"
	case PhaseCSCP:
		return "cscp"
	case PhaseAggregate:
		return "aggregate"
	case PhaseBlame:
		return "blame"
	case PhaseDone:
		return "done"
	case PhaseAborted:
		return "aborted"
	default:
		return fmt.Sprintf("phase(%d)", uint8(p))
	}
}

// phaseTransitions is the legal-transition table. A transition not listed here
// is rejected by [Session.Advance] — the state machine cannot skip a
// preprocessing phase or resurrect a terminal session.
var phaseTransitions = map[Phase]map[Phase]struct{}{
	PhaseInit:      {PhaseNonceDKG: {}, PhaseAborted: {}},
	PhaseNonceDKG:  {PhaseBCC: {}, PhaseBlame: {}, PhaseAborted: {}},
	PhaseBCC:       {PhaseCEF: {}, PhaseBlame: {}, PhaseAborted: {}},
	PhaseCEF:       {PhaseCSCP: {}, PhaseBlame: {}, PhaseAborted: {}},
	PhaseCSCP:      {PhaseAggregate: {}, PhaseBlame: {}, PhaseAborted: {}},
	PhaseAggregate: {PhaseDone: {}, PhaseBlame: {}, PhaseAborted: {}},
	PhaseBlame:     {PhaseAborted: {}},
	PhaseDone:      {},
	PhaseAborted:   {},
}

// CanTransition reports whether from→to is a legal phase transition.
func CanTransition(from, to Phase) bool {
	nexts, ok := phaseTransitions[from]
	if !ok {
		return false
	}
	_, ok = nexts[to]
	return ok
}

// NonceDKGDeal is one node's contribution to the dealerless joint-nonce DKG. It
// carries the public commitment root binding the contribution; Deal is the
// opaque per-engine share payload (engine-defined encoding).
type NonceDKGDeal struct {
	NonceID    [32]byte
	From       NodeID
	CommitRoot [32]byte
	Deal       []byte
}

// BCCShare is one node's Boundary-Clearance commitment carry for a nonce. Only
// the public commitment leaves the node; the nonce share does not.
type BCCShare struct {
	NonceID    [32]byte
	From       NodeID
	Commitment []byte
}

// CEFCarryShare is one node's carry-elimination share of w1 = HighBits(A·ȳ).
// W1Share is the engine-encoded contribution to the public challenge input;
// w0/w are never carried.
type CEFCarryShare struct {
	NonceID [32]byte
	From    NodeID
	W1Share []byte
}

// CSCPShare is one node's secure-comparison share realizing the HighBits
// boundary count without forming w. Share is the engine-encoded masked carry.
type CSCPShare struct {
	NonceID [32]byte
	From    NodeID
	Share   []byte
}

// PartialZ is one node's single online broadcast: the proof-carrying z-partial
// z_i = λ_i·y_i + c·λ_i·s1_i. The coordinator sums these into the final z.
type PartialZ struct {
	NonceID [32]byte
	From    NodeID
	Z       []byte
}

// BlameAccusation attributes a protocol fault to a specific node in a specific
// round, enabling identifiable abort. Evidence is the engine-encoded proof of
// misbehavior (e.g. an inconsistent share opening).
type BlameAccusation struct {
	Round    Phase
	Accuser  NodeID
	Accused  NodeID
	Evidence []byte
}
