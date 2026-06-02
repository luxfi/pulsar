// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

// orchestrate.go — in-process orchestration helper that drives a
// complete v0.3 algebraic-aggregate threshold sign across t parties
// AND runs the FIPS 204 rejection-restart loop. This is the surface
// the luxfi/threshold JSON-RPC dispatcher consumes — it lets the
// dispatcher publish a Signature from a single function call
// without leaking pulsar's package-private polyVec type into the
// dispatcher.
//
// Trust model is the same as the test-side stageAlgebraic helper:
// all t parties' state lives in this process. This is appropriate
// for the JSON-RPC dispatcher (off-chain integration test harness,
// MPC bus dev tooling, SDK fixtures), NOT for chain-genesis
// ceremonies. Chain-genesis runs the no-trusted-dealer DKG via
// pulsar.NewDKGSession across the messaging layer.

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

// OrchestrateV03Sign drives the full Round1 → Round2W → Round2Sign
// → AlgebraicAggregate cycle for the t signers in `quorum`, looping
// over FIPS 204 rejection-restart attempts up to maxAttempts. The
// output Signature verifies under unmodified FIPS 204 ML-DSA
// (Class N1 manifesto).
//
// Arguments:
//
//   - params:       the canonical Pulsar Params for setup.Mode.
//   - setup:        the v0.3 algebraic-aggregate setup produced by
//     DealAlgebraicV03Shares (carries the group public
//     key + ρ + tr + A). No master sk inside.
//   - msg:          the FIPS 204 message bytes.
//   - sessionID:    a fresh per-Sign session identifier.
//   - quorum:       the t-element committee (sorted by NodeID).
//   - quorumShares: each quorum member's AlgebraicKeyShare in the
//     same order as quorum.
//   - evalPoints:   the Shamir x-coordinates for each quorum
//     member; precomputed via V03QuorumEvalPoints.
//   - sessionKeys:  the pairwise ML-KEM-768 session keys (see
//     SymmetricSession) for every pair in the quorum.
//   - maxAttempts:  cap on FIPS 204 rejection-restart attempts. Pass
//     params.MaxRestart for the production default.
//   - rng:          per-party PRNG. nil falls back to crypto/rand.
//
// Returns the aggregated Signature on success, or an error if no
// attempt within maxAttempts produced a signature that passes the
// FIPS 204 norm checks (||w_0 - c·s_2||, ||z||, ||c·t_0||, hint
// population). The probability of needing > k attempts under
// honest sampling is ~exp(-k/5) per FIPS 204; maxAttempts=256
// gives an abort probability < 2^-512.
//
// This helper does NOT compute sessionKeys for the caller — the
// caller owns the identity layer. For a self-contained one-shot
// API, see OrchestrateV03SignWithKeys below.
//
// EMPTY ctx: equivalent to OrchestrateV03SignCtx(..., nil, ...).
// Output bytes are byte-identical to the historical empty-ctx v0.3
// path; existing chain certs / KATs remain valid.
func OrchestrateV03Sign(
	params *Params,
	setup *AlgebraicSetup,
	msg []byte,
	sessionID [16]byte,
	quorum []NodeID,
	quorumShares []*AlgebraicKeyShare,
	evalPoints []uint32,
	sessionKeys map[NodeID]map[NodeID][32]byte,
	maxAttempts uint32,
	rng io.Reader,
) (*Signature, error) {
	return OrchestrateV03SignCtx(params, setup, nil, msg, sessionID,
		quorum, quorumShares, evalPoints, sessionKeys, maxAttempts, rng)
}

// OrchestrateV03SignCtx drives the full Round1 → Round2W → Round2Sign
// → AlgebraicAggregateCtx cycle with an explicit FIPS 204 §5.4 context
// string bound into μ.
//
// Identical in semantics to OrchestrateV03Sign but with a ctx []byte
// parameter. Output signature verifies under FIPS 204 §6.3
// VerifyCtx(pk, msg, ctx, sig) — byte-identical to a single-party
// FIPS 204 deterministic SignCtx on the same (sk, ctx, msg) tuple up
// to the y_total sampling difference inherent to the threshold path
// (see threshold_v03.go's Class N1 byte-equality contract).
//
// ctx is the FIPS 204 octet-string context (0..255 bytes); nil for
// the empty context. Returns ErrCtxTooLarge if len(ctx) > 255.
//
// Class N1 byte-equality: for any (msg, ctx) the resulting wire bytes
// satisfy mldsa.VerifyCtx(pk, msg, ctx, sig) where pk is the group
// public key bound into setup.Pub.
func OrchestrateV03SignCtx(
	params *Params,
	setup *AlgebraicSetup,
	ctx []byte,
	msg []byte,
	sessionID [16]byte,
	quorum []NodeID,
	quorumShares []*AlgebraicKeyShare,
	evalPoints []uint32,
	sessionKeys map[NodeID]map[NodeID][32]byte,
	maxAttempts uint32,
	rng io.Reader,
) (*Signature, error) {
	if err := params.Validate(); err != nil {
		return nil, err
	}
	if setup == nil {
		return nil, ErrAlgebraicNoSetup
	}
	if setup.Mode != params.Mode {
		return nil, ErrModeMismatch
	}
	if len(ctx) > 255 {
		return nil, ErrCtxTooLarge
	}
	threshold := len(quorum)
	if threshold == 0 {
		return nil, ErrEmptyQuorum
	}
	if len(quorumShares) != threshold {
		return nil, fmt.Errorf("pulsar: quorumShares length %d != quorum length %d",
			len(quorumShares), threshold)
	}
	if len(evalPoints) != threshold {
		return nil, fmt.Errorf("pulsar: evalPoints length %d != quorum length %d",
			len(evalPoints), threshold)
	}
	if maxAttempts == 0 {
		maxAttempts = params.MaxRestart
	}
	if rng == nil {
		rng = rand.Reader
	}

	K, _, _ := modeShape(setup.Mode)

	for attempt := uint32(0); attempt < maxAttempts; attempt++ {
		signers := make([]*AlgebraicThresholdSigner, threshold)
		for i := 0; i < threshold; i++ {
			signer, err := NewAlgebraicThresholdSignerCtx(
				params, setup, sessionID, attempt, quorum, quorumShares[i],
				sessionKeys[quorum[i]], ctx, msg, rng)
			if err != nil {
				return nil, fmt.Errorf("pulsar: NewAlgebraicThresholdSignerCtx party %d: %w", i, err)
			}
			if err := signer.SetQuorumEvalPoints(evalPoints); err != nil {
				return nil, fmt.Errorf("pulsar: SetQuorumEvalPoints party %d: %w", i, err)
			}
			signers[i] = signer
		}

		r1 := make([]*AlgebraicRound1Message, threshold)
		for i, signer := range signers {
			m, err := signer.Round1()
			if err != nil {
				return nil, fmt.Errorf("pulsar: Round1 party %d attempt %d: %w", i, attempt, err)
			}
			r1[i] = m
		}

		r2W := make([]*AlgebraicRound2Message, threshold)
		for i, signer := range signers {
			m, _, err := signer.Round2W(r1)
			if err != nil {
				return nil, fmt.Errorf("pulsar: Round2W party %d attempt %d: %w", i, attempt, err)
			}
			r2W[i] = m
		}

		peerWByParty := make([]map[NodeID]polyVec, threshold)
		for i := 0; i < threshold; i++ {
			peerW := make(map[NodeID]polyVec, threshold-1)
			for j := 0; j < threshold; j++ {
				if i == j {
					continue
				}
				peerW[r2W[j].NodeID] = unpackPolyVec(r2W[j].W, K)
			}
			peerWByParty[i] = peerW
		}

		r2 := make([]*AlgebraicRound2Message, threshold)
		for i, signer := range signers {
			m, _, err := signer.Round2Sign(r1, peerWByParty[i])
			if err != nil {
				return nil, fmt.Errorf("pulsar: Round2Sign party %d attempt %d: %w", i, attempt, err)
			}
			r2[i] = m
		}

		sig, err := AlgebraicAggregateCtx(params, setup, ctx, msg, sessionID, attempt,
			quorum, evalPoints, threshold, r1, r2, sessionKeys)
		if err == nil {
			return sig, nil
		}
		if !errors.Is(err, ErrAlgebraicRestart) {
			return nil, fmt.Errorf("pulsar: AlgebraicAggregateCtx attempt %d: %w", attempt, err)
		}
		// Restart with attempt+1.
	}

	return nil, fmt.Errorf("pulsar: no acceptance within %d FIPS 204 rejection-restart attempts", maxAttempts)
}

// QuorumSessionKeys computes every pairwise ML-KEM-768-derived
// session key for the quorum and returns each party's local view
// (peer -> session key). Required by OrchestrateV03Sign so the
// per-pair Round-1 MAC keys are ephemeral and authenticated under
// each party's long-term ML-DSA-65 identity.
//
// For a quorum of t parties this is t*(t-1)/2 SymmetricSession
// calls. Each SymmetricSession is deterministic from (sid,
// transcript) so two parties agreeing on those inputs derive the
// same key independently in production.
//
// identities MUST cover every NodeID in quorum; missing keys
// produce ErrIdentityKeyMissing.
func QuorumSessionKeys(
	quorum []NodeID,
	identities map[NodeID]*IdentityKey,
	sid [16]byte,
	transcript []byte,
) (map[NodeID]map[NodeID][32]byte, error) {
	if len(quorum) == 0 {
		return nil, ErrEmptyQuorum
	}
	out := make(map[NodeID]map[NodeID][32]byte, len(quorum))
	for _, id := range quorum {
		out[id] = make(map[NodeID][32]byte, len(quorum)-1)
	}
	for i := 0; i < len(quorum); i++ {
		aKey, ok := identities[quorum[i]]
		if !ok {
			return nil, fmt.Errorf("%w: party %x", ErrIdentityKeyMissing, quorum[i][:4])
		}
		for j := i + 1; j < len(quorum); j++ {
			bKey, ok := identities[quorum[j]]
			if !ok {
				return nil, fmt.Errorf("%w: party %x", ErrIdentityKeyMissing, quorum[j][:4])
			}
			key, err := SymmetricSession(quorum[i], aKey, quorum[j], bKey, sid, transcript)
			if err != nil {
				return nil, fmt.Errorf("SymmetricSession %x↔%x: %w",
					quorum[i][:4], quorum[j][:4], err)
			}
			out[quorum[i]][quorum[j]] = key
			out[quorum[j]][quorum[i]] = key
		}
	}
	return out, nil
}
