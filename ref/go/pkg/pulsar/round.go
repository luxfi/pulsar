// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package pulsar

// round.go -- Wave-driven metastable threshold signing.
//
// For validator pools above the GF(257) Pulsar cap of n=256, the
// canonical Lux deployment does NOT run one large Pulsar ceremony.
// It runs Pulsar (3, 2) at the per-Lux-round committee level. Each
// Lux round (one Wave Tick) samples K validators via prism.Cut, the
// K members emit Pulsar Round-1 commits over the value under vote,
// Wave decides agreement (alpha-of-K), Pulsar Round-2 reveals are
// collected, and after Focus.Tracker reaches the beta-confidence
// threshold the accumulator combines all collected (3, 2) signatures
// into a single FIPS 204 ML-DSA proof via the P3Q STARK rollup at
// the Z-Chain layer.
//
// The result: a 1.1M-validator pool reaches finality with constant
// per-Lux-round cost (K=3 Pulsar ceremonies in flight) and
// constant final-certificate size (one P3Q proof).
//
// This file provides the helper primitives that the
// consensus/protocol/quasar Wave-driver calls during each Lux round.
// The Wave / Focus / Cut wiring itself lives in
// consensus/protocol/quasar/wave_signer.go (out of pulsar's scope).

import (
	"encoding/binary"
	"math"
)

// RoundContext is the per-Lux-round binding context. Each Wave Tick
// produces a fresh context whose bytes are committed into every
// Pulsar transcript-hash so cross-round Round-1 commits cannot be
// replayed against a different Wave round.
type RoundContext struct {
	// Epoch is the validator-set epoch identifier (e.g. block height
	// divided by the epoch length).
	Epoch uint64
	// Round is the within-epoch Lux-round counter, incremented by the
	// Wave protocol at every Tick.
	Round uint64
	// Item is the canonical hash of the value being signed (FIPS 204
	// message-hash binding mu).
	Item [32]byte
	// CommitteeRoot is the canonical 32-byte digest of the Wave-
	// sampled K-committee for this round (sorted ascending NodeID).
	CommitteeRoot [32]byte
}

// Encode returns the canonical wire encoding of a RoundContext. The
// encoding is consumed by transcripts; changing the layout
// invalidates every KAT pinned at this version.
func (c RoundContext) Encode() []byte {
	out := make([]byte, 0, 8+8+32+32)
	var u [8]byte
	binary.BigEndian.PutUint64(u[:], c.Epoch)
	out = append(out, u[:]...)
	binary.BigEndian.PutUint64(u[:], c.Round)
	out = append(out, u[:]...)
	out = append(out, c.Item[:]...)
	out = append(out, c.CommitteeRoot[:]...)
	return out
}

// RoundSessionID derives a deterministic per-Lux-round Pulsar
// SessionID from a RoundContext. The session-id binds the Pulsar
// per-round PRNG (PULSAR-SIGN-PRNG-V1 customisation tag in
// transcript.go) to the unique (epoch, round, item, committee) tuple,
// closing the CRIT-1 replay vector that del Pino-Niot's PRNGKeyForRound
// addresses in the small-committee path.
func RoundSessionID(ctx RoundContext) [16]byte {
	digest := cshake256(ctx.Encode(), 16, tagSignPRNG)
	var out [16]byte
	copy(out[:], digest)
	return out
}

// RoundCommitteeRoot returns the canonical 32-byte digest of a
// Wave-sampled K-committee (sorted ascending NodeID). Both the
// per-round Pulsar transcript and the Wave protocol's per-round
// commitments bind to this digest.
func RoundCommitteeRoot(committee []NodeID) [32]byte {
	sorted := make([]NodeID, len(committee))
	copy(sorted, committee)
	for i := 1; i < len(sorted); i++ {
		for j := i; j > 0 && nodeIDLess(sorted[j], sorted[j-1]); j-- {
			sorted[j], sorted[j-1] = sorted[j-1], sorted[j]
		}
	}
	parts := make([][]byte, 0, len(sorted)+1)
	parts = append(parts, []byte("PULSAR-ROUND-COMMITTEE-V1"))
	for _, id := range sorted {
		parts = append(parts, id[:])
	}
	return transcriptHash32(tagDKGCommit, parts...)
}

// RoundSigShare is the per-validator Pulsar signature contribution
// emitted in one Lux round. It rides alongside the validator's Wave
// preference vote on the Photon wire. The aggregator at the Quasar
// layer collects β rounds worth of these, passes them to LargeCombine
// (or the small-committee Combine), and emits one FIPS 204 ML-DSA
// signature that the P3Q rollup attests to as part of the final
// block certificate.
type RoundSigShare struct {
	// Context binds the share to its Lux round.
	Context RoundContext
	// Round1 is the per-round Pulsar Round-1 commit message.
	Round1 *Round1Message
	// Round2 is the per-round Pulsar Round-2 reveal message.
	// Filled in after the Wave alpha-of-K agreement check passes.
	Round2 *Round2Message
}

// RoundQuorumPolicy bundles the (alpha, beta) parameters Wave uses to
// drive Lux-round agreement. These are exposed here so the
// consensus-layer Wave-driver can synchronise them with the Pulsar
// combiner's expectations.
//
// alpha is the within-Lux-round agreement threshold (yes-votes among
// K samples that count this round as "successful"). beta is the
// number of consecutive successful Lux rounds before the Focus
// tracker fires "decided" -- at which point the aggregator combines
// β·alpha Pulsar shares into one FIPS 204 signature.
type RoundQuorumPolicy struct {
	K     int
	Alpha int
	Beta  int
}

// DefaultRoundQuorumPolicy matches consensus/protocol/quasar's
// grouped-threshold defaults (DefaultGroupSize=3, DefaultGroupThreshold=2)
// extended to a metastable K-sample of 21 (Wave's typical K) with a
// 15-of-21 alpha and 12-round beta. These are starting points; the
// Quasar config layer (config/pq_mode.go) is the source of truth.
var DefaultRoundQuorumPolicy = RoundQuorumPolicy{
	K:     21,
	Alpha: 15,
	Beta:  12,
}

// ApproxRoundSecurity returns an approximation of the per-round
// adversary advantage given a corruption ratio rho and policy
// (K, alpha). Used by the Quasar config layer to pin alpha and beta
// per security target; see proofs/pulsar-m/lux-round-metastable.tex
// for the formal statement.
//
// The formula computes 2^(-bits-of-security) where bits is the
// binomial tail bound for {alpha-of-K} from a rho-fraction-corrupted
// pool: Pr[X >= alpha when X ~ Bin(K, rho)]. We return the natural
// logarithm to avoid floating-point precision loss; callers convert
// to log2 as needed.
func ApproxRoundSecurity(rho float64, policy RoundQuorumPolicy) float64 {
	// Cumulative binomial Pr[X >= alpha; K, rho] via direct sum.
	logFactorial := func(n int) float64 {
		acc := 0.0
		for i := 2; i <= n; i++ {
			acc += logf(float64(i))
		}
		return acc
	}
	logChoose := func(n, k int) float64 {
		if k < 0 || k > n {
			return -1e308
		}
		return logFactorial(n) - logFactorial(k) - logFactorial(n-k)
	}

	sum := 0.0
	for x := policy.Alpha; x <= policy.K; x++ {
		// Pr[X=x] = C(K, x) * rho^x * (1-rho)^(K-x)
		logp := logChoose(policy.K, x) +
			float64(x)*logf(rho) +
			float64(policy.K-x)*logf(1.0-rho)
		sum += expf(logp)
	}
	return sum
}

// logf / expf are stdlib wrappers; pulled behind named indirection so
// unit tests can stub them if needed.
var (
	logf = func(x float64) float64 { return math.Log(x) }
	expf = func(x float64) float64 { return math.Exp(x) }
)
