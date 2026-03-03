// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package keyera is the lifecycle wrapper for a Pulsar group lineage.
//
// One KeyEra is opened by Bootstrap (a one-time foundation MPC ceremony
// at chain genesis or governance-gated Reanchor). The trust is confined
// to genesis of that key era. Subsequent validator-set rotations call
// Reshare, which preserves the GroupKey (A, bTilde) and rotates only
// the share distribution; no trusted dealer is needed for resharing.
// Reanchor opens a new era with a fresh GroupKey for security-event
// response (rare, governance-gated).
//
// The single source of truth for the lifecycle is
// `~/work/lux/pulsar/DESIGN.md`.
//
// Invariants (enforced loudly):
//
//	BLS lane:    each validator has its OWN keypair.
//	ML-DSA lane: each validator has its OWN keypair.
//	Pulsar lane:  each validator has a SHARE of one group key.
//
// Within a key era:
//
//   - The same hidden signing secret s is preserved across epochs.
//   - The same public matrix A is preserved.
//   - The same public key bTilde is preserved (the GroupKey is byte-
//     identical across resharing).
//   - The error e is NOT reshared. It was used only at Bootstrap to
//     form the LWE public key; dealer state is erased.
//   - Only the share distribution of s rotates per epoch.
//
// Across key eras (Reanchor): A, s, e, bTilde all change.
package keyera

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/luxfi/pulsar/hash"
	"github.com/luxfi/pulsar/primitives"
	"github.com/luxfi/pulsar/reshare"
	"github.com/luxfi/pulsar/sign"
	"github.com/luxfi/pulsar/threshold"
	"github.com/luxfi/pulsar/utils"

	"github.com/luxfi/lattice/v7/ring"
	"github.com/luxfi/lattice/v7/utils/sampling"
	"github.com/luxfi/lattice/v7/utils/structs"
)

// Errors returned by the package.
var (
	ErrUninitialized    = errors.New("keyera: era is uninitialized")
	ErrInvalidThreshold = errors.New("keyera: threshold must satisfy 1 <= t <= n")
	ErrEmptyValidators  = errors.New("keyera: validator set is empty")
	ErrMissingShare     = errors.New("keyera: share missing for validator")
)

// PulsarKeyEraID is a monotonically increasing identifier for a key era.
// Bumped only on Reanchor (rare governance event). All resharings
// within an era keep the same era ID.
type PulsarKeyEraID uint64

// PulsarGroupID identifies one Pulsar group for grouped Quasar setups
// where validator sets are partitioned into smaller groups, each with
// its own GroupKey lineage. For the single-group case it is zero.
type PulsarGroupID uint64

// KeyEra is one Pulsar group lineage. The GroupKey (A, bTilde) is set at
// Bootstrap and persists across every Reshare within the era. State is
// the current epoch's share distribution; it rotates each Reshare.
//
// HashSuiteID pins the hash profile this era was opened under. It is
// recorded at Bootstrap and remains immutable through every Reshare in
// the era (per pulsar/proofs/hash-suite-separation.tex Remark on
// era-pinning). Reanchor MAY change the suite for the new era. The
// field is read-only after Bootstrap returns; Reshare propagates it
// without parameterisation.
type KeyEra struct {
	EraID        PulsarKeyEraID
	GroupID      PulsarGroupID
	GroupKey     *threshold.GroupKey
	GenesisEpoch uint64
	HashSuiteID  string
	State        *EpochShareState
}

// EpochShareState is the per-epoch share distribution for a key era.
// Replaces the legacy "EpochKeys" naming — distinguishes "share
// rotation" from "key rotation".
//
// Three lineage fields, kept distinct (do not collapse — they mean
// different things):
//
//   - KeyEraID: Pulsar group-key lineage. Bumps only at Reanchor (fresh
//     GroupKey).
//   - Generation: LSS resharing version within this key era. Bumps
//     every Refresh / Reshare under the same GroupKey. Aligns with
//     LSS's Generation field; managed by threshold/protocols/lss when
//     this state is driven through the LSS-Pulsar adapter.
//   - RollbackFrom: nonzero only when this state descends from a
//     Rollback (= the prior Generation that was reverted from). Zero
//     on ordinary forward transitions.
//
// In production, threshold/protocols/lss owns Generation/RollbackFrom
// updates. In the in-process keyera reference path (used for tests +
// KAT replay), keyera updates them itself.
type EpochShareState struct {
	// Lineage (changes only at Reanchor — fresh GroupKey).
	KeyEraID uint64

	// HashSuiteID is the pinned hash profile for this share state.
	// Mirrored from the parent KeyEra at Bootstrap and propagated
	// without modification through every Reshare. NEVER set this
	// field on a state that descends from a Reshare; use the parent
	// era's HashSuiteID. Reanchor opens a NEW era with a fresh value.
	HashSuiteID string

	// LSS lifecycle.
	Generation   uint64
	RollbackFrom uint64

	// Per-epoch state (rotates every Refresh / Reshare).
	Epoch      uint64
	Validators []string
	Threshold  int
	Shares     map[string]*threshold.KeyShare
}

// Bootstrap runs the one-time trusted-dealer ceremony at chain genesis
// or governance-gated Reanchor.
//
// The trust is confined to genesis of the key era: someone (the dealer)
// momentarily knows the master secret s while constructing the shares.
// If s is retained, copied, or exfiltrated, the long-lived Pulsar group
// key is compromised. Foundation MUST coordinate Bootstrap as a
// publicly observable MPC ceremony at chain launch — the entropy MUST
// come from a verifiable commit-and-reveal among the genesis
// validators, and the dealer state MUST be erased before the ceremony
// closes.
//
// After Bootstrap returns, the master secret no longer exists in the
// dealer's memory. The chain only has the public GroupKey and the
// distributed shares. Subsequent Reshare calls preserve s without
// reconstructing it.
//
// Use crypto/rand.Reader for the kernel's randomness when no specific
// ceremony source is provided. Tests pass a deterministic source for
// KAT replay.
//
// Bootstrap pins the production HashSuite (Pulsar-SHA3). Use
// BootstrapWithSuite to open an era under the legacy Pulsar-BLAKE3
// profile (for cross-suite KAT replay only — NOT for production).
func Bootstrap(t int, validators []string, groupID PulsarGroupID, eraID PulsarKeyEraID, entropy io.Reader) (*KeyEra, error) {
	return BootstrapWithSuite(hash.Default(), t, validators, groupID, eraID, entropy)
}

// BootstrapWithSuite is the canonical entrypoint that explicitly pins
// the hash profile this era will run under. The supplied suite is
// recorded on the returned KeyEra and propagates unchanged through
// every Reshare; Reanchor opens a fresh era and MAY pin a different
// suite. Pass nil to use the production default (Pulsar-SHA3).
func BootstrapWithSuite(suite hash.HashSuite, t int, validators []string, groupID PulsarGroupID, eraID PulsarKeyEraID, entropy io.Reader) (*KeyEra, error) {
	if len(validators) == 0 {
		return nil, ErrEmptyValidators
	}
	n := len(validators)
	if t < 1 || t > n {
		return nil, fmt.Errorf("%w: t=%d n=%d", ErrInvalidThreshold, t, n)
	}
	if entropy == nil {
		entropy = rand.Reader
	}
	suite = hash.Resolve(suite)
	suiteID := suite.ID()

	gk, sStd, err := genGroupKey(entropy)
	if err != nil {
		return nil, fmt.Errorf("keyera: bootstrap genGroupKey: %w", err)
	}

	r := gk.Params.R
	skShares := primitives.ShamirSecretSharingGeneral(r, []ring.Poly(sStd), t, n)
	for _, sh := range skShares {
		utils.ConvertVectorToNTT(r, sh)
	}

	seeds, macKeysByParty := derivePairwiseMaterial(n, entropy)
	lagrange := computeFullCommitteeLagrange(r, n)

	state := &EpochShareState{
		KeyEraID:     uint64(eraID),
		HashSuiteID:  suiteID,
		Generation:   0,
		RollbackFrom: 0,
		Epoch:        0,
		Validators:   append([]string(nil), validators...),
		Threshold:    t,
		Shares:       make(map[string]*threshold.KeyShare, n),
	}
	for i, v := range validators {
		lambda := r.NewPoly()
		lambda.Copy(lagrange[i])
		r.NTT(lambda, lambda)
		r.MForm(lambda, lambda)
		state.Shares[v] = &threshold.KeyShare{
			Index:    i,
			SkShare:  skShares[i],
			Seeds:    seeds,
			MACKeys:  macKeysByParty[i],
			Lambda:   lambda,
			GroupKey: gk,
		}
	}

	// The dealer's master secret is no longer needed. Zero the standard-
	// form copy so it is at least overwritten in this stack frame; the
	// NTT-Mont copy was destroyed by ConvertVectorToNTT in place.
	for i := range sStd {
		for k := range sStd[i].Coeffs {
			coeffs := sStd[i].Coeffs[k]
			for j := range coeffs {
				coeffs[j] = 0
			}
		}
	}

	return &KeyEra{
		EraID:        eraID,
		GroupID:      groupID,
		GroupKey:     gk,
		GenesisEpoch: 0,
		HashSuiteID:  suiteID,
		State:        state,
	}, nil
}

// Reshare evolves the era to a new committee while preserving GroupKey.
//
// The bare Shamir kernel runs in-process; for distributed deployments
// the consensus layer wraps this in the full Verifiable Secret Resharing
// (VSR) exchange (commits, complaints, activation cert) defined in
// pulsar/reshare. This kernel exists to (a) drive the cryptographic core,
// (b) be reused as the trusted-collaborator path for single-process
// integration tests, and (c) provide a reference against which the
// distributed protocol can be byte-equality checked.
//
// rand defaults to crypto/rand.Reader. Pass a deterministic source for
// KAT replay.
func (era *KeyEra) Reshare(newValidators []string, newThreshold int, randSource io.Reader) (*EpochShareState, error) {
	if era == nil || era.GroupKey == nil || era.State == nil {
		return nil, ErrUninitialized
	}
	if len(newValidators) == 0 {
		return nil, ErrEmptyValidators
	}
	K := len(newValidators)
	if newThreshold < 1 || newThreshold > K {
		return nil, fmt.Errorf("%w: t=%d n=%d", ErrInvalidThreshold, newThreshold, K)
	}
	if randSource == nil {
		randSource = rand.Reader
	}

	r := era.GroupKey.Params.R

	oldSharesByID := make(map[int]reshare.Share, len(era.State.Shares))
	for i, v := range era.State.Validators {
		ks, ok := era.State.Shares[v]
		if !ok {
			return nil, fmt.Errorf("%w: %s", ErrMissingShare, v)
		}
		stdShare := cloneVectorAsStandard(r, ks.SkShare)
		oldSharesByID[i+1] = reshare.Share(stdShare)
	}

	newCommitteeIDs := make([]int, K)
	for i := range newValidators {
		newCommitteeIDs[i] = i + 1
	}

	newSharesByID, err := reshare.Reshare(
		r,
		oldSharesByID,
		era.State.Threshold,
		newCommitteeIDs,
		newThreshold,
		randSource,
	)
	if err != nil {
		return nil, fmt.Errorf("keyera: reshare kernel: %w", err)
	}

	lagrange := computeFullCommitteeLagrange(r, K)
	seeds, macKeys := derivePairwiseMaterial(K, randSource)

	nextState := &EpochShareState{
		// Lineage preserved across resharing (KeyEraID never changes
		// inside an era).
		KeyEraID: era.State.KeyEraID,
		// HashSuiteID is era-pinned; propagated, NOT a parameter.
		// Reshare cannot change the suite — see hash-suite-separation
		// theorem (proofs/pulsar/hash-suite-separation.tex).
		HashSuiteID: era.HashSuiteID,
		// LSS Generation increments by 1 on every successful Reshare.
		Generation: era.State.Generation + 1,
		// Ordinary forward transition; not a Rollback.
		RollbackFrom: 0,
		Epoch:        era.State.Epoch + 1,
		Validators:   append([]string(nil), newValidators...),
		Threshold:    newThreshold,
		Shares:       make(map[string]*threshold.KeyShare, K),
	}
	for idx, v := range newValidators {
		partyID := idx + 1
		skShareNTT := stdShareToNTT(r, newSharesByID[partyID])
		lambda := r.NewPoly()
		lambda.Copy(lagrange[idx])
		r.NTT(lambda, lambda)
		r.MForm(lambda, lambda)
		nextState.Shares[v] = &threshold.KeyShare{
			Index:    idx,
			SkShare:  skShareNTT,
			Seeds:    seeds,
			MACKeys:  macKeys[idx],
			Lambda:   lambda,
			GroupKey: era.GroupKey,
		}
	}

	era.State = nextState
	return nextState, nil
}

// Reanchor opens a new key era with a fresh GroupKey. Use ONLY for
// security-event response — long-tail share leakage, suspected master-
// secret compromise, etc. The chain governance MUST authorize this; it
// is not a routine operation.
//
// Reanchor inherits the prior era's HashSuiteID. To migrate to a
// different suite (e.g. moving from legacy Pulsar-BLAKE3 to production
// Pulsar-SHA3) call ReanchorWithSuite.
func Reanchor(prev *KeyEra, t int, validators []string, groupID PulsarGroupID, entropy io.Reader) (*KeyEra, error) {
	var suite hash.HashSuite
	if prev != nil && prev.HashSuiteID == hash.LegacyBLAKE3ID {
		suite = hash.NewPulsarBLAKE3()
	} else {
		suite = hash.Default()
	}
	return ReanchorWithSuite(prev, suite, t, validators, groupID, entropy)
}

// ReanchorWithSuite opens a new key era with a fresh GroupKey under
// the supplied HashSuite. Reanchor is the ONLY lifecycle entrypoint
// that may pin a hash profile different from the prior era's
// (Reshare cannot — that is enforced by Reshare not accepting a suite
// parameter). nil suite resolves to the production default.
func ReanchorWithSuite(prev *KeyEra, suite hash.HashSuite, t int, validators []string, groupID PulsarGroupID, entropy io.Reader) (*KeyEra, error) {
	var nextEraID PulsarKeyEraID
	var nextEpoch uint64
	if prev != nil {
		nextEraID = prev.EraID + 1
		if prev.State != nil {
			nextEpoch = prev.State.Epoch + 1
		}
	}
	next, err := BootstrapWithSuite(suite, t, validators, groupID, nextEraID, entropy)
	if err != nil {
		return nil, err
	}
	next.GenesisEpoch = nextEpoch
	next.State.Epoch = nextEpoch
	return next, nil
}

// genGroupKey samples (A, s, e), forms b = A*s + e, rounds to bTilde,
// and returns a populated *threshold.GroupKey along with the master
// secret s in standard (non-NTT) form. The caller is responsible for
// either sharing s and erasing it (Bootstrap) or zeroing it (Reanchor).
func genGroupKey(entropy io.Reader) (*threshold.GroupKey, structs.Vector[ring.Poly], error) {
	params, err := threshold.NewParams()
	if err != nil {
		return nil, nil, err
	}
	r := params.R
	rXi := params.RXi

	seed := make([]byte, sign.KeySize)
	if _, err := io.ReadFull(entropy, seed); err != nil {
		return nil, nil, err
	}
	prng, err := sampling.NewKeyedPRNG(seed)
	if err != nil {
		return nil, nil, err
	}
	uniformSampler := ring.NewUniformSampler(prng, r)
	gaussianParams := ring.DiscreteGaussian{Sigma: sign.SigmaE, Bound: sign.BoundE}
	gaussianSampler := ring.NewGaussianSampler(prng, r, gaussianParams, false)

	A := utils.SamplePolyMatrix(r, sign.M, sign.N, uniformSampler, true, true)
	sStd := utils.SamplePolyVector(r, sign.N, gaussianSampler, false, false)

	// Compute b = A*s + e. We need NTT-Mont s for the matrix multiply,
	// but we want to keep a standard-form copy of s for the Shamir
	// sharing step.
	sNTT := make(structs.Vector[ring.Poly], len(sStd))
	for i := range sStd {
		sNTT[i] = r.NewPoly()
		sNTT[i].Copy(sStd[i])
	}
	utils.ConvertVectorToNTT(r, sNTT)

	e := utils.SamplePolyVector(r, sign.M, gaussianSampler, true, true)
	b := utils.InitializeVector(r, sign.M)
	utils.MatrixVectorMul(r, A, sNTT, b)
	utils.VectorAdd(r, b, e, b)
	utils.ConvertVectorFromNTT(r, b)
	bTilde := utils.RoundVector(r, rXi, b, sign.Xi)

	// Erase the dealer's e from this stack. Quasar never reshares e —
	// it was only needed to form bTilde at genesis.
	for i := range e {
		for k := range e[i].Coeffs {
			coeffs := e[i].Coeffs[k]
			for j := range coeffs {
				coeffs[j] = 0
			}
		}
	}

	return &threshold.GroupKey{
		A:      A,
		BTilde: bTilde,
		Params: params,
	}, sStd, nil
}

// computeFullCommitteeLagrange returns Lagrange coefficients for the
// committee positions [0, 1, ..., n-1] (0-indexed evaluation points;
// primitives.ComputeLagrangeCoefficients adds 1 internally).
func computeFullCommitteeLagrange(r *ring.Ring, n int) []ring.Poly {
	T := make([]int, n)
	for i := range T {
		T[i] = i
	}
	return primitives.ComputeLagrangeCoefficients(r, T, big.NewInt(int64(sign.Q)))
}

// derivePairwiseMaterial generates per-pair PRF seeds and MAC keys for
// a committee of size K.
//
//	seeds[i][j] : sign.KeySize bytes, present for every (i, j).
//	macKeys[i][j] : sign.KeySize bytes, present for i != j; symmetric.
//
// In a single-process simulation the material is freshly drawn from
// randSource. In a distributed deployment the consensus layer overrides
// this with authenticated pairwise KEX from pulsar/reshare/pairwise.go,
// ensuring both endpoints derive the same value without a shared
// trusted dealer.
func derivePairwiseMaterial(K int, randSource io.Reader) (map[int][][]byte, []map[int][]byte) {
	seeds := make(map[int][][]byte, K)
	macKeys := make([]map[int][]byte, K)
	for i := 0; i < K; i++ {
		seeds[i] = make([][]byte, K)
		macKeys[i] = make(map[int][]byte, K-1)
	}
	for i := 0; i < K; i++ {
		for j := 0; j < K; j++ {
			buf := make([]byte, sign.KeySize)
			_, _ = io.ReadFull(randSource, buf)
			seeds[i][j] = buf
		}
	}
	for i := 0; i < K; i++ {
		for j := i + 1; j < K; j++ {
			buf := make([]byte, sign.KeySize)
			_, _ = io.ReadFull(randSource, buf)
			macKeys[i][j] = buf
			macKeys[j][i] = buf
		}
	}
	return seeds, macKeys
}

// cloneVectorAsStandard copies an NTT-Mont vector into a fresh standard-
// form vector, leaving the input untouched. Used by Reshare to feed the
// reshare kernel without mutating the caller's KeyShare.
func cloneVectorAsStandard(r *ring.Ring, in structs.Vector[ring.Poly]) structs.Vector[ring.Poly] {
	out := make(structs.Vector[ring.Poly], len(in))
	for i := range in {
		out[i] = r.NewPoly()
		out[i].Copy(in[i])
		r.IMForm(out[i], out[i])
		r.INTT(out[i], out[i])
	}
	return out
}

// stdShareToNTT converts a standard-form share (Reshare output) into
// the NTT-Mont form required by sign.Party. The input is consumed; the
// caller must not reuse the standard-form vector after this returns.
func stdShareToNTT(r *ring.Ring, in reshare.Share) structs.Vector[ring.Poly] {
	out := structs.Vector[ring.Poly](in)
	utils.ConvertVectorToNTT(r, out)
	return out
}
