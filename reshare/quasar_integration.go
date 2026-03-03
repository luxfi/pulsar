// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package reshare

// Quasar consensus integration for the Reshare / Refresh primitives.
//
// This file is the integration sketch that the consensus engineer wires
// into `~/work/lux/consensus/protocol/quasar/epoch.go`. It does NOT
// import the consensus package (to avoid a circular dependency: the
// consensus layer depends on pulsar, not the other way around). Instead
// it documents the API surface and provides helper types the caller
// can adapt directly.
//
// # Renaming (Correction 1, addressed in this PR)
//
// The current `protocol/quasar/epoch.go` uses a vocabulary that
// pre-dates Reshare and is now misleading:
//
//	OLD NAME                 NEW NAME (this PR)
//	────────                 ──────────────────
//	RotateEpochKeys          ReshareEpoch (or RotateEpochShares)
//	EpochKeys (struct)       EpochShareState
//	RotateEpoch(newVals)     RotateEpoch(newVals) calls Reshare(...)
//	  → calls GenerateKeys      instead of GenerateKeys
//
// Concretely the existing `EpochManager.RotateEpoch` re-runs
// `ringtailThreshold.GenerateKeys(t, n, nil)` which generates a FRESH
// secret and a NEW group public key per epoch. With Reshare, the
// master secret and group public key are PERSISTENT across epochs;
// only the share distribution rotates. So:
//
//   - At genesis: EpochManager.InitializeEpoch creates the persistent
//     GroupKey via DKG (or trusted-dealer Gen for bootstrap).
//   - At each epoch boundary: RotateEpoch calls Reshare under the
//     hood, producing new EpochShareState that signs under the
//     SAME GroupKey.
//   - BetweenEpochs (optional): the same set of validators may run
//     Refresh periodically to defeat mobile adversaries.
//
// # Activation circuit-breaker
//
// Before the chain commits a new EpochShareState, the new committee
// MUST emit a valid ActivationCert (activation.go) over the resharing
// transcript. The chain calls VerifyActivation; if it fails, the chain
// stays at the old epoch. See ActivationMessage for the canonical
// signed bytes.
//
// # Slashing evidence
//
// Each Complaint that disqualifies a sender is admissible as slashing
// evidence at the consensus layer. The Quasar slashing module
// (slasher TBD: ~/work/lux/consensus/protocol/quasar/slashing.go,
// not yet implemented) consumes:
//
//	Evidence_Equivocation = (sender_id, complaint, commits_a, commits_b)
//	Evidence_BadDelivery   = (sender_id, complaint, share, blind, commits)
//
// The slasher re-runs CommitDigest equality (for equivocation) or
// VerifyShareAgainstCommits (for bad delivery) under the recorded
// transcript_hash. Successful re-verification triggers a stake
// slashing transaction signed by the slasher's authority key.

// EpochShareState is the renamed analogue of Quasar's `EpochKeys`
// struct. It carries the per-validator shares for one epoch, the
// (unchanged) group public key, and the metadata the consensus layer
// needs to rotate.
//
// Distinction from `EpochKeys`:
//   - GroupKey is a POINTER, shared across epochs. The pointer is
//     established at genesis and persists for the entire group lineage.
//   - ValidatorSet is the new committee. Old shares from the previous
//     epoch are NOT carried here — they are erased after activation.
//   - Threshold may differ from previous epoch (Reshare allows
//     t_old → t_new transitions). Refresh keeps t unchanged.
type EpochShareState struct {
	Epoch           uint64
	ValidatorSet    []string                 // ordered validator wire-identity strings
	Threshold       int                      // new threshold t_new (= t_old for Refresh)
	Shares          map[string]*PartyKeyShare // validator-ID → share
	GroupKey        *PartyGroupKey           // POINTER to persistent group key
	TranscriptHash  [32]byte                 // bind to TranscriptInputs.Hash()
	ActivationCert  *ActivationCert          // proof the chain accepted this epoch
}

// ReshareEpochInputs is the parameter bundle for one resharing round.
// The Quasar `EpochManager.ReshareEpoch` consumes it to produce the
// next EpochShareState.
//
// OldShares and NewValidators are the substantive inputs. The other
// fields are protocol context: chain ID, group ID, epoch IDs (mainly
// for transcript binding), and the threshold parameters.
//
// The caller is responsible for ensuring NewValidators is correctly
// ordered (the order determines the 0-indexed Index field of each
// PartyKeyShare). Sorted-by-public-key is the canonical choice; see
// ValidatorSetHash in transcript.go.
type ReshareEpochInputs struct {
	ChainID       []byte
	GroupID       []byte
	OldEpochID    uint64
	NewEpochID    uint64
	OldValidators []string
	NewValidators []string
	OldShares     map[int]Share // 1-indexed party ID → share
	OldThreshold  int
	NewThreshold  int
	GroupKeyHash  [32]byte
}

// RefreshEpochInputs is the parameter bundle for one same-committee
// Refresh round. The committee and threshold are unchanged, only the
// share distribution rotates.
type RefreshEpochInputs struct {
	ChainID       []byte
	GroupID       []byte
	OldEpochID    uint64
	NewEpochID    uint64
	Validators    []string      // unchanged committee
	Shares        map[int]Share // 1-indexed party ID → share
	Threshold     int           // unchanged threshold
	GroupKeyHash  [32]byte
}

// BuildTranscript converts ReshareEpochInputs into the
// TranscriptInputs ready for transcript-binding.
func (i *ReshareEpochInputs) BuildTranscript() TranscriptInputs {
	oldKeys := make([][]byte, len(i.OldValidators))
	for k, v := range i.OldValidators {
		oldKeys[k] = []byte(v)
	}
	newKeys := make([][]byte, len(i.NewValidators))
	for k, v := range i.NewValidators {
		newKeys[k] = []byte(v)
	}
	return TranscriptInputs{
		ChainID:            i.ChainID,
		GroupID:            i.GroupID,
		OldEpochID:         i.OldEpochID,
		NewEpochID:         i.NewEpochID,
		OldSetHash:         ValidatorSetHash(oldKeys, nil),
		NewSetHash:         ValidatorSetHash(newKeys, nil),
		ThresholdOld:       uint32(i.OldThreshold),
		ThresholdNew:       uint32(i.NewThreshold),
		GroupPublicKeyHash: i.GroupKeyHash,
		Variant:            "reshare",
	}
}

// BuildTranscript for Refresh. Old/new sets are equal; old/new
// thresholds are equal.
func (i *RefreshEpochInputs) BuildTranscript() TranscriptInputs {
	keys := make([][]byte, len(i.Validators))
	for k, v := range i.Validators {
		keys[k] = []byte(v)
	}
	hash := ValidatorSetHash(keys, nil)
	return TranscriptInputs{
		ChainID:            i.ChainID,
		GroupID:            i.GroupID,
		OldEpochID:         i.OldEpochID,
		NewEpochID:         i.NewEpochID,
		OldSetHash:         hash,
		NewSetHash:         hash,
		ThresholdOld:       uint32(i.Threshold),
		ThresholdNew:       uint32(i.Threshold),
		GroupPublicKeyHash: i.GroupKeyHash,
		Variant:            "refresh",
	}
}

// QuasarIntegrationChecklist is the development punch-list for wiring
// this package into `protocol/quasar/epoch.go`. Each item is
// individually verifiable:
//
//	[1] Rename EpochManager.RotateEpoch → ReshareEpoch (or keep the
//	    name but change the body). Caller code in quasar.go and the
//	    `validator-rotation` consensus path need updates.
//
//	[2] Replace `ringtailThreshold.GenerateKeys` call with a Reshare
//	    invocation: extract OldShares from current EpochShareState,
//	    feed into Reshare(r, oldShares, tOld, newSet, tNew, randSource).
//
//	[3] Wire transport: the resharing exchange happens over the
//	    Quasar p2p mesh. The p2p layer must expose authenticated
//	    point-to-point channels OLD → NEW (an existing facility for
//	    BLS aggregation; reuse it). Do NOT introduce a new transport.
//
//	[4] Add commit broadcast: each old party commits to its g_i
//	    polynomial via CommitToPoly and broadcasts the digest via
//	    CommitDigest.
//
//	[5] Add complaint workflow: each new party verifies received
//	    shares via VerifyShareAgainstCommits; on failure emits a
//	    signed Complaint. Complaints aggregate at the chain layer
//	    until DisqualificationThreshold is met or the round timer
//	    expires.
//
//	[6] Compute disqualified set deterministically via
//	    ComputeDisqualifiedSet, then re-shape the qualified quorum
//	    via FilterQualifiedQuorum.
//
//	[7] If the qualified quorum drops below tOld, the round FAILS;
//	    the chain emits a "reshare-failed" event and stays at the old
//	    epoch.
//
//	[8] On success, every new validator computes its PartyKeyShare
//	    via PartyKeyShareFromShare. The committee then jointly produces
//	    an ActivationCert by signing the activation message under the
//	    UNCHANGED GroupKey.
//
//	[9] The chain runs VerifyActivation on the activation cert;
//	    success commits the new EpochShareState.
//
//	[10] Old shares are erased via EraseShare; the old EpochShareState
//	     is removed from epochHistory after a configurable grace
//	     period (e.g. 6 epochs of cross-epoch verification window).
//
//	[11] Slashing evidence (Complaints + commit pairs for
//	     equivocation) is forwarded to the slashing module. The
//	     slasher reverifies on-chain and emits the slashing tx.
//
//	[12] Backwards compatibility: `EpochManager.GenerateKeys` is
//	     KEPT as the genesis path (one-time bootstrap). Subsequent
//	     epoch rotations go through ReshareEpoch only.
//
// Realistic effort estimate: 2-3 weeks for an engineer familiar with
// Quasar's consensus internals to land items [1]-[10] with integration
// tests. Items [11]-[12] are an additional 1-2 weeks each (slashing
// evidence ingestion is more complex than this checklist suggests
// because the evidence format must round-trip through the chain's
// transaction encoding).
type QuasarIntegrationChecklist struct{}
