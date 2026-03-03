# Quasar Consensus Integration: Resharing Replaces Per-Epoch DKG

This document describes how `~/work/lux/consensus/protocol/quasar/epoch.go`
should be modified to call `pulsar/reshare` at validator-set rotations
instead of running a fresh trusted-dealer `GenerateKeys` every time.

## Status

- Resharing primitive: complete (`pulsar/reshare/reshare.go`)
- Refresh primitive: complete (same-committee proactive update)
- KAT oracle: complete (16 entries, byte-equal Go↔C++)
- C++ port: complete (`luxcpp/crypto/pulsar/cpp/reshare.{hpp,cpp}`)
- Integration test: complete (signature with new committee verifies under
  unchanged public key b̃)
- Wire integration into Quasar consensus: PENDING
- Verifiable Secret Resharing layer (commitments, complaints,
  activation certs): PENDING (depends on `pulsar/dkg2/`, parallel track)

## Current state of `epoch.go`

```go
// EpochManager.generateEpochKeysWithThreshold (line 336)
func (em *EpochManager) generateEpochKeysWithThreshold(
    epoch uint64, validators []string, threshold int,
) (*EpochKeys, error) {
    // ... Generate Ringtail threshold keys ...
    shares, groupKey, err := ringtailThreshold.GenerateKeys(threshold, n, nil)
    // ...
}
```

`GenerateKeys` runs trusted-dealer `Gen` internally. Whoever runs
`generateEpochKeysWithThreshold` learns the master secret `s` and the
new public key `b` is unrelated to the previous epoch's. This is the
defect the resharing primitive fixes.

## Target state

```go
// genesis only — runs once, before any epoch rotation
func (em *EpochManager) InitializeGenesis(validators []string) (*EpochKeys, error) {
    // First time only: run trusted-dealer Gen (or the eventual MPC
    // ceremony in pulsar/dkg2/). Result: shares + groupKey + master
    // public key b̃. Persist b̃ to chain genesis state — it is a
    // permanent, public, never-rotating value.
    shares, groupKey, err := ringtailThreshold.GenerateKeys(
        em.threshold, len(validators), nil)
    // ...
}

// epoch rotation — runs every time the validator set changes
func (em *EpochManager) RotateEpochViaReshare(
    newValidators []string,
) (*EpochKeys, error) {
    // 1. Build the input to pulsar/reshare.Reshare from the OUTGOING
    //    epoch's shares.
    oldEpoch := em.currentKeys
    oldShares := convertToReshareInput(oldEpoch)

    // 2. Compute new committee party IDs (1-indexed).
    newSet := buildPartyIDs(newValidators)

    // 3. Run reshare. The randSource MUST be mixed by the consensus
    //    layer from a per-epoch entropy beacon (e.g. the previous
    //    block's hash + an honest-validator BLS contribution). Each
    //    PARTICIPATING outgoing validator runs Reshare LOCALLY with
    //    its OWN share + its OWN local randomness, then ships
    //    g_i(j) to each new validator. The function below is what
    //    one outgoing validator runs.
    newShares, err := reshare.Reshare(
        ringParams.R,
        oldShares,
        oldEpoch.Threshold,
        newSet,
        em.threshold,
        per_party_rng_source(epoch),
    )

    // 4. Wrap the new shares into Ringtail KeyShare instances.
    //    GroupKey is INHERITED from the old epoch — same A, same b̃.
    newKeyShares := wrapAsRingtailShares(
        newShares, oldEpoch.GroupKey,
        recomputeLagrangeCoefficients(newValidators, em.threshold),
    )

    // 5. Activation certificate: the new committee threshold-signs
    //    the transcript of the resharing under the SAME group key.
    //    Chain accepts the new epoch only when this cert verifies.
    activationSig, err := signActivationCert(
        newKeyShares, oldEpoch.GroupKey,
        transcriptHash(epoch, oldValidators, newValidators, em.threshold),
    )

    // 6. Build new EpochKeys with the inherited group key.
    return &EpochKeys{
        Epoch:        epoch + 1,
        ValidatorSet: newValidators,
        Threshold:    em.threshold,
        GroupKey:     oldEpoch.GroupKey,  // unchanged!
        Shares:       newKeyShares,
        // ...
    }, nil
}
```

## Critical design points

1. **GroupKey inheritance.** The `GroupKey` (which contains `A` and
   `bTilde`) is set at genesis and persists for the lifetime of the
   group. Every epoch's `EpochKeys.GroupKey` points to the same
   underlying object. This is what makes `VerifySignatureForEpoch`
   work across epochs without separate per-epoch verification keys
   and what eliminates the need for "verification key history".

2. **Lagrange coefficients are recomputed per epoch.** In the old
   `sign.Gen` flow, each party's `Lambda` is baked into its share.
   Reshare produces shares in the standard polynomial-evaluation form,
   so each party computes its `Lambda` on the fly using
   `primitives.ComputeLagrangeCoefficients` over the active signing
   set. This is a tiny computation (one Lagrange basis evaluation per
   signer per signing session) and avoids the need for any committee-
   specific share preprocessing.

3. **Pairwise channels.** `Reshare` outputs the kernel — the function
   computes one party's shares from its own old share + fresh
   randomness, but assumes a magic transport. In the wire integration:

   - Each outgoing party `i` independently:
     - Computes `g_i(X)` (one polynomial of degree `t_new - 1`).
     - Evaluates at every `j ∈ new_set`.
     - Encrypts `g_i(j)` for party `j` under their pairwise key
       (X25519 + ML-KEM hybrid).
     - Broadcasts the ciphertexts on a chain-anchored bulletin board.

   - Each incoming party `j` independently:
     - Decrypts the `t_old` (or fewer, if some `i ∈ Q` are unavailable)
       envelopes addressed to it.
     - Sums the decrypted `g_i(j)` values.
     - Result is `s'_j`.

4. **VSR layer (out of scope here).** The kernel above is correct
   under honest-but-curious dealers. For full Byzantine resilience the
   following are required, in `pulsar/dkg2/` (parallel track):
   - Pedersen-style polynomial commitments to `g_i`.
   - Complaint protocol for inconsistent dealings.
   - Deterministic disqualification + re-quorum.

5. **Activation certificate.** The chain MUST NOT accept a new epoch
   unless the new committee can produce a valid threshold signature
   under the inherited `GroupKey`. This proves liveness of the new
   committee. The activation message is the transcript hash of the
   resharing.

6. **Genesis is special.** The initial `s` must come from somewhere:
   - Foundation MPC ceremony (recommended): N geographically distinct
     parties run a verifiable DKG once, ship transcripts; chain genesis
     pins `bTilde`.
   - Trusted-dealer (acceptable for testnets only): one party runs Gen,
     publishes `bTilde`, deletes `s`.

   After genesis, **no party ever re-derives `s`**.

7. **Refresh between rotations.** Within a stable validator set, the
   `pulsar/reshare.Refresh` primitive runs the HJKY97 zero-polynomial
   update. Recommended cadence: every `MaxEpochDuration` (1 hour by
   default) even when validator set unchanged. This defeats a mobile
   adversary that compromises < t parties per epoch and tries to
   accumulate share material over time.

## Migration path

Phase 1 (this PR): land the kernel + KAT + C++ port. No consensus
changes yet. Resharing is callable from tests but not from production.

Phase 2: add `RotateEpochViaReshare` to `epoch.go` behind a feature
flag. Existing `RotateEpoch` (which calls `GenerateKeys`) remains the
default. New method is exercised on devnet only.

Phase 3: wire VSR layer (commitments, complaints, activation) on top
of `RotateEpochViaReshare`. Continue devnet exercise; harden against
adversarial validators.

Phase 4: switch testnet default to resharing. Run for at least one
month with mixed honest/byzantine drills. Continue to allow
`GenerateKeys` as escape hatch via governance proposal.

Phase 5: switch mainnet default. `GenerateKeys` removed from epoch
code path; only callable for testnet bootstrap.

## Proof of public-key invariance (test)

```go
// pulsar/reshare/integration_test.go: TestResharePreservesPublicKey
//
// Demonstrates the load-bearing claim:
//
// 1. Sample s, A, e at genesis. Compute b = A·s + e, b̃ = round(b, ξ).
// 2. Standard-Shamir-share s across 3 parties with threshold 2.
// 3. Run the existing 2-round Sign protocol with the OLD committee.
//    Verify the resulting signature against b̃. Pass.
// 4. Reshare onto a 5-party committee with threshold 3, FRESH PARTY
//    IDs (no overlap with old committee).
// 5. Run Sign again with the NEW committee. Verify against the SAME
//    b̃ from step 1. Pass.
//
// Test status: PASSING.
```

Test output (current run):

```
=== RUN   TestResharePreservesPublicKey
    integration_test.go:131: OLD: signature verified
    integration_test.go:213: NEW: signature verified
    integration_test.go:217: PASS: NEW-committee signature verifies against
                                   UNCHANGED public key b̃
--- PASS: TestResharePreservesPublicKey (0.53s)
```
