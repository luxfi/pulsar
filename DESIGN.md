# Pulsar — Design for leaderless permissionless Quasar

> Lux is not merely adding post-quantum signatures to a chain; it defines a hybrid finality architecture for DAG-native consensus, with protocol-agnostic threshold lifecycle, post-quantum threshold sealing, and cross-chain propagation of Horizon finality.

See [LP-105 §Claims and evidence](https://github.com/luxfi/lps/blob/main/LP-105-lux-stack-lexicon.md#claims-and-evidence) for the canonical claims/evidence table and the ten architectural commitments. This DESIGN.md does not duplicate them.

**Pulsar in one paragraph.** One **trusted setup** at chain genesis (a one-time MPC ceremony confined to the launch of a *key era*), then **verifiable resharing** at every epoch boundary. The persistent group public key — `(A, bTilde)` — survives every validator-set rotation; only the share distribution rotates. The hidden signing secret `s` is preserved across epochs *within a key era*. Reanchor (rare governance event) opens a new key era with a fresh `(A', s', e', bTilde')`.

This document is the **single source of truth** for the Pulsar lifecycle and Quasar integration. Every Go and C++ file should be reviewable against the contracts here.

---

## The Pulsar metaphor (load-bearing, not flavor)

```
Persistent body  →  GroupKey, A, hidden master secret s
Rotating beam    →  epoch share distribution
Observed pulse   →  threshold certificate emitted periodically
```

A pulsar is a rotating neutron star. The body persists; only the beam direction rotates. Pulses are observed periodically as the beam sweeps past. That is exactly the resharing invariant: the GroupKey persists across epochs within a key era, only the share distribution rotates, and each Quasar bundle produces one threshold certificate (a "pulse") signed under the unchanged GroupKey.

Use this metaphor explicitly in code comments and papers. It makes the design self-documenting.

---

## Vocabulary stack (Quasar consensus stack)

Pulsar is one lane of the Quasar consensus stack. The full vocabulary (each name does ONE job — do not conflate them):

| Name | Role | Layer | Per-validator |
|---|---|---|---|
| **Photon** | individual validator vote / attestation | message | own credential |
| **Lumen** | PQ E2E stream that *carries* Photons | transport | own hybrid-KEM/ML-DSA keys + OTS hypertree |
| **Beam** | classical aggregate certificate | finality | own BLS keypair |
| **Pulsar** | post-quantum threshold engine | finality | **share** of one group key |
| **Pulse** | one Pulsar certificate (over a bundle) | finality artifact | — |
| **ML-DSA** | PQ accountability lane (cert *set*, not aggregate) | finality | own ML-DSA keypair |
| **Horizon** | Quasar finality boundary; combines all lanes | finality | — |
| **Quasar** | full leaderless consensus protocol | (whole stack) | — |

> *Photons travel through Lumen streams. Beams aggregate classical votes. Pulsars emit PQ threshold pulses. Quasar reaches the Horizon when finality is sealed.*

### Lumen ≠ Pulsar (critical distinction)

| | Lumen (transport) | Pulsar (finality) |
|---|---|---|
| **Layer** | encrypted+authenticated stream | threshold signature certificate |
| **Confidentiality** | yes — hybrid KEM (X-Wing combiner: ML-KEM-768 ⊕ X25519, cited as primitive) + AEAD ratchet | n/a — finality is public |
| **Authentication** | per-frame OTS signatures rooted at ML-DSA stream-root | threshold sig over bundle root |
| **Per-validator key** | own ML-DSA root + OTS hypertree + hybrid-KEM recipient keys | **share** of one Pulsar group key |
| **Uses ratchet?** | yes — AEAD chain key + periodic hybrid-KEM rekey | no |
| **Equivocation slashing** | yes — same `stream_root`+`leaf_index`+two digests = double-sign proof | yes — via complaint pipeline at reshare |
| **Lives at** | `~/work/lux/lumen/` (forthcoming, separate repo) | `~/work/lux/pulsar/` (this repo) |

The two are complementary, not alternatives. A validator running full Quasar holds:

- BLS keypair (independent) — for Beams
- ML-DSA keypair (independent) — for accountability + Lumen stream root
- Hybrid-KEM recipient keys (independent; see X-Wing combiner) — for Lumen confidentiality
- OTS hypertree (independent) — for Lumen per-frame auth
- One **share** of the Pulsar group key — for Pulses

### Lumen stream layer (sketch — separate work, not in this repo)

```
type LumenStreamRoot struct {
    ChainID, NetworkID, Epoch          uint64
    StreamID, ValidatorID              ids.ID
    XWingRecipientOrSession            []byte   // ML-KEM-768 ⊕ X25519 hybrid
    OTSRoot                            []byte   // hypertree root
    Capacity                           uint64
    IdentityScheme                     string   // "ML-DSA-65"
    IdentitySig                        []byte   // ML-DSA over the above
}

type LumenFrame struct {
    StreamID     ids.ID
    Seq          uint64
    LeafIndex    uint64
    PayloadType  uint16
    Ciphertext   []byte    // AEAD-encrypted under chain-key-derived frame key
    AEADTag      []byte
    OTSSig       []byte    // one-time signature over frame digest
    AuthPath     [][]byte  // Merkle path to OTSRoot
}
```

Verification:

1. Verify ML-DSA signature on stream root.
2. Use hybrid-KEM-derived session key to decrypt frame.
3. Verify frame sequence / anti-replay.
4. Verify OTS signature on frame digest.
5. Verify OTS leaf path to stream root.
6. Reject and emit slashing evidence if the same `(stream_root, leaf_index)` is observed under two different digests.

PFS construction (against later endpoint-key compromise):

```
root_secret  = HybridKEM(static_kem_keys, ephemeral_kem_keys)  // X-Wing combiner
chain_key_0  = HKDF(root_secret, transcript_binding)
for each frame i:
    frame_key_i, chain_key_{i+1} = HKDF(chain_key_i)
    erase frame_key_i and chain_key_i

every N frames or M seconds:
    run fresh hybrid-KEM encapsulation
    mix new shared secret into chain_key
    erase old state
```

The hybrid-KEM handshake alone is NOT PFS. The KEM/symmetric ratchet above is. OTS is forward-secure *authentication* (after a leaf is erased, even total compromise of current signing state cannot forge past frames) — distinct from PFS confidentiality.

> *Where age fits.* Encrypted snapshots, validator backup material, state-sync chunks, archive bundles, key-ceremony artifacts, and offline transport of Pulsar shares. For high-throughput live consensus streams, use the Lumen stream protocol (which borrows age's design principles — small explicit keys, hybrid PQ recipient wrapping, random session key, streamed AEAD, simple framing — but as an interactive session protocol, not file-by-file).

The composition Quasar emits at finality:

```go
type HorizonCertificate struct {
    Beam       bls.AggregateCertificate
    MLDSA      mldsa.CertificateSet      // NOT "aggregate" — it's a cert set with signer bitmap
    Pulsar     pulsar.Certificate        // the threshold pulse
    KeyEraID   pulsar.KeyEraID
    GroupID    pulsar.GroupID
    BundleRoot ids.ID
}
```

> **Groth16 is NOT post-quantum.** The optional Z-Chain Groth16 rollup that may compress the ML-DSA cert-set is a *classical succinct proof of post-quantum signature verification*. Pairing-based SNARKs are broken under Shor's algorithm. PQ finality lives in **ML-DSA + Pulsar**, never in any pairing-based wrapper. Use Groth16 only as a compatibility/compression layer for EVM verifiers.

> **Network tier model.** L1 = sovereign chain (default). L2 = co-validation binding to a primary network (not a rollup). L3 = rollup / validity / app-specific execution layer (settles via succinct proof, fraud proof, or FHE). A chain's choice of proof system does not define its tier; the tier is the *role*. See LP-105 for the canonical definition.

---

## Relationship to LSS

**Pulsar is not a replacement for LSS. Pulsar is the lattice adapter that makes LSS dynamic resharing available to Ringtail-style post-quantum threshold finality.**

LSS is Lux's generic dynamic threshold lifecycle framework (`~/work/lux/threshold/protocols/lss/`, paper-backed by Seesahai 2025). It **owns** the orchestration:

- Generation numbers and version monotonicity
- Rollback lineage and `GenerationSnapshot` history
- Live resharing orchestration (no-downtime transitions, Section 4)
- `Bootstrap Dealer` and `Signature Coordinator` role separation
- Protocol adapter boundaries (`lss_frost.go`, `lss_cmp.go`, future `lss_pulsar.go`)

Pulsar **contributes** the lattice math the framework needs:

- `R_q` share representation (Z_q[X]/(X^N+1) over a 48-bit NTT prime)
- Pedersen-style commitments where applicable (`A·NTT(s) + B·NTT(r)`)
- Ringtail/Pulsar signing material: `Lambda` + PRF `Seeds` + `MACKeys` regeneration
- Activation certificate **message format** (the lattice signature itself)
- Lattice-specific transcript binding for Quasar epochs

What Pulsar must NOT inherit from LSS-ECDSA internals:

- ECDSA auxiliary secrets `w`, `q` (Section 4 nonce blinding) — Ringtail's signing protocol has Gaussian noise blinding built into Sign1/Sign2; no `w, q` needed
- `curve.Point` Pedersen commits — replaced by lattice commits over `R_q`
- ECDSA scalar serialization
- Curve-specific Lagrange interpolation — replaced by `primitives.ComputeLagrangeCoefficients` over Z_q

What Pulsar must NOT duplicate from LSS framework:

- Generation tracking (use LSS `Generation uint64`)
- Rollback semantics (use LSS `RollbackManager`)
- Snapshot persistence (use LSS `GenerationSnapshot`)
- Failure response: do **not** invent "activation-fails-then-fall-back" semantics inside Pulsar; emit the failure and let LSS `RollbackManager.Rollback(targetGeneration)` restore the prior snapshot

The `pulsar/keyera/` package is a **standalone reference lifecycle** for in-process tests + KAT replay. It is NOT the production orchestration layer. Production goes through `threshold/protocols/lss/lss_pulsar.go`.

---

## Bootstrap Dealer vs Signature Coordinator (LSS roles, no-slashing semantics)

The LSS paper distinguishes two operational roles. Pulsar inherits both names and contracts. Crucially: **failure responses are non-punitive**. There is no slashing dependency in either role — failures retry, rollback, or reanchor.

| Role | LSS responsibility | Pulsar / Quasar mapping | Failure response |
|---|---|---|---|
| **Bootstrap Dealer** | Network membership manager; orchestrates resharing; never holds unencrypted secrets | Foundation MPC node at chain genesis (Bootstrap); P-Chain governance authority for Reanchor | If ceremony fails: retry; if persistent failure: governance reanchor (new KeyEraID) |
| **Signature Coordinator** | Operational workhorse; collects Pulsar partials; combines certificates | Quasar block proposer / per-epoch consensus runtime; coordinates Sign1/Sign2/Combine for each Pulse over a bundle | If signing fails: retry with another coordinator; if a generation can't activate: Rollback to previous Generation; ultimate fallback: reanchor |

Crucially, the two roles are **distinct authorities**:

- A compromised Signature Coordinator cannot reshare or change the validator set (it has no membership-management authority).
- A compromised Bootstrap Dealer (at non-Bootstrap times) cannot sign (it holds no shares; only the membership-management authority).

Coordinator failure doesn't punish anyone. The chain's response is graded:

```
1. Coordinator timeout / unavailable
   → consensus picks the next coordinator deterministically.

2. Resharing round fails (commit mismatch, bad share, etc.)
   → emit signed evidence of the failure point; retry under new
     transcript binding next epoch.

3. Activation cert fails to verify under unchanged GroupKey
   → LSS Rollback(targetGeneration = current - 1); chain stays at
     the previous generation; signing continues.

4. Multiple consecutive activation failures
   → governance reanchor: new KeyEraID, fresh ceremony, new GroupKey.
```

No step in this ladder requires identifying a malicious actor. Slashing evidence is **collected** during steps 2-3 (the LSS framework persists signed messages from the failed protocol run for later forensic review), but the chain's liveness and safety do not depend on attribution. This is the no-slashing-dependency property.

---

## The codebase invariant (enforce loudly)

```
BLS lane:    each validator has its OWN keypair.
ML-DSA lane: each validator has its OWN keypair.
Pulsar lane:  each validator has a SHARE of one group key — NOT a keypair.
```

Resharing reshuffles shares. It does NOT make independent keys threshold-compatible. Anyone proposing "give each validator their own Ringtail keypair" is conceptually proposing to delete Ringtail's threshold property — which is the only reason to use it.

---

## Language discipline

The shipping plan stands or falls on language honesty. The following pairs are not stylistic preferences — using the wrong vocabulary leaks into code, comments, and papers and gives readers a wrong mental model.

| Wrong / loose | Right |
|---|---|
| "key rotation" (per epoch) | **share rotation** (per epoch); key rotation only at Reanchor |
| "same `s` forever" | **same `s` within a key era**; new `s` only at Reanchor |
| "Bitcoin-like launch" | **one-time trusted setup** confined to genesis of one key era |
| "activation cert proves VSR was correct" | **activation cert proves new signing capability** under the unchanged GroupKey |
| "DKG runs every epoch" | DKG only at Reanchor (rare); routine epochs use **resharing** |

A Pulsar genesis ceremony has a toxic-waste trust assumption: someone once knew `s` while constructing the shares; if `s` was retained, copied, exfiltrated, or generated maliciously, the long-lived Pulsar group key is compromised. Bitcoin did not require users to trust that any launch secret was erased. The honest framing is: *Layer 1 assumes a one-time trusted setup / ceremony for the initial Pulsar group key. The trust is confined to genesis of that key era. Subsequent validator rotations use verifiable resharing and do not require a trusted dealer.*

---

## Three layers, one shipping path

| Layer | Operation | Trigger | Trust |
|---|---|---|---|
| 1. **Bootstrap** | trusted-dealer `Gen(s, A, e) → (bTilde, shares)` | Chain genesis, ONCE per key era | Foundation MPC ceremony, observable, single one-time trust event |
| 2. **Reshare** | preserves `s, bTilde, GroupKey`; rotates share distribution | Every epoch with validator-set change | NO new trust; old qualified subset Q (size ≥ t_old) cooperates to deliver fresh sharing |
| 3. **Reanchor** | new `(s', A', e', bTilde')` | Rare governance event (suspected long-tail share leakage) | Same as Bootstrap; new key era ID |

Layer 1 is what `pulsar/threshold.GenerateKeys` already does (with a fix in `pulsar/keyera` to use general Shamir for proper t-of-n). Layer 2 is the only new package needed. Layer 3 is just "Layer 1 again" with a governance-gate and an EraID bump.

### What is preserved across resharing within a key era

| Quantity | Status across resharing |
|---|---|
| `A` (public matrix) | **PRESERVED** |
| `s` (hidden signing secret) | **PRESERVED** (its share distribution rotates) |
| `bTilde` (rounded public key) | **PRESERVED** |
| `GroupKey` (= `(A, bTilde)`, byte-identical) | **PRESERVED** |
| `e` (LWE error) | **NOT preserved.** Used at genesis to form `bTilde = Round(A·s + e)`; erased with dealer state. Operationally, signers only need shares of `s` — they do not need `e`. |
| Share distribution `{s_i}` | **ROTATED** |
| Pairwise PRF/MAC material | **REGENERATED** for the new committee via authenticated KEX |

---

## Two distinct primitives in `pulsar/reshare/`

Do NOT bury these under one fuzzy `Reshare` call.

### Refresh (same set, fresh shares)

Each party samples a degree-`t-1` polynomial `z_i(x)` with `z_i(0) = 0`. Distributes `z_i(α_j)` to each peer. Each party updates `s'_j = s_j + Σ_i z_i(α_j)`. Master secret unchanged.

```go
// Refresh produces fresh shares for the SAME committee at the SAME threshold.
// Defends against mobile-adversary share accumulation across time.
func Refresh(
    params *threshold.Params,
    committee []ValidatorID,                          // unchanged
    threshold int,                                    // unchanged
    oldShares map[ValidatorID]*threshold.KeyShare,
    transcript TranscriptBinding,                     // chain_id, epoch, group_id
    pairwiseKEX func(i, j ValidatorID) []byte,        // for re-deriving Seeds/MACKeys
) (map[ValidatorID]*threshold.KeyShare, []byte, error)
```

### ReshareToNewSet (set rotation, new shares)

Old qualified subset `Q ⊆ O` with `|Q| ≥ t_old` cooperates. Each `i ∈ Q` samples fresh polynomial `g_i(x)` of degree `t_new - 1` with `g_i(0) = s_i` (their own old share as constant term). Delivers `g_i(β_j)` to each new party `j`. New party `j` computes `s'_j = Σ_{i ∈ Q} λ^Q_i · g_i(β_j)` where `λ^Q_i` are Lagrange coefficients for `Q` evaluated at 0. New polynomial `g(x) = Σ λ^Q_i · g_i(x)` satisfies `g(0) = Σ λ^Q_i · s_i = s` — recovers the same master secret structurally.

```go
// ReshareToNewSet produces fresh shares for a NEW committee from an old qualified subset.
// Master secret s, A, bTilde, GroupKey all preserved. The error e is NOT carried —
// signers only need shares of s.
func ReshareToNewSet(
    params *threshold.Params,
    qualifiedOldSet []ValidatorID,                    // |Q| >= t_old; deterministic ordering
    oldShares map[ValidatorID]*threshold.KeyShare,
    oldThreshold int,
    newSet []ValidatorID,
    newThreshold int,
    transcript TranscriptBinding,
    pairwiseKEX func(i, j ValidatorID) []byte,
) (map[ValidatorID]*threshold.KeyShare, []byte, error)
```

---

## What a complete Pulsar share state looks like

`KeyEraID`, `Generation`, and `RollbackFrom` are **three distinct concepts** — do not collapse them:

| Field | Meaning | Bumps when |
|---|---|---|
| `KeyEraID` | Pulsar group-key **lineage**. The persistent (A, bTilde) public key. | Only at **Reanchor** (rare governance event); fresh GroupKey. |
| `Generation` | LSS resharing **version** within an era. | Every Refresh or Reshare under the same GroupKey. |
| `RollbackFrom` | Audit lineage when reverting to an older generation. | Set to the previous `Generation` only when this state descends from a Rollback; zero on ordinary forward transitions. |

Concrete trajectory example:

```
KeyEraID = 7, Generation = 0, RollbackFrom = 0   genesis state of era 7
KeyEraID = 7, Generation = 1, RollbackFrom = 0   reshared to a new validator set
KeyEraID = 7, Generation = 2, RollbackFrom = 0   refreshed (same set)
KeyEraID = 7, Generation = 3, RollbackFrom = 0   reshared again
KeyEraID = 7, Generation = 4, RollbackFrom = 2   activation @gen 3 failed; reverted to gen 2
KeyEraID = 8, Generation = 0, RollbackFrom = 0   reanchor: fresh GroupKey, new era
```

```go
// EpochShareState replaces consensus/protocol/quasar/EpochKeys.
// Distinguishes "share distribution rotates" from "key rotates".
type EpochShareState struct {
    // ── Lineage (changes only at Reanchor) ──
    KeyEraID     uint64                            // Pulsar group-key lineage
    GroupID      PulsarGroupID                     // group within a partitioned-set deployment
    GroupKey     *threshold.GroupKey               // A, bTilde, params (byte-identical within era)
    GenesisEpoch uint64                            // when this era's bootstrap/reanchor happened

    // ── LSS lifecycle (managed by threshold/protocols/lss) ──
    Generation   uint64                            // resharing version within this key era
    RollbackFrom uint64                            // nonzero only if this state descends from rollback

    // ── Per-epoch state (rotates every Refresh / Reshare) ──
    Epoch              uint64
    Validators         []ValidatorID
    Threshold          int
    Shares             map[ValidatorID]*threshold.KeyShare
    PairwisePRFSeeds   map[ValidatorID]map[ValidatorID][]byte
    PairwiseMACKeys    map[ValidatorID]map[ValidatorID][]byte
    OldSetHash         []byte
    NewSetHash         []byte
    ResharingTranscriptHash []byte
    ActivationCert     *threshold.Signature        // proves new signing capability
}
```

Pairwise material is **regenerated per epoch** via authenticated KEX between new validators (ML-KEM-768 hybrid recommended for PQ-aware deployments):

```
pair_secret_ij = KEX(validator_i_identity, validator_j_identity)
seed_i_j       = KDF(pair_secret_ij, "pulsar.reshare.prf-seed.v1",
                     chain_id, epoch, group_id, i, j)
mac_i_j        = KDF(pair_secret_ij, "pulsar.reshare.mac-key.v1",
                     chain_id, epoch, group_id, i, j)
```

Domain-separation tags MUST be distinct from any other Pulsar/Ringtail KDF tag.

---

## Domain-separated message prefixes

Every signature produced under any Quasar lane carries a distinct version-tagged prefix. **No shared prefix between any two.** Pin these now before KATs spread.

| Prefix | Used for | Lane |
|---|---|---|
| `QUASAR-PHOTON-VOTE-v1` | Individual validator vote / attestation | (any) |
| `QUASAR-BEAM-BLS-v1` | BLS aggregate certificate | Beam |
| `QUASAR-MLDSA-ATTEST-v1` | ML-DSA attestation set | ML-DSA |
| `QUASAR-PULSAR-BUNDLE-v1` | Pulsar pulse over a Quasar bundle | Pulsar |
| `QUASAR-PULSAR-SIGN1-v1` | Pulsar signing Round 1 message | Pulsar |
| `QUASAR-PULSAR-SIGN2-v1` | Pulsar signing Round 2 message | Pulsar |
| `QUASAR-PULSAR-COMBINE-v1` | Pulsar finalize transcript | Pulsar |
| `QUASAR-PULSAR-REFRESH-v1` | Refresh activation cert (same set) | Pulsar |
| `QUASAR-PULSAR-RESHARE-v1` | Reshare activation cert (set rotation) | Pulsar |
| `QUASAR-PULSAR-ACTIVATE-v1` | Generic activation cert (Refresh/Reshare alias) | Pulsar |
| `QUASAR-PULSAR-REANCHOR-v1` | Reanchor authorization (governance) | Pulsar |

If a new class of signed message emerges, it MUST get its own version-tagged prefix; never reuse one.

### Activation message canonical bytes

The activation message bound by the new committee under the unchanged GroupKey:

```
QUASAR-PULSAR-ACTIVATE-v1 ||
    chain_id ||
    network_id ||
    key_era_id ||
    group_id ||
    old_epoch ||
    new_epoch ||
    old_validator_set_hash ||
    new_validator_set_hash ||
    old_threshold ||
    new_threshold ||
    group_public_key_hash ||
    reshare_transcript_hash ||
    pairwise_material_commitment_hash ||
    implementation_version
```

The last two fields are essential for KAT/cross-language byte-identical replay. `pairwise_material_commitment_hash` binds the new committee's pairwise PRF/MAC derivation to a specific transcript moment. `implementation_version` distinguishes Go and C++ ports during development and pins the canonical byte format.

---

## Activation cert (the circuit-breaker)

After resharing finishes the math, the chain does NOT accept the new epoch on faith. The new committee threshold-signs an activation message under the **unchanged GroupKey** using their freshly-derived shares; only when this signature verifies does the chain mark the new epoch live.

```
activation_msg = "QUASAR-PULSAR-ACTIVATE-v1"
               || transcript_hash       (32 bytes; from TranscriptInputs.Hash)
               || reshare_transcript_hash (32 bytes; exchange digest)

activation_sig = threshold.Sign(new_shares, activation_msg)

if threshold.Verify(unchanged_GroupKey, activation_msg, activation_sig) == OK:
    chain accepts new_epoch as live
else:
    new_epoch rejected; old_committee continues; reshare must restart
```

### What activation proves (only this)

**Successful new signing capability under the unchanged GroupKey.** That is, the new committee collectively holds enough usable shares to sign under the original group public key.

### What activation does NOT prove

| Property | Where it is established |
|---|---|
| which old party sent a bad contribution | Complaint pipeline (`pulsar/reshare/complaint.go`) |
| which new party lied about receiving one | Complaint pipeline |
| whether all contributions were polynomial-consistent | Pedersen-style commits + verifier (`pulsar/reshare/commit.go`) |
| whether a malicious old subset caused a failed activation | Complaint quorum + disqualification logic |
| publicly attributable evidence for slashing | Slashing-evidence pipeline at consensus layer (next-PR work) |

Activation is necessary but **not sufficient** for the full Byzantine-attribution story. The three pipelines — activation, complaint+disqualification, slashing evidence — are distinct and must not be conflated.

---

## VSR maturity ladder

There are two distinct production targets, with very different effort budgets:

### MVP VSR (first shipping target)

- Encrypted resharing channels (X25519 + Ed25519; ML-KEM hybrid wraps additively).
- Signed messages from each old participant.
- Deterministic transcript hash bound to `(chain_id, group_id, era_id, old_epoch, new_epoch, old_set_hash, new_set_hash, thresholds, group_pk_hash)`.
- Pedersen-style commitments to share polynomials.
- Activation certificate gating epoch acceptance.
- Fallback path: if activation fails, old committee continues; chain stays at old epoch.

This is `pulsar/reshare/` today. Effort estimate from "kernel landed" to "Quasar-integrated MVP": **8-13 weeks** for an engineer fluent in Quasar internals, including consensus go.mod migration, complaint mempool, and Ringtail KAT extension. Production hardening (mlock-pinned shares, secure erasure pinpointing, transport ML-KEM hybrid) adds another 2-4 weeks.

### Robust VSR (mainnet-grade target)

- Complaint phase with timeout discipline.
- Deterministic disqualification of bad senders.
- **Public, attributable slashing evidence** — without leaking enough share material to reconstruct the master secret.
- Slashing integration at the consensus layer.

The hard part is item 3. For old-set-to-new-set resharing, old party `i` sends `g_i(β_j)` to new party `j`. If a complaint reveals too many such values publicly, the network may reconstruct `g_i(x)`, including `g_i(0) = s_i` — which is dangerous in a (t_old, n_old)-Shamir scheme that uses small `t_old`. So the evidence model needs care.

| Failure class | Evidence shape |
|---|---|
| Missing message | Timeout + signed absence statements; weaker. |
| Equivocation | Two signed conflicting messages from the same old party; cleanly attributable. |
| Malformed ciphertext | Public failure evidence depends on the encryption layer (e.g., decryption oracle); careful design needed. |
| Invalid share contribution | Hard to prove publicly without one of: hiding commitments / PVSS; ZK proof; or a blame protocol that does not leak threshold-reconstructing data. |

Effort budget for "publicly slash every invalid share contribution without leakage" is significantly more than MVP — likely **another 6-12 weeks** of focused engineering plus formal review.

The shipping plan: land MVP first; iterate on Robust as a separate workstream.

---

## Threshold layer wiring (`~/work/lux/threshold`)

`~/work/lux/threshold` is THE consolidation point for all Lux threshold protocols. It already contains `protocols/{bls, mldsa, ringtail, frost, cmp, doerner, lss, tfhe, quasar}/`.

**Pulsar is the lattice adapter to LSS.** Just as `lss_frost.go` adapts FROST to LSS's dynamic-resharing framework and `lss_cmp.go` adapts ECDSA-CMP, `lss_pulsar.go` adapts Pulsar.

### LSS is the canonical orchestration framework

LSS (Linear Secret Sharing) is the formally-specified Lux dynamic-resharing framework, paper-backed by Vishnu J. Seesahai's *"LSS MPC ECDSA: A Pragmatic Framework for Dynamic and Resilient Threshold Signatures"* (Aug 2025). Implementation lives at `~/work/lux/threshold/protocols/lss/`.

LSS already provides:

| Component | Lives at | Provides |
|---|---|---|
| `DynamicLSS` | `lss/dynamic.go` | Generation tracking, no-downtime resharing orchestration (Section 4) |
| `RollbackManager` + `GenerationSnapshot` | `lss/rollback.go` | Point-in-time config history; rollback on signing failure (Section 6) |
| `Generation uint64` + `RollbackFrom uint64` on every config | `lss/config/config.go` | Audit-trail fields, every epoch versioned |
| `JVSS` (Joint Verifiable Secret Sharing) | `lss/jvss/` | Pedersen commits + ZK proofs for share validity |
| 3-round wire protocol | `lss/reshare/round{1,2,3}.go` | Generic round-based reshare wire format |
| Bootstrap Dealer role | (paper §3) | Long-lived membership manager, never holds unencrypted secrets |
| Signature Coordinator role | (paper §3) | Operational signing orchestrator, distinct from dealer |
| `DynamicReshareFROST`, `DynamicReshareCMP` | `lss/lss_frost.go`, `lss/lss_cmp.go` | Per-protocol adapters |

What is **scheme-specific** in LSS (and therefore not reusable verbatim for Pulsar):

- The auxiliary secrets `w` and `q` for ECDSA multiplicative nonce blinding (Protocol I/II). Pulsar/Ringtail's signing protocol has its own Gaussian-noise blinding built into Sign1/Sign2; no `w, q` needed.
- The `curve.Point` Pedersen commits in JVSS — for Pulsar these become `A·NTT(s) + B·NTT(r)` lattice commits over R_q.

What IS reusable verbatim:

- The orchestration: `DynamicLSS`, `RollbackManager`, generation tracking.
- The 3-round wire protocol shape: commitments → private deliveries → combine + activate.
- The dealer/coordinator role separation.
- The adapter pattern (`lss_pulsar.go` analogous to `lss_frost.go`).

### Concept mapping (Pulsar ↔ LSS)

The naming I introduced in pulsar/keyera duplicates what LSS already names. The paper-backed names take precedence; pulsar should align.

| Pulsar (current) | LSS (paper-backed) | Action |
|---|---|---|
| `PulsarKeyEraID` | `Generation uint64` (with `RollbackFrom uint64`) | Pulsar should also expose Generation/RollbackFrom on EpochShareState; KeyEraID can remain as a coarser "key era" boundary that bumps only at Reanchor |
| `Reshare` advance | `LiveReshare` (LSS Section 4) | Same Section 4 semantics; Pulsar adapter calls into pulsar/reshare for lattice math |
| Activation-cert-fail → continue old epoch | `Rollback(targetGeneration)` | Pulsar should expose explicit Rollback API, not just implicit fallback |
| `EpochShareState` | `config.Config` (per-protocol) | Parallel construction; OK to keep distinct types per protocol |
| In-process `keyera.KeyEra` lifecycle wrapper | `DynamicLSS` orchestrator | LSS is the right abstraction at the orchestration layer; keyera stays as the kernel-level reference |
| (none in pulsar) | Bootstrap Dealer / Signature Coordinator role separation | Add to pulsar DESIGN as the role split for distributed deployment |
| (none in pulsar) | `RollbackManager.SaveSnapshot` | Add to pulsar via the LSS adapter (don't duplicate) |

### Bootstrap Dealer vs Signature Coordinator (LSS paper roles)

The LSS paper distinguishes two operational roles. They map onto Quasar deployment:

| Role | LSS responsibility | Quasar mapping |
|---|---|---|
| **Bootstrap Dealer** | Network membership manager, orchestrates resharing; never handles unencrypted secrets | Foundation MPC node at chain genesis (Bootstrap); P-Chain governance authority for Reanchor; never holds master `s` after ceremony close |
| **Signature Coordinator** | Operational workhorse exposing public signing API; collects partial signatures; triggers rollback on failure | Quasar block proposer / consensus runtime per-epoch; coordinates Sign1/Sign2/Combine for Pulse emission over each bundle |

The two roles are **distinct**: a compromise of the Signature Coordinator does not give an adversary the ability to reshare, and a compromise of the Bootstrap Dealer (at non-Bootstrap times) does not let it sign — because the dealer holds no shares, only the membership-manager authority.

### Layer separation

```
~/work/lux/pulsar/                         # MATH KERNEL
  ├── primitives, sign, threshold, reshare, dkg2, keyera
  ├── single-process API; deterministic; KAT-replayable
  └── lattice-specific: Pedersen R_q commits, NTT, Gaussian sampling

~/work/lux/threshold/protocols/lss/        # ORCHESTRATION FRAMEWORK
  ├── DynamicLSS, RollbackManager, JVSS    (generic, paper-backed)
  ├── lss_frost.go: DynamicReshareFROST    (Schnorr/EdDSA adapter)
  ├── lss_cmp.go:   DynamicReshareCMP      (ECDSA adapter)
  └── lss_pulsar.go: DynamicResharePulsar  (lattice adapter — TO ADD)

~/work/lux/threshold/protocols/pulsar/     # ROUND-BASED WRAPPER
  ├── pulsar.go (thin pass-through)
  └── doc.go (full vocabulary stack)
```

### Reuse pattern (the LSS adapter contract)

`lss_pulsar.go: DynamicResharePulsar` is the analogue of `lss_frost.go: DynamicReshareFROST`. Shape:

```go
// DynamicResharePulsar performs the LSS dynamic resharing protocol on
// Pulsar configurations. Implements LSS Section 4 — transition from
// T-of-N to T'-of-(N±k) without reconstructing the master key —
// adapted for the Pulsar lattice setting.
//
// Pulsar lattice math diverges from LSS ECDSA in three places:
//
//  1. Pedersen commits use A·NTT(s) + B·NTT(r) over R_q instead of
//     g^s on an elliptic curve. Provided by pulsar/reshare/commit.go.
//  2. Auxiliary secrets w, q (LSS Section 4 ECDSA nonce blinding) are
//     not needed — Pulsar's signing protocol has Gaussian blinding
//     built into Sign1/Sign2.
//  3. The activation cert is a Lumen / Ringtail threshold signature
//     under the unchanged GroupKey, not an ECDSA verification.
//
// Everything else (orchestration, generation tracking, rollback,
// snapshot persistence, dealer/coordinator role separation) reuses
// LSS unchanged.
func DynamicResharePulsar(
    oldEra *pulsar.KeyEra,
    newParticipants []party.ID,
    newThreshold int,
    pl *pool.Pool,
) (*pulsar.KeyEra, error)
```

### Migration plan: protocols/ringtail → protocols/pulsar (revised)

Don't back-port the corrected kernel under `protocols/ringtail/`. Keep them distinct:

| Package | Status |
|---|---|
| `protocols/ringtail/` | DEPRECATED. Upstream academic POC; broken DKG; trusted-dealer-per-epoch. `GenerateKeys` should return an error pointing callers at `protocols/pulsar`. |
| `protocols/pulsar/` | Production. Corrected kernel via `github.com/luxfi/pulsar`. |
| `protocols/lss/lss_pulsar.go` | NEW. Dynamic-resharing adapter — production resharing path. |
| `protocols/quasar/` | Update to consume `protocols/pulsar` + `lss/lss_pulsar.go` + `bls/` + `mldsa/`. |

### Commit sequence (review-friendly migration)

1. Rename `lumen → pulsar` (no behavior change). ✅ Done.
2. Add `threshold/protocols/pulsar` kernel wrapper. ✅ Done.
3. Lock LSS framework relationship in DESIGN.md. ✅ Done (this section).
4. Add `Generation` and `RollbackFrom` to `pulsar.EpochShareState`.
5. Add `lss_pulsar.go` adapter — `DynamicResharePulsar` analogous to `DynamicReshareFROST`.
6. Wire `RollbackManager` for Pulsar via the adapter.
7. Add `RefreshSameSet` round-based protocol (3-round shape from LSS).
8. Add `ReshareToNewSet` round-based protocol (same shape).
9. Add activation cert sign as a follow-on round after reshare round 3.
10. Quasar: switch from `protocols/ringtail` to `protocols/pulsar` + `lss/lss_pulsar`.
11. Quasar: add ML-DSA certificate-set lane.
12. Deprecate `protocols/ringtail` (`GenerateKeys` returns error).
13. Add grouped Pulsar certificates.

### Cited works

- **Seesahai 2025**: *"LSS MPC ECDSA: A Pragmatic Framework for Dynamic and Resilient Threshold Signatures"* — LSS framework. The orchestration this work plugs into.
- **HJKY97**: Herzberg-Jakobsson-Jarecki-Krawczyk-Yung, *"Proactive secret sharing or: How to cope with perpetual leakage"* (CRYPTO 1995/1997) — the Refresh primitive.
- **Desmedt-Jajodia 1997**: *"Redistributing secret shares to new access structures"* — the ReshareToNewSet primitive.
- **Wong-Wang-Wing 2002**: *"Verifiable secret redistribution for archive systems"* — the VSR composition.
- **NTT et al 2024**: *"Ringtail"* (eprint 2024/1113, IEEE S&P 2025) — the inherited 2-round Sign protocol.
- **BDLOP18**: Baum-Damgård-Lyubashevsky-Oechsner-Peikert, *"More Efficient Commitments from Structured Lattice Assumptions"* (SCN 2018) — informs the lattice Pedersen commits in `pulsar/reshare/commit.go` (and the dkg2 research path).

---

## Quasar integration: surgical Go changes

The Go surgery is in **one file** plus **one new package**.

### New package: `~/work/lux/pulsar/keyera/`

```go
package keyera

type KeyEra struct {
    EraID        PulsarKeyEraID
    GroupID      PulsarGroupID
    GroupKey     *threshold.GroupKey
    GenesisEpoch uint64
    State        *EpochShareState
}

// Bootstrap runs the one-time trusted-dealer ceremony at chain launch.
// Foundation-coordinated MPC; the entropySource MUST come from a verifiably
// public ceremony (e.g. commit-and-reveal from genesis validators). The
// dealer state MUST be erased before the ceremony closes.
func Bootstrap(t int, validators []ValidatorID, groupID PulsarGroupID, eraID PulsarKeyEraID, entropy io.Reader) (*KeyEra, error)

// Reshare evolves the era to a new committee while preserving GroupKey.
// Calls into pulsar/reshare under the hood; activation cert is run by the
// caller (consensus layer) before the new state is accepted.
func (era *KeyEra) Reshare(
    newValidators []ValidatorID,
    newThreshold int,
    randSource io.Reader,
) (*EpochShareState, error)

// Reanchor opens a NEW key era with a fresh GroupKey. Use only for
// security-event response. Requires governance.
func Reanchor(prev *KeyEra, t int, validators []ValidatorID, groupID PulsarGroupID, entropy io.Reader) (*KeyEra, error)
```

### Surgical edit: `~/work/lux/consensus/protocol/quasar/epoch.go`

Replace `RotateEpoch` body (the call to `ringtailThreshold.GenerateKeys(threshold, n, nil)`) with:

```go
func (em *EpochManager) ReshareEpoch(validators []string, force bool) (*EpochShareState, error) {
    // ... existing rate-limit + change-detection logic UNCHANGED ...

    if em.currentEra == nil {
        // Layer 1: chain genesis only
        era, err := keyera.Bootstrap(t, validators, em.groupID, em.nextEraID(), em.ceremonySource)
        if err != nil {
            return nil, fmt.Errorf("bootstrap: %w", err)
        }
        em.currentEra = era
        return era.State, nil
    }

    // Layer 2: every subsequent rotation is a share-rotation, not a key-rotation
    return em.currentEra.Reshare(validators, t, em.randSource)
}
```

The activation cert is run by the consensus layer caller (after the kernel returns) using the new state's shares to threshold-sign the activation message under the unchanged GroupKey.

### Renames for clarity

In Quasar consensus:

| Before (wrong under resharing) | After |
|---|---|
| `EpochKeys` | `EpochShareState` |
| `RotateEpochKeys` (function/method names) | `ReshareEpoch` |
| comment "rotate keys" | "rotate shares; group key persistent" |
| `currentKeys *EpochKeys` | `currentEra *keyera.KeyEra` |
| `QUASAR-QB-v1:%x` (bundle prefix) | `QUASAR-PULSAR-BUNDLE-v1:%x` |

Everything else in `epoch.go` (rate limit, change detection, validator set management) stays.

---

## Acceptance gate (must pass before merging into Quasar)

A Reshare implementation merges into `consensus/protocol/quasar/epoch.go` only after:

1. Old → new resharing works for `t_old != t_new`.
2. New shares reconstruct the same Ringtail master secret (verified via `Lagrange(new_shares) == s`).
3. Original `GroupKey` (== `bTilde`) is **byte-identical** after resharing.
4. New committee produces a valid Pulsar signature that verifies under the unchanged `GroupKey` — this is what the activation cert proves.
5. Old shares are unnecessary after activation (chain rejects signatures from old committee under the new epoch).
6. Resharing transcript is domain-separated by `(chain_id, era_id, group_id, old_epoch, new_epoch, old_set_hash, new_set_hash, thresholds, group_pk_hash)`.
7. Pairwise PRF/MAC material is regenerated for the new committee with proper domain separation.
8. Malformed share delivery produces attributable evidence (signed slashing data, with care taken not to leak threshold-reconstructing data publicly).
9. Activation cert verifies under unchanged GroupKey (proves new signing capability; does NOT alone prove correct VSR exchange).
10. Failure path is explicit: retry, disqualify, continue old epoch, or reanchor.

Each gate item maps to at least one KAT or ctest target.

---

## KAT requirements

Deterministic test vectors (Go oracle → JSON → C++ test, byte-equal):

1. Shamir share-and-recover over `R_q` (already in `primitives/shamir.go` upstream).
2. Refresh preserves master secret (same set, after refresh `Lagrange(new_shares) == s`).
3. ReshareToNewSet preserves master secret (different set, after `Lagrange_{newSet}(new_shares) == s`).
4. Invalid old share is detected during resharing.
5. Invalid resharing evaluation triggers complaint + disqualification.
6. Activation signature verifies under unchanged `GroupKey`.
7. Inherited Sign1/Sign2/Combine remain byte-equal vs upstream Ringtail.
8. Go and C++ serialization of `EpochShareState` are byte-identical.
9. Domain separation: changing any field in `TranscriptBinding` alters the resulting transcript hash.
10. Hash-output sanity: `H_u` outputs Gaussian `u`-vector; `H_c` outputs ternary challenge `c`. Don't accidentally invert.

---

## C++/GPU port roadmap (mechanical, after Go locks)

Once Go ships and KATs are pinned:

```
~/work/luxcpp/crypto/pulsar/
├── reshare/              ← byte-equal port of pulsar/reshare/
│   ├── refresh.{hpp,cpp}
│   ├── reshare_to_new_set.{hpp,cpp}
│   └── transcript.{hpp,cpp}
├── keyera/               ← thin wrapper above reshare
│   └── keyera.{hpp,cpp}
└── c-abi/
    └── c_pulsar_lifecycle.cpp   ← pulsar_bootstrap, pulsar_reshare, pulsar_activate
```

C-ABI surface (mirror existing `ringtail_*` pattern):

```c
int pulsar_bootstrap(
    uint32_t t, uint32_t n,
    const uint8_t* entropy, size_t entropy_len,
    pulsar_keyera** out_era,
    uint8_t* out_share_state, size_t* out_share_state_len);

int pulsar_reshare(
    pulsar_keyera* era,
    const uint8_t* new_set, size_t new_set_len,        // serialized validator set
    uint32_t new_threshold,
    const uint8_t* pair_secrets, size_t pair_secrets_len,  // pre-computed KEX outputs
    uint8_t* out_share_state, size_t* out_share_state_len,
    uint8_t* out_activation_sig, size_t* out_activation_sig_len);

int pulsar_verify_activation(
    const uint8_t* group_key, size_t group_key_len,
    const uint8_t* activation_msg, size_t activation_msg_len,
    const uint8_t* activation_sig, size_t activation_sig_len);
```

GPU acceleration: only the **inherited Sign protocol** has GPU-relevant primitives (NTT/Mont). Reshare itself is small-N polynomial arithmetic + KDF; no GPU win. The existing Metal/CUDA/WGSL kernels in `~/work/luxcpp/crypto/ringtail/gpu/` cover Sign; they're inherited unchanged.

---

## What this isn't

- **Not a fresh DKG every epoch.** Genesis uses trusted-dealer Gen, contained to a one-time public ceremony. After that, no party ever sees `s` again.
- **Not "same `s` forever."** Resharing preserves `s` across an arbitrary number of epochs **within a key era**. Reanchor (rare governance event) starts a new key era with fresh `(s', A', e', bTilde')`.
- **Not Pedersen DKG over R_q.** That research path stays as a future option (Pulsar `dkg2/` package is reference-only). Resharing avoids it entirely.
- **Not Bitcoin's launch.** Bitcoin had no toxic-waste secret. Pulsar's Layer 1 has a one-time trusted-setup MPC ceremony — comparable to Zcash's ceremony in trust shape, NOT to Bitcoin's launch.
- **Not 500 LoC + 1 week.** That's the math kernel only. Production permissionless VSR with complaint phase, slashing evidence, activation cert, erasure obligations, KAT coverage, and C++ port is **8-13 weeks for MVP**, plus another **6-12 weeks** for fully attributable robust VSR.

---

## Status

| Component | State |
|---|---|
| Pulsar fork at `~/work/lux/pulsar` | shipping |
| Inherited Sign1/Sign2/Combine | byte-equal vs upstream |
| `pulsar/reshare/` (kernel + VSR scaffolding) | shipping (45 tests passing) |
| `pulsar/keyera/` | shipping (proper t-of-n via general Shamir) |
| Activation cert format `QUASAR-PULSAR-ACTIVATE-v1` | shipping |
| Quasar `epoch.go` LSS-Pulsar wiring | shipping (consensus 119c2166 lineage) |
| LSS-Pulsar adapter at `threshold/protocols/lss/lss_pulsar.go` | shipping (10/10 acceptance tests) |
| Warp 2.0 envelope at `warp/pulsar` | shipping |
| MVP VSR (complaint mempool, fallback path, transport ML-KEM hybrid) | partial; complaint mempool open |
| Robust VSR (public slashing evidence) | open research workstream |
| C++ port | Sign math wired (LP-137-ACTUAL-STATE 2026-04-28); KAT in flight |
| GPU coverage | inherited from Sign port; reshare itself is small-N polynomial arithmetic, no GPU benefit |
