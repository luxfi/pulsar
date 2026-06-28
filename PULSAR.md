# PULSAR — Committee-Threshold ML-DSA Certificate Layer

> **Status.** Architecture specification. This document defines the *certificate
> layer* of Pulsar: how committee-threshold ML-DSA is organized into epochs,
> committees, DKG transcripts, signing tickets, and on-chain-verifiable
> certificates so that it scales to a permissionless validator set of
> N > 1000. It is the consensus-integration companion to the algorithm-level
> NIST-MPTC submission spec (`spec/pulsar.tex`, `spec/parameters.tex`,
> `spec/system-model.tex`) and the proofs under `~/work/lux/proofs/pulsar/`.
>
> **SPEC ONLY.** No code is changed by this document. Sections labelled
> *implemented today* cite the real reference implementation under
> `ref/go/pkg/pulsar/`; everything else is a *Pulsar target* to build.

---

## 0. Claim discipline (read first)

This layer makes **two distinct claims that must never be conflated**. Most
flawed "threshold post-quantum" marketing collapses them; Pulsar keeps them
apart on purpose.

- **Claim (A) — FIPS-204 verification *compatibility*.** The verifier boundary
  is **standard, unmodified** FIPS-204 ML-DSA verification:

  ```
  Verify_MLDSA(GroupPK, digest, sig) ∈ {accept, reject}
  ```

  The threshold-produced `(c̃, z, h)` is byte-for-byte a FIPS-204 signature; a
  stock verifier (`cloudflare/circl` `mldsa65.Verify` / `mldsa87.Verify`,
  BoringSSL/AWS-LC FIPS ML-DSA, OpenSSL 3.x PQ provider) accepts it with **no
  Pulsar code in the verify path**. This is a *compatibility* claim about the
  output bytes, and it is **proven today** for the no-reconstruct signer
  (§4, `ref/go/pkg/pulsar/bcc_sign_test.go:86`).

- **Claim (B) — DKG/threshold *construction* soundness.** The distributed key
  generation and the threshold signing protocol are a **Lux-authored
  construction** (TALUS / BCC / CEF / CSCP and the committee orchestration
  specified here). Its security is argued by reduction to ML-DSA EUF-CMA under
  Module-LWE / Module-SIS, *plus* the protocol-level privacy/abort properties
  proven in `~/work/lux/proofs/pulsar/`. This is **our** theorem, not NIST's.

**What we never say.** There is no such thing as "FIPS-certified threshold
ML-DSA" or "NIST-certified threshold ML-DSA." FIPS 204 standardizes
*single-party* ML-DSA KeyGen/Sign/Verify. Pulsar's contribution is (A) that
our threshold *output* is accepted by the certified *verifier*, and (B) a
construction we prove ourselves. Conformance language is always one of:
"verifies under unmodified FIPS-204," or "Lux-authored threshold construction,
reduction in `proofs/pulsar/`."

---

## 1. Why a certificate layer, and why not Shamir/FROST end-to-end

ML-DSA is not Schnorr. Four features break Schnorr-style threshold composition:

1. **Small secrets.** `s1, s2` are sampled uniformly from
   `S_η = {p ∈ R_q : ‖p‖∞ ≤ η}` (η = 2 or 4). The *entire* parameter set is
   calibrated to this bound.
2. **Rejection sampling.** Signing loops until `‖z‖∞ < γ1 − β` and
   `‖r0‖∞ < γ2 − β`; the accepted distribution is not a simple linear image of
   the inputs.
3. **Decompose / rounding.** `w1 = HighBits(A·y)` and `r0 = LowBits(w − c·s2)`
   are non-linear; there is no homomorphic commitment to `w1` over additive
   nonce shares — this is precisely why naive FROST-style additive-nonce
   threshold ML-DSA is impossible.
4. **Hints.** The signature carries `h = MakeHint(...)`; recovering it from
   shares without leaking the key residual `w' − w = c·t0 − c·s2` is the
   delicate part.

Consequences for the *key* layer:

- **Naive Lagrange/additive DKG blows the norm.** A dealerless joint secret
  formed as a sum / Lagrange combination of N ≥ 2 independent `S_η`
  contributions has `‖s2_joint‖∞ ≤ N·η`, hence `‖c·s2_joint‖∞ ≤ N·β`. This
  violates both the BCC boundary-clearance hypothesis (`‖c·s2‖∞ ≤ β`) and
  ML-DSA's `S_η`-calibrated EUF-CMA. This **naive-additive obstruction is
  computed, not asserted**, in
  `ref/go/pkg/pulsar/naive_additive_seta_obstruction.go:196`
  (`assessDealerlessFIPS`) and is the reason the dealerless entry point fails
  closed (`ErrDealerlessByteFIPSUnreachable`,
  `naive_additive_seta_obstruction.go:152`). **It is the naive *lift* only —
  it does *not* prove a general impossibility** (the file's own header lists
  open research directions, e.g. sharings whose reconstruction is in `S_η` by
  construction — exactly Mithril's escape; see §11).

So Pulsar does **not** push one global Shamir/FROST sharing across all N
validators. Instead it **scales by committees** and treats the *certificate*
(an epoch/committee-bound, on-chain-verifiable ML-DSA signature) as the unit of
composition.

---

## 2. What exists today vs. the Pulsar target

Grounded in `ref/go/pkg/pulsar/` (origin/main).

| Concern | Implemented today (file:line) | Pulsar target |
|---|---|---|
| (A) Threshold output verifies under **unmodified FIPS-204** | **DONE** — `bcc_sign_test.go:86` `TestBCCSignRoundTripVerifiesCIRCL` checks a no-leak BCC/CEF signature byte-for-byte under independent `circl` `mldsa65/87.Verify` (+ tamper/wrong-msg/wrong-ctx negatives) | **Unchanged** — the verifier boundary stays standard. Certificates carry exactly `(c̃, z, h)`. |
| No-reconstruct online signing | **DONE** — `distributed_bcc.go:28` partial `z_i = λ_i·y_i + c·λ_i·s1_i`; aggregates to `z = ȳ + c·s1` **without ever forming `s1`** (let alone the seed); hint from public `w' = A·z − c·t1·2^d` | Productionize as a *networked* committee protocol; close malicious-secure residual. |
| Keygen | **TRUSTED-DEALER** — `distributed_bcc.go:148` `DealAlgShares` expands the seed once, Shamir-shares `s1` over GF(q), wipes secrets | Add **dealerless committee DKG** (Pulsar-MPC, §11) + TEE-assisted (Pulsar-TEE). |
| Dealerless byte-FIPS-204 key DKG (naive additive) | **OBSTRUCTION COMPUTED, fail-closed** — `naive_additive_seta_obstruction.go:196` `assessDealerlessFIPS` (`JointS2Linf = N·η`, `JointCS2Linf = N·β`); `:152` `ErrDealerlessByteFIPSUnreachable` | Short replicated sharing (Mithril) sidesteps the *additive* `N·η` blowup; large-committee dealerless is research-open. |
| Offline preprocessing / ticket factory | **BUILT (semi-honest)** — TALUS `talus.go`, CEF `talus_cef.go`, CSCP secure-comparison `talus_cscp.go` (W-LEAK closed semi-honest, simulation-proven) | Productionize; malicious-secure layer (BLOCKERS Residual A). |
| TEE-assisted low-latency mode | Profile present — `talus.go:62` `TalusTEE` (wired via optional `luxfi/tee`) | Wire as the **Pulsar-TEE** certificate mode. |
| Committee/epoch object model + on-chain registry | **NOT BUILT** — consensus currently wires a *placeholder* Pulsar verifier (`LLM.md`: "finality verify path replaces the placeholder Pulsar verifier") | This document's object model (§7–§9) + on-chain verifier (§13, Phase 5). |
| Package independence | **COUPLED** — `~/work/lux/threshold/pkg/thresholdd/` builds `corona.go` + `magnetar.go` + `pulsar.go` in **one** Go package | Pulsar in its **own** package (§16). |
| Permissionless dealerless safety | **Carried by Corona** (natively dealerless Ring-LWE) in the Quasar AND-mode dual-PQ cert | **Unchanged.** Pulsar is the FIPS-204-standard leg / defence-in-depth. |

The load-bearing fact: **(A) is done and proven; the keygen half of (B) is the
work.** Online no-reconstruct signing already produces a standard FIPS-204
signature; the open problem is *dealerless* key setup at committee scale.

---

## 3. Parameter sets

Pulsar is defined for the BCC-proven scope only: **ML-DSA-65** and
**ML-DSA-87**. ML-DSA-44 has **no** Pulsar suite (see below).

Common FIPS-204 modulus `q = 8380417 = 2^23 − 2^13 + 1`, ring
`R_q = Z_q[X]/(X^256 + 1)`, Power2Round `d = 13` (so `2^(d−1) = 4096`).

| Symbol | ML-DSA-65 | ML-DSA-87 | Meaning |
|---|---|---|---|
| Category | NIST 3 (production target) | NIST 5 | |
| `(K, L)` | `(6, 5)` | `(8, 7)` | matrix `A ∈ R_q^{K×L}` |
| `η` | `4` | `2` | secret bound, `s1,s2 ∈ S_η` |
| `τ` | `49` | `60` | challenge weight (# of ±1 in `c`) |
| `β = τ·η` | `196` | `120` | key-shift bound `‖c·s2‖∞ ≤ β` |
| `γ1` | `2^19` | `2^19` | nonce range |
| `γ2` | `261888 = (q−1)/32` | `261888` | HighBits bucket half-width |
| `ω` | `55` | `75` | hint weight bound |
| `\|c̃\|` | `48 B` (λ=192) | `64 B` (λ=256) | challenge-hash length |
| suite id | `pulsar-talus-mldsa-65` | `pulsar-talus-mldsa-87` | `talus.go` `SuiteTalusMLDSA{65,87}` |

**BCC clearance margin** (`boundary.go`): a nonce is accepted only if its
commitment `w = A·y` clears a fixed boundary
`boundaryThreshold = γ2 − 2β − slack`, `slack = 16`. This guarantees
`HighBits(w − c·s2) = HighBits(w)` so the hint is **public-computable** and the
key residual never appears in the transcript.

**Why ML-DSA-44 is excluded.** BCC requires `‖c·t0‖∞ ≤ τ·2^(d−1) < γ2`.
For ML-DSA-44, `τ·2^(d−1) = 39·4096 = 159744 > γ2 = 95232` — the hint cannot be
kept public-computable. (`bccParams` returns `ok=false`; `TalusSuiteFor`
refuses ML-DSA-44 with `ErrTalusSuiteUnsupported`.)

---

## 4. Online signing primitive (the part that exists)

The certificate's signature is produced by the **no-reconstruct BCC/CEF**
signer. This is the kernel; the committee layer (§5–§13) wraps custody and
on-chain binding around it but **does not change the bytes a verifier checks**.

Per-party share custody (`distributed_bcc.go:104`, `AlgShare`): each member
holds **exactly one** poly-vector Shamir share of the *expanded* signing
component `s1` (length L) over GF(q) at its evaluation point — never `s2`,
never `t0`, never the seed. Because `s1` enters the response **linearly**:

```
party i:    z_i = λ_i · y_i + c · λ_i · s1_i        (over R_q^L)
aggregate:  z   = Σ_i z_i = (Σ_i λ_i·y_i) + c·(Σ_i λ_i·s1_i) = ȳ + c·s1
```

so the designated aggregator forms `z` **without ever materializing `s1`**.
The hint is recovered from public `w' = A·z − c·t1·2^d` via `FindHint`, so
`c·s2`, `c·t0`, `r0`, and full `w` never enter any transcript
(`bcc_sign_test.go:217` `assertBCCTranscriptNoLeak` enforces this with a
debug oracle).

**One online round** (TALUS, `arXiv:2603.22109`): given an offline ticket
(§10), `c = H(μ ‖ w1)`, each signer broadcasts its `z_i`, the coordinator sums,
runs `FindHint`, and emits `(c̃, z, h)`. A **mandatory release-gate**
(`talus_sign.go` `TalusReleaseGate`) runs stock FIPS-204 verify before any
signature leaves the process — a malicious deviation is bounded to **liveness**
(abort/retry), never forgery or leak.

**Honest caveat (carried from `talus.go:35`).** The threshold *transcript* may
be distinguishable in distribution from a single-party ML-DSA transcript (extra
observables: masked CEF broadcasts, per-party `z_i`). The final signature's
byte format and verify path are identical and standard; the distinguishability
is at the protocol layer, addressed by the privacy proof in (B), not by (A).

---

## 5. System, adversary, and synchrony model

**Parties.**
- `N` permissionless validators (target `N > 1000`), each with stake and a
  registered long-term identity key. The validator set at an epoch is committed
  by `validator_set_root` (§7).
- Per epoch, `m` **committees** (target `m ∈ [8, 32]`) of size `k` (§6) are
  sampled by stake/VRF weight from the validator set.
- A **coordinator** per signing session is a committee member (e.g. lowest
  index); it has **no special trust** — it only routes and aggregates public
  data, and the release gate makes coordinator misbehavior detectable.

**Adversary.**
- **Byzantine, up to `t−1` corruptions per committee** for unforgeability and
  `(t−1)`-privacy (the standard threshold bound). With `t ≈ 2k/3` the committee
  tolerates `f < k/3` Byzantine members.
- **Static corruption** is the submission posture; adaptive corruption ports
  through the chain-corruption simulator in a later audit cycle (mirrors the
  NIST-MPTC submission's stated posture).
- **Network adversary** may reorder/delay; cannot break Module-LWE/Module-SIS
  (the PQ assumption) or SHA3/SHAKE (modeled as RO for domain-separated input).
- The TALUS-MPC profile is **malicious-secure with identifiable abort under an
  honest majority** at the substrate level (`talus_mpc.go`, BGW, STOC 1988);
  the full malicious-secure CSCP layer is an open residual (BLOCKERS Residual A).

**Synchrony.**
- **DKG and preprocessing**: partially synchronous with a known upper bound for
  complaint/blame rounds (identifiable abort needs bounded message delay).
- **Online signing**: one round under partial synchrony; liveness is provided
  by sampling **multiple committees** per epoch (§12) so one stalled committee
  does not stall finality.
- **On-chain verification**: deterministic, no synchrony assumption — it is a
  pure function of committed registry state and the certificate (§13).

**Trust anchors.** The chain's epoch randomness beacon (committee sampling), the
on-chain validator registry (membership + stake), and — for the Pulsar leg's
*genesis only* in TD/TEE modes — the dealer/TEE. Permissionless *safety* is
anchored by the **Corona** leg in the AND-mode dual-PQ Quasar cert; Pulsar is
the FIPS-204-standard leg.

---

## 6. Committee sizing

Committees are the BFT and liveness unit. Sizing trades signature cost (linear
in `k`) against the corruption budget.

| Use class | `k` (committee size) | threshold `t` | tolerated Byz `f` | rationale |
|---|---|---|---|---|
| Standard finality | `64` | `⌈2k/3⌉ = 43` | `21` (< k/3) | cheapest BFT-safe committee |
| Elevated | `96` | `⌈2k/3⌉ = 64` | `31` | higher assurance |
| Bridge / cross-chain / upgrade / emergency | `128` | `⌈3k/4⌉ = 96` | `31` (< k/4) | super-majority for irreversible/high-value actions |

Notes:
- `t` is the *reconstruction/aggregation* threshold of the underlying sharing.
  The online signer needs `t` valid `z_i` partials to assemble `z`.
- High-value actions additionally require **multiple independent committee
  certificates** (§12), so the effective corruption budget is the product of
  per-committee budgets across the required committees.
- These are policy defaults bound to `policy_id` (§7); they are not protocol
  constants and may be tuned per chain without changing the crypto.

**Dealerless feasibility vs. `k`.** The *signing* primitive (§4) works at all
these `k` today (trusted-dealer / TEE genesis). The *dealerless* committee DKG
(Pulsar-MPC) is currently practical only for **small** committees (Mithril's
short replicated sharing is combinatorial, practical `k ≲ 8`; §11). At BFT
committee sizes (`k = 64..128`) dealerless Pulsar is **research-open** — this is
exactly why network-level permissionless safety is carried by Corona, and
Pulsar committees at scale use Pulsar-TD/Pulsar-TEE genesis until the
arbitrary-`T` dealerless branch lands. This gap is stated, not hidden.

---

## 7. Object model

All objects are content-addressed by a SHAKE256 hash over their canonical
encoding with a domain tag (§14). On-chain we store **commitments**, not raw
material.

### PulsarEpoch
```
epoch_id            uint64        monotonic epoch counter
validator_set_root  [32]byte      Merkle root over (validator_id, stake, ltk) leaves
randomness_seed     [32]byte      beacon output that seeds committee sampling
policy_id           uint32        selects committee sizes / thresholds / suites (§6)
activation_height   uint64        first block at which this epoch's committees may sign
expiry_height       uint64        last block; certs under this epoch invalid after it
```

### PulsarCommittee
```
epoch_id            uint64
committee_id        uint32        index within the epoch (0..m-1)
members             []ValidatorID stake/VRF-sampled, size k
stake_weights       []uint64      aligned with members (audit / slashing)
threshold_t         uint16        signing/aggregation threshold (§6)
scheme              uint8         ML-DSA-65 | ML-DSA-87
keygen_mode         uint8         Pulsar-TD | Pulsar-MPC | Pulsar-TEE (§11)
group_public_key    []byte        FIPS-204 pk bytes (the GroupPK a verifier uses)
dkg_transcript_root [32]byte      commitment to PulsarDKGTranscript (§8)
status              uint8         Proposed | Active | Expired | Slashed
```

### PulsarDKGTranscript (§8)
### PulsarSigningTicket (§10)

### PulsarCertificate
```
epoch_id              uint64
committee_id          uint32
policy_id             uint32
message_kind          uint16      finality | bridge | upgrade | warp | emergency
message_digest        [32]byte    domain-separated digest the committee signed (§14)
signature             []byte      STANDARD FIPS-204 (c̃, z, h) bytes
group_public_key_ref  [32]byte    hash of the registered GroupPK (registry lookup key)
signing_transcript_hash [32]byte  commitment to the signing session (ticket id + members)
```

The certificate is the only object a relying chain needs at verify time, plus
the on-chain committee registry it references.

---

## 8. DKG transcript format

`PulsarDKGTranscript` is the auditable record that a committee's `GroupPK` was
generated correctly. It is mode-specific (§11) but always carries enough to
(a) verify the public key was honestly derived and (b) attribute blame.

```
header
  epoch_id, committee_id, scheme, keygen_mode, k, threshold_t
commitments
  per-member commitment to that member's contribution
  (mode TD: a single dealer commitment; mode MPC: one per contributor)
replicated_share_commitments
  Mithril short-share commitments (Pulsar-MPC): commitments to the
  short replicated shares, NOT the additive sums that the
  naive_additive_seta_obstruction.go bound rules out (§11)
share_proofs
  per-member zero-knowledge proof that the shared secret material is
  short (‖s1‖∞,‖s2‖∞ ≤ η; ‖t0‖∞ ≤ 2^(d−1)); this is the well-formedness
  proof (cf. dkg_wellformed_proof.go) the committee verifies before
  accepting GroupPK
complaints
  signed accusations against members whose contribution/opening failed
blame
  resolution of complaints → set of faulty members (for slashing)
finalization_cert
  the threshold attestation that ≥ t members accepted the same GroupPK
transcript_hash
  SHAKE256 over the canonical encoding of all of the above, domain tag
  pulsar:v1:dkg
```

**On-chain we store only `dkg_transcript_root` (= `transcript_hash`).** The
full transcript lives in DA / p2p; the chain accepts `GroupPK` iff the
finalization rules pass (§12) and the root is committed. A verifier at *signing*
time never re-runs DKG math — it trusts the registered, finalized `GroupPK`.

---

## 9. Share format

Two layers — *long-term* (key) shares and *per-session* (nonce) shares.

**Key share** (held for the committee's lifetime). One per member; **custody
invariant: exactly one share per process** (`distributed_bcc.go:104`).
```
node_id        ValidatorID
eval_point     uint32       distinct GF(q) Shamir x-coordinate in [1, q)
s1_share       polyVec[L]   Shamir share of s1 over GF(q) (s1 ONLY — never s2/t0/seed)
scheme         uint8        ML-DSA-65 | 87
```
Sharing regime (matches the existing two-field design):
- **GF(257)** small-committee wire encoding (k ≤ 256) — 64-byte share.
- **GF(q)** large-committee wire encoding — 128-byte share.

In Pulsar-MPC the key shares are **short replicated shares** (Mithril), whose
reconstruction lies in `S_η` by construction; in Pulsar-TD/Pulsar-TEE they are
GF(q) Shamir shares of a dealer/TEE-expanded `s1`. The *online signing*
arithmetic (§4) is identical across modes.

**Nonce share** (per signing session, one-time). Established by the offline
ticket factory (§10): a dealerless one-time joint nonce `ȳ` is secret-shared so
that **no process forms `ȳ` or the commitment `w`** (TALUS-MPC), or supplied by
the TEE (TALUS-TEE). Only `w1 = HighBits(A·ȳ)` and the BCC clear-bit are public.

---

## 10. Ticket format (offline preprocessing)

TALUS separates an **offline ticket factory** (no message yet) from the **online
signing round** (one broadcast). A ticket bundles one boundary-cleared nonce so
the online path is a single round.

```
PulsarSigningTicket
  committee_id            uint32
  ticket_id               [32]byte    unique; binds the offline session
  offline_nonce_commitment [32]byte   commitment to the shared nonce (NOT w itself)
  w1                       []byte      HighBits(A·ȳ) — public challenge input
  bcc_metadata            ...         boundary-clearance witness: clear-bit, margin
  scheme                  uint8
  expiry                  uint64      tickets are perishable (epoch-bound)
  consumed                bool        one-shot: a ticket signs at most one digest
```

Properties:
- **Boundary clearance is checked offline.** Only ~31.7% of candidate nonces
  clear the BCC boundary (`talus.go:20`); the factory runs continuously so a
  ready ticket exists when a digest arrives.
- **One ticket, one signature.** Reuse is a nonce-reuse fault; `consumed` is
  enforced and a reused `ticket_id` is rejected (§13 replay protection).
- **Tickets carry no secret.** They carry `w1` (public) and the clear-bit; the
  secret nonce shares stay with members. A leaked ticket cannot forge.

---

## 11. The three modes (honestly labelled)

All three emit **identical, standard FIPS-204 signatures** (Claim A). They
differ only in **how the key and nonce custody is established** (Claim B).

### Pulsar-TD — trusted dealer
- **Use:** bootstrap, test vectors, HSM-backed genesis, migration.
- **Today:** `distributed_bcc.go:148` `DealAlgShares` — dealer expands the seed
  once, Shamir-shares `s1`, wipes. Signing is **no-reconstruct** (no party ever
  reconstructs `s1`); **keygen is not dealerless**.
- **Honesty:** this is **not** a DKG. Never described as dealerless. The dealer
  is a single point of trust *at genesis only*.

### Pulsar-MPC — dealerless committee DKG (the main permissionless mode)
- **Use:** permissionless committees; the target.
- **Construction:** **Mithril** short replicated secret sharing
  (`ia.cr/2026/013`, USENIX Security 2026) + **local per-party rejection**, with
  **no global-abort MPC**. Mithril supports DKG *and* a-posteriori key sharing
  and is standard-verifier-compatible.
- **Why it sidesteps the obstruction:** the
  `naive_additive_seta_obstruction.go:196` bound is computed *for the additive /
  Lagrange-sum lift* — a joint secret `= Σ` of N `S_η` contributions, giving
  `‖s2_joint‖∞ ≤ N·η` and `‖c·s2_joint‖∞ ≤ N·β > β`. Short replicated sharing
  **does not form such a sum**: the reconstructed secret stays in `S_η` by
  construction, and per-party rejection keeps the *signature* short. The
  obstruction file fails closed for the naive path precisely so that Mithril is
  the named, deliberate escape — not a silently weakened bound.
- **Scope honesty:** Mithril's replicated sharing is combinatorial, practical
  for **small committees (`k ≲ 8`)**. At BFT sizes (`k = 64..128`) this is
  **research-open**; the candidate is the **masked-Lagrange arbitrary-`T`**
  branch. Until it lands, large permissionless committees use TD/TEE genesis for
  the Pulsar leg, and **Corona** carries dealerless permissionless safety in the
  AND-mode dual-PQ cert. *Do not claim large-committee dealerless Pulsar as
  shipped.*

### Pulsar-TEE — TEE-assisted low latency
- **Use:** low-latency lanes where a TEE custody boundary is acceptable.
- **Today:** `talus.go:62` `TalusTEE` profile — a TEE/coordinator holds the
  joint nonce `ȳ`, computes `w1` and the BCC filter directly, deals `y`-shares.
  No honest-majority restriction (`N ≥ T`). Wired via the **optional**
  `luxfi/tee` extension, never baked into the core.
- **Honesty:** **not** the default trustless claim. The TEE is a trust anchor;
  a compromised TEE degrades to the TD trust model, not to forgery (the release
  gate still runs stock verify).

---

## 12. DKG lifecycle and multi-committee scaling

**Per-epoch lifecycle (permissionless):**

1. **Epoch start** → snapshot the validator set; commit `validator_set_root`.
2. **Beacon** → `randomness_seed` selects `m` committees by stake/VRF weight.
3. **Committee DKG** (off-chain / p2p, mode per §11) → each committee runs
   dealerless DKG (Pulsar-MPC) or dealer/TEE genesis (Pulsar-TD/TEE),
   producing a `GroupPK` and a `PulsarDKGTranscript`.
4. **Commit** → `(GroupPK, dkg_transcript_root, complaints, blame)` posted
   on-chain. The chain **accepts `GroupPK` iff** the finalization rules pass:
   `≥ t` members signed the same `GroupPK`, well-formedness proofs verify, and
   unresolved complaints do not exceed the fault budget. Faulty members → blame
   set → slashing input.
5. **Preprocessing** → committees continuously run the offline ticket factory
   (§10), maintaining a pool of boundary-cleared tickets.
6. **Per certificate:** coordinator proposes a domain-separated `message_digest`
   → members consume **one** ticket and broadcast their `z_i` → coordinator
   assembles a **standard** ML-DSA signature → release gate verifies → emit
   `PulsarCertificate`.
7. **Verify** (any relying party / chain) → §13.
8. **Rotation** → at `expiry_height` the committee's `GroupPK` expires.

**Churn via key expiry, not key mutation.** Validators join/leave between
epochs; a *live* committee key is **never** mutated per join/leave (that path
invites reshare-races and key-confusion). Membership changes take effect at the
**next** epoch's fresh DKG. Proactive resharing (beacon-randomized quorum) is a
separate, epoch-boundary operation.

**Never all-N-sign.** A certificate is signed by **one** committee of `k`
members, not by all `N` validators. Cost is `O(k)`, independent of `N`.

**Multiple committees for liveness and high value.**
- *Liveness:* sampling `m ∈ [8, 32]` committees per epoch means a stalled or
  censored committee does not stall finality — another committee's certificate
  suffices.
- *High value:* bridge / upgrade / warp / emergency actions require
  **multiple independent committee certificates** (e.g. 2-of-`m` or a
  policy-set quorum of committees), multiplying the corruption budget. The
  policy is bound by `policy_id` and `message_kind`.

---

## 13. On-chain verification

Verification is **cheap and stateless w.r.t. DKG** — no threshold or DKG math
runs per signature. Given a `PulsarCertificate` and the on-chain committee
registry, check, in order, fail-closed:

1. **Committee active.** `(epoch_id, committee_id)` resolves to a `Active`
   committee whose `[activation_height, expiry_height]` brackets the current
   height, and whose `policy_id` admits `message_kind`.
2. **GroupPK matches registry.** `group_public_key_ref == hash(registry
   GroupPK)`; load the registered FIPS-204 `GroupPK`.
3. **Digest domain-separated.** Recompute `message_digest` from the action with
   the correct domain tag (§14) and confirm equality — binds the signature to
   `epoch / committee / policy / chain / message_kind` so a signature for one
   context cannot be replayed in another.
4. **Standard verify.** `MLDSA.Verify(GroupPK, message_digest, signature)` using
   an **unmodified** FIPS-204 verifier (Claim A). This is the only crypto op.
5. **Not replayed.** `(epoch_id, committee_id, message_digest)` (and, for
   ticket-bound flows, `ticket_id`) has not been accepted before.

For high-value `message_kind`, repeat 1–5 for each required independent
committee certificate (§12) and require the full policy quorum.

This replaces the current **placeholder Pulsar verifier** in
`luxfi/consensus/protocol/quasar` (Phase 5).

---

## 14. Domain separation tags

All hashing/digesting uses SHAKE256 with a version-pinned tag. **One tag per
purpose; never reuse.**

```
pulsar:v1:dkg        DKG transcript hashing / finalization
pulsar:v1:share      share commitment / well-formedness binding
pulsar:v1:ticket     offline ticket commitment / id
pulsar:v1:sign       per-session signing transcript + message_digest base
pulsar:v1:bridge     message_digest domain for bridge/cross-chain certs
pulsar:v1:finality   message_digest domain for finality certs
pulsar:v1:upgrade    message_digest domain for upgrade/governance certs
```

`message_digest = SHAKE256(pulsar:v1:<kind> ‖ epoch_id ‖ committee_id ‖
policy_id ‖ chain_id ‖ canonical(action))`. The FIPS-204 signature is computed
over this digest (with the FIPS-204 context string set to the suite id), so the
verifier's domain binding (§13 step 3) and the signer's are lock-step.

---

## 15. Abort, blame, and slashing

- **DKG abort.** A member that fails to open a commitment, fails a
  well-formedness proof, or is the target of a sustained complaint is placed in
  the **blame set** (`PulsarDKGTranscript.blame`); the committee either
  re-runs without it (if `k − |blame| ≥ t`) or the epoch resamples. Blame is
  on-chain → slashing input.
- **Signing abort (liveness, not safety).** A malicious `z_i` or a coordinator
  that submits a bad aggregate is caught by the **mandatory release-gate stock
  FIPS-204 verify** (`talus_sign.go`): the signature simply fails to verify and
  the session aborts/retries with another ticket. A deviating party is bounded
  to **liveness** harm — it can never produce a forgery or leak the key. Under
  the honest-majority MPC profile, abort is **identifiable** (`talus_mpc.go`,
  BGW), feeding blame.
- **Nonce-reuse / ticket-reuse.** Enforced one-shot (`consumed`, §10) and by
  the on-chain replay check (§13 step 5).

---

## 16. Build note — packaging

Today the threshold daemon couples all three schemes in **one** Go package:
`~/work/lux/threshold/pkg/thresholdd/{corona.go, magnetar.go, pulsar.go}`. A
change to one scheme's dependencies recompiles the others, and the package can
only build if *every* scheme's deps resolve.

**Pulsar must live in its own package** (its own module path under the pulsar
repo, consumed by `thresholdd` as an adapter), so that Corona and Pulsar build
and version **independently** — consistent with the dual-PQ design where the two
legs are deliberately decoupled (a Module-LWE issue in one must not block the
other). This also keeps the FIPS-204 verifier dependency (`luxfi/crypto/pq/mldsa`)
off Corona's build graph and vice-versa.

---

## 17. Implementation phases

| Phase | Deliverable | State |
|---|---|---|
| **0** | **Claim cleanup** — separate (A) FIPS-204 *verification compatibility* from (B) the Lux-authored *DKG/threshold construction*; replace any "FIPS/NIST-certified threshold" language; make the dealerless obstruction **computed, not faked**. | **DONE** — grounded in `naive_additive_seta_obstruction.go` (fail-closed, computed), README/LLM claim-discipline sections, and `bcc_sign_test.go:86` proving (A) for the no-reconstruct signer. |
| **1** | **Package split** — extract Pulsar into its own package so Corona/Pulsar build independently (§16). | To build. |
| **2** | **Object model + registry types** — `PulsarEpoch / Committee / DKGTranscript / SigningTicket / Certificate`, canonical encodings, domain tags (§7–§10, §14). | To build. |
| **3** | **Committee DKG modes** — formalize Pulsar-TD (today `DealAlgShares`), wire Pulsar-TEE (`luxfi/tee`), and implement Pulsar-MPC dealerless committee DKG via Mithril short shares for small committees (§11). | TD done; TEE wired; MPC small-`k` to build; large-`k` research-open. |
| **4** | **Offline ticket factory + networked online signing** — productionize the TALUS preprocessing + one-round signer at committee scale; close the malicious-secure CSCP residual (BLOCKERS Residual A). | Semi-honest built; productionization + malicious layer to build. |
| **5** | **On-chain verifier** — the cheap 5-check verify (§13), replacing the placeholder Pulsar verifier in `luxfi/consensus/protocol/quasar`; multi-committee policy enforcement (§12). | To build. |

---

## 18. Security summary

- **(A) Verification compatibility** — *proven today* for the no-reconstruct
  signer (`bcc_sign_test.go:86`, independent `circl` verifiers + tamper/wrong-
  message/wrong-context negatives). Certificates carry exactly `(c̃, z, h)`.
- **(B) Construction** — Lux-authored. Online signing reduces to ML-DSA
  EUF-CMA under Module-LWE / Module-SIS (the output is a standard signature;
  BCC/CEF change only *how* `(c̃, z, h)` is produced). Threshold privacy /
  identifiable abort are proven in `~/work/lux/proofs/pulsar/`
  (`unforgeability.tex`, `dkg-soundness.tex`, `reshare-preservation.tex`,
  `output-interchangeability.tex`). **Honest caveat:** the *transcript* may be
  distinguishable from single-party ML-DSA (extra observables); the *signature*
  is not.
- **Permissionless dealerless safety** — anchored by the **Corona** leg
  (natively dealerless Ring-LWE) in the Quasar **AND-mode dual-PQ** cert. A
  forgery requires breaking **both** the Module-LWE Pulsar leg and the Corona
  leg; Pulsar is the FIPS-204-standard, assumption-shared defence-in-depth
  half, **not** the sole permissionless guarantee.

---

## 19. References

- **TALUS** — J. Kao, "TALUS: Threshold ML-DSA with One-Round Online Signing via
  Boundary Clearance and Carry Elimination," `arXiv:2603.22109`. *(BCC = Boundary
  Clearance Condition; CEF = Carry Elimination Framework; reduces to ML-DSA
  EUF-CMA; offline ticket factory + one-round online signing.)*
- **Mithril** — "Mithril: Threshold ML-DSA from Short Replicated Secret Sharing,"
  `ia.cr/2026/013`, USENIX Security 2026. *(Short replicated sharing + local
  per-party rejection, no global-abort MPC; DKG + a-posteriori key sharing;
  standard-verifier-compatible; practical small `N ≲ 8`.)*
- **Masked-Lagrange** — arbitrary-`T` dealerless threshold-ML-DSA research branch
  (the candidate for large-committee dealerless DKG).
- **Threshold Raccoon** — R. del Pino, S. Katsumata, T. Prest, M. Rossi,
  EUROCRYPT 2024. *(Noise-flooded lattice signatures — a **non-FIPS** verifier;
  the Corona/Raccoon line, not byte-FIPS-204; why Corona is the dealerless leg.)*
- **Corona** — Boschini et al., Ring-LWE threshold signatures (`luxfi/corona`),
  the dealerless leg of the dual-PQ Quasar cert.
- **BGW** — Ben-Or, Goldwasser, Wigderson, "Completeness Theorems for
  Non-Cryptographic Fault-Tolerant Distributed Computation," STOC 1988. *(The
  honest-majority MPC substrate; `N ≥ 2T−1` for the degree-2(T−1) product;
  `talus_mpc.go`.)*
- **FIPS 204** — NIST, Module-Lattice-Based Digital Signature Standard (ML-DSA).
  *(The single-party standard whose **verifier** accepts Pulsar output — Claim
  A. NIST does not standardize threshold ML-DSA.)*

### Companion artifacts in this repo / ecosystem
- Algorithm-level spec: `spec/pulsar.tex`, `spec/parameters.tex`,
  `spec/system-model.tex`, `spec/security-games.tex`.
- Proofs: `~/work/lux/proofs/pulsar/` (LaTeX) + `~/work/lux/proofs/lean/Crypto/Pulsar/`.
- Reference implementation: `ref/go/pkg/pulsar/` (BCC/CEF kernel, TALUS, the
  computed dealerless obstruction).
- Open residuals: `BLOCKERS.md` (Residual A: malicious-secure CSCP + networked
  MPC; Residual B: dealerless-key impossibility ⇒ Corona carries permissionless).
