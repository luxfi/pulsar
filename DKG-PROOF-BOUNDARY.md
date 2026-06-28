# Pulsar — DKG Proof-Boundary Specification

> **Purpose.** This document fixes the *proof boundary* of the Pulsar DKG and
> threshold-signing protocol: the exact bytes, domain separators, binding rules,
> commitment formats, test vectors, cross-version KATs, and the test→property
> map. It is the auditable contract between "what the protocol hashes/signs" and
> "what a security claim is allowed to say."
>
> **Grounded in v0.5.0** (`git tag v0.5.0` → commit `53ed1c2`, `origin/main`).
> Every implementation claim cites `ref/go/pkg/pulsar/<file>:<line>`. Companion
> documents: `PROOF-CLAIMS.md` (assurance vocabulary — the gate-read file),
> `VERSIONS.md` (version/track ledger), `BLOCKERS.md` (open residuals),
> `PULSAR.md` (the certificate-layer architecture this kernel sits under).

---

## §0. Claim discipline (read first — this is the whole point)

Two claims are made, and they are **never** conflated:

- **Claim (A) — standard-verifier compatibility (PROVEN).** A Pulsar threshold
  signature `(c̃, z, h)` is byte-for-byte a FIPS-204 ML-DSA signature: the
  *unmodified* `cloudflare/circl` `mldsa65.Verify` / `mldsa87.Verify` accepts it
  with **no Pulsar code in the verify path**. This is proven by
  `TestBCCSignRoundTripVerifiesCIRCL` (`bcc_sign_test.go:86`), which verifies a
  no-reconstruct BCC/CEF signature under an independent circl public key
  re-derived from the seed (`bcc_sign_test.go:140`,
  `:163`), with tamper / wrong-message / wrong-context **negatives**
  (`bcc_sign_test.go:144`, `:168`, `:172`). Assurance tag: **interop-tested**.

- **Claim (B) — DKG / threshold-protocol construction soundness (Lux-authored,
  SCOPED).** The distributed key generation and the threshold signing protocol
  are a Lux construction. Their security is the **scoped claim** in
  `PROOF-CLAIMS.md §0`:

  > *Dealerless committee key/nonce gen + CEF/CSCP no-reconstruct signing +
  > standard-ML-DSA-verifier output, semi-honest / no-leak today; malicious-CSCP +
  > networked-MPC are gated residuals.*

**Never claimed** (`PROOF-CLAIMS.md §0`): FIPS/NIST-certified threshold ML-DSA ·
fully-malicious-secure-proven · global-1000-validator DKG. NIST FIPS-204
standardises *single-party* ML-DSA only; Claim (A) is about the *output bytes*,
Claim (B) is *our* theorem.

### §0.1 The keygen residual — stated precisely (do not round this off)

The no-reconstruct property is a **SIGN-time** property. **Key generation is a
distinct axis** with its own honest scope (`VERSIONS.md` "Keygen / nonce-gen
track"). There are two share lineages in the tree, and they do **not** yet meet
in one path that is *both* dealerless at keygen *and* no-reconstruct:

| Lineage | Keygen | Sign | Status |
|---|---|---|---|
| **Seed-share** (`dkg.go` small GF(257); `large_dkg.go` large GF(q)) | dealerless ceremony, but **forms `sk` at keygen** | reconstruct-at-sign (`Combine`/`LargeCombine`) | `dkg.go` compiled; `large_dkg.go` **quarantined** behind `//go:build legacy_trusted_dealer` (`large_dkg.go:1`) |
| **`s1` poly-share** (`DealAlgShares`) | **trusted dealer** | **no-reconstruct** (`DistributedBCCSigner`/`AggregateBCC`) | sign path is the v0.5.0 production path; `DealAlgShares` keygen is **quarantined to `bootstrap_dealer_test.go`** (`distributed_bcc.go:140`) |

Concretely, for the dealerless seed-share ceremony:

- The committee derives `GroupPK` in the **seed domain**:
  `masterSeed = cSHAKE256( jointByteSum ‖ committeeRoot, "PULSAR-SEED-SHARE-V1" )`
  then `sk = KeyFromSeed(masterSeed)`, `GroupPK = sk.Pub`
  (`dkg.go:422`–`426`; quarantined twin `large_dkg.go:359`–`363`).
- A test proves **structural seed-equivalence**:
  `GroupPK == KeyFromSeed(masterSeed).Pub` —
  `TestDKG_ProducesValidPubkey_VerifiableSign` reconstructs the seed from a
  threshold share set (`shamirReconstructGF`, `dkg.go_test:189`), recomputes
  `masterSeed` (`dkg_test.go:201`) and `sk = KeyFromSeed` (`dkg_test.go:202`),
  and asserts `sk.Pub.Equal(groupPub)` (`dkg_test.go:206`).

**The residual:** deriving `GroupPK` this way **forms `sk` at keygen**
(keygen-side reconstruction). In the *small-committee* `dkg.go` ceremony every
member additionally learns the master secret (the dealer contributions `c_i` are
summed locally — the explicit "v0.1 reconstruction-aggregator trust model",
`dkg.go:366`–`368`). This is **separate from**, and weaker than, the
no-reconstruct **SIGNING** path (`distributed_bcc.go`), which is v0.5.0-clean: no
process forms `s1`, the seed, `sk`, `c·s2`, `c·t0`, `r0`, or full `w`
(`distributed_bcc.go:39`–`68`, enforced by `assertBCCTranscriptNoLeak`,
`bcc_sign_test.go:112`).

**What is NOT yet proven.** Full FIPS-204 *KeyGen-distribution-equivalence* — that
the dealerless ceremony's `GroupPK` is distributed identically to a single honest
`KeyGen`, with (i) an unbiased master seed, (ii) hiding against `< t`
corruptions, and (iii) abort-bias resistance — requires a separate
simulation/hiding proof. It is **not** established by the structural
seed-equivalence test (which only proves the *map* `seed ↦ pk` is the FIPS one).
This is the dealerless-keygen track (`feat/v02-pedersen-vss-no-reconstruct`,
`VERSIONS.md`); for the *byte-FIPS-204 `s1`-share* DKG the naive additive lift is
**proven unreachable** by a parameter obstruction (§1.4, §7), with Mithril short
replicated sharing (`ia.cr/2026/013`) as the named adoption target.

**Therefore:** SIGNING = no-reconstruct + malicious-hardened (v0.5.0); KEYGEN =
dealerless-but-seed-reconstruct-for-`GroupPK` (seed-share lineage) *or*
trusted-dealer (`s1`-share lineage) — that gap is the residual. Permissionless
dealerless *safety* is carried by the **Corona** leg of the Quasar AND-mode
dual-PQ cert, not by Pulsar keygen (`naive_additive_seta_obstruction.go:105`–
`108`).

### §0.2 Consensus-native framing

Pulsar is **not** an all-`N`-sign protocol. Lux consensus subsampling carries
chain *safety*; Pulsar produces **compact post-quantum certificates over
consensus-finalised digests** — one committee of `k` members signs, never all `N`
validators (`PULSAR.md §12` "Never all-N-sign"; cost `O(k)`, independent of `N`).
The DKG below is therefore a **per-committee, per-epoch** ceremony, and the
binding rules (§3) pin each share/cert to its committee, epoch, and key.

---

## §1. Deliverable 1 — Protocol transcript spec (byte layout & ordering)

All Pulsar hashing routes through `transcript.go` (FIPS-202 / SP 800-185); direct
stdlib-hash use elsewhere is a CI failure (`transcript.go:9`–`11`). The two
framing primitives:

- **`cshake256(input, outLen, S)`** = cSHAKE256 with function-name `N = "Pulsar"`
  (`transcript.go:66`, `:72`–`78`). Pinning `N="Pulsar"` makes a cross-suite
  mix-up a deterministic mismatch.
- **`transcriptHash(S, parts…)`** → 48-byte digest, SP 800-185 TupleHash256-style:
  `leftEncode(nparts) ‖ Σ encodeString(part_i)`, then `cSHAKE256(·, 48, S)`
  (`transcript.go:170`–`180`). **`transcriptHash32`** is the 32-byte counterpart
  (`transcript.go:184`–`194`). Length-prefixed parts ⇒ unambiguous boundaries.

### §1.1 DKG transcript (seed-share ceremony, `dkg.go` / `large_dkg.go`)

Three rounds. `SeedSize = 32`. Committee is canonicalised (byte-ascending
`NodeID` sort) so all parties agree on the position↔eval-point map with no
out-of-band coordination (`dkg.go:145`–`154`).

**committeeRoot** (binds the ceremony to this exact committee):
```
committeeRoot = transcriptHash32( "PULSAR-DKG-COMMIT-V1",
                                  "PULSAR-COMMITTEE-V1",
                                  sortedNodeID_1, …, sortedNodeID_n )
```
(`dkg.go:514`–`521`; GF(q) twin `large_dkg.go:428`–`435`.)

**Round 1** — each party samples a 32-byte contribution `c_i` (SECRET,
`dkg.go:202`–`205`) and an independent non-secret `encapBlindKey`
(`dkg.go:213`; independence is the C2 fix — a fault on the cSHAKE call cannot
leak `c_i`). It byte-wise Shamir-shares `c_i` over GF(257) with coefficient
stream
```
stream = cSHAKE256( "PULSAR-DKG-DEALER-V1" ‖ committeeRoot ‖ be16(myIndex) ‖ c_i,
                    (t−1)·SeedSize·2, "PULSAR-SEED-SHARE-V1" )
```
(`dkg.go:223`–`233`; GF(q) twin uses width ·4 and 128-byte shares,
`large_dkg.go:182`–`196`). Each per-recipient share is sealed in an ML-KEM-768
envelope under the recipient's long-term identity KEM key, with encapsulation
seed
```
encapBlind = cSHAKE256( encapBlindKey ‖ myID ‖ recipient, 64, "PULSAR-DKG-ENCAPSEED-V1" )
```
(`dkg.go:264`–`270`). `DKGRound1Msg = { NodeID, Envelopes: map[NodeID]DKGShareEnvelope }`
(`dkg.go:291`–`294`); each envelope carries `{ KEMCiphertext, Sealed }`.

**Round 2** — the **equivocation gate**. Every honest party computes the SAME
canonical digest over the ordered Round-1 set:
```
D = transcriptHash32( "PULSAR-DKG-COMMIT-V1",
       committeeRoot,
       for each sender m in committee order:
           m.NodeID,
           for each recipient k in sorted order:
               k, env.KEMCiphertext, env.Sealed )
```
(`dkg.go:492`–`510`). `DKGRound2Msg = { NodeID, Digest: [32]byte }`
(`dkg.go:313`–`316`). The committeeRoot inside `D` pins it to this committee, so a
colluding dealer+recipient cannot replay an envelope across committees
(`dkg.go:488`–`491`).

**Round 3** — verify digest agreement (constant-time `ctEqual32`,
`dkg.go:345`–`355`; mismatch ⇒ `ComplaintEquivocation`), open each envelope to me,
aggregate my Shamir share `aggY` and the contribution byte-sum
`byteSum = Σ_i c_i mod 257` (`dkg.go:402`–`405`), then derive the master key:
```
byteSumBytes = be16-pack(byteSum)            # 2 bytes/lane (GF(257)); GF(q): 4 bytes/lane be32
mixInput     = byteSumBytes ‖ committeeRoot
masterSeed   = cSHAKE256( mixInput, 32, "PULSAR-SEED-SHARE-V1" )   # dkg.go:422–424
sk           = KeyFromSeed(params, masterSeed)                     # dkg.go:426  ← forms sk (residual §0.1)
transcript   = transcriptHash( "PULSAR-DKG-TRANSCRIPT-V1",
                               committeeRoot, D, sk.Pub.Bytes )    # dkg.go:439–443
```
`DKGOutput = { GroupPubkey: sk.Pub, SecretShare: KeyShare{NodeID, EvalPoint,
Share, Pub, Mode}, TranscriptHash, AbortEvidence }` (`dkg.go:451`–`462`). Local
secret material is zeroized (`dkg.go:467`–`470`). The 48-byte `TranscriptHash` is
the chain-pinning commitment (it equals FIPS-204 CTildeSize, so it doubles as a
fixed-width anchor, `transcript.go:161`–`164`).

### §1.2 Signing transcript (no-reconstruct BCC/CEF, `distributed_bcc.go`)

The per-party key custody is **one** `AlgShare` — a poly-vector Shamir share of
the *expanded* `s1` (length `L`) over GF(q), `s1` only, never `s2`/`t0`/seed
(`distributed_bcc.go:104`–`117`). One online round over an offline nonce:

**μ and challenge (single source of truth).**
```
μ  = SHAKE256( tr ‖ 0x00 ‖ |ctx| ‖ ctx ‖ msg )        # FIPS-204 §5.4 (deriveMuCtx)
c̃ = SHAKE256( μ ‖ packW1(w1) )                         # deriveCTilde, distributed_bcc.go:1002–1012
c  = SampleInBall(c̃)                                   # polyDeriveUniformBall, :580–586
```
Every party's Round-1 `c` and the aggregator's signature `c̃` are the SAME bytes
for the same `(tr, ctx, msg, w1)` (`distributed_bcc.go:997`–`1001`).

**Round 1** (`DistributedBCCSigner.Round1`, `distributed_bcc.go:554`–`589`) binds
the canonical `NonceCert` to the session (`sid` match, `nonceID` match, mode
match), unpacks `w1 = HighBits(w)`, captures the packed `w1` as the single-use
material (keyed on `w1`, not the `nonceID` label, `:574`–`576`), and derives `c`.
`SignRound1 = { SessionID, NonceID, NonceCert }`.

**Round 2** (`distributed_bcc.go:597`–`680`) — **reserve the nonce BEFORE the
secret is touched** (§3.3), then emit the proof-carrying partial:
```
z_i      = partialLinearMap( λ_i, ĉ, y_i, s1_i )                 # :639  (λ_i·y_i + c·λ_i·s1_i over R_q^L)
proof    = ProvePartial( PartialStatement{ Mode, λ_i, c, z_i, sid, nonceID,
                         PartyID, DKGCommitment, NonceCommitment }, witness )  # :647–658
Partial  = { PartyID, NonceID, SessionID, ZShare=packPolyVec(z_i), Proof,
             [Author, AuthSig] }                                  # :662–679
```
`DKGCommitment, NonceCommitment` come from `shareCommitmentsFor` — the single
source of truth shared with the verifier; **nil today** (§4). If an identity
signer is wired, `AuthSig = idSigner.SignProtocolMessage(partialAuthTBS(p, epoch))`
(`:675`–`678`).

**Finalize** (aggregator = `quorum[0]`, `AggregateBCCWithBlame`,
`distributed_bcc.go:830`–`995`), in order, fail-closed:
1. **Authenticate origin** before any attribution (`:849`–`862`): drop
   forged/wrong-slot/unsigned partials with no blame against the slot's owner.
2. **Verify + attribute** each partial's sigma proof bound to
   `(λ_p, c, z_p, session, nonce, party)` and the per-party commitments; first
   partial per `PartyID` is authoritative; duplicates/malformed/invalid →
   `PartialBlame` (`:882`–`923`).
3. **Canonical signer subset** of exactly `threshold` distinct signers
   (`CanonicalSignerSet`, non-grindable, `:926`).
4. `z = Σ_chosen z_p` (Lagrange-linear, telescopes to `ȳ + c·s1`; `s1` never
   formed, `:931`–`938`).
5. `‖z‖∞ < γ1 − β` (FIPS-204 reject bound, `:941`).
6. `w' = A·z − c·t1·2^d` (PUBLIC, `:945`–`968`); `hint = FindHint(w', w1)` from
   public data only (`:973`).
7. `sigEncode(c̃, z, h)` per FIPS-204 Algorithm 28 (`:978`–`986`).

Output: `ConsensusCert = { JointPKID, SignerBitmap, Signature }`
(`:989`–`993`). **No share, sk, or seed enters `AggregateBCC`'s parameter list** —
the load-bearing no-reconstruct boundary (`:796`–`805`).

---

## §2. Deliverable 2 — Domain separators (every DST, from code)

All tags are version-pinned; rotating one invalidates every vector pinned at it
(`transcript.go:18`–`21`). Two encodings coexist:
**`PULSAR-…-V1`** (cSHAKE customisation strings, `transcript.go`) and
**`PULSAR/…/v1`** (literal prefixes hashed as the first SHAKE input). Both are
the *implemented reality*; `PULSAR.md §14`'s `pulsar:v1:*` is the *proposed
certificate-layer* namespace (not yet in code) — kept distinct on purpose.

### §2.1 cSHAKE256 customisation tags (`transcript.go:33`–`66`)

| Constant | Value | Purpose | Site |
|---|---|---|---|
| `functionName` | `Pulsar` | cSHAKE `N` param (all calls) | `transcript.go:66` |
| `tagDKGCommit` | `PULSAR-DKG-COMMIT-V1` | DKG Round-2 digest + committeeRoot | `transcript.go:33`; `dkg.go:509`,`520` |
| `tagDKGTranscript` | `PULSAR-DKG-TRANSCRIPT-V1` | DKG transcript / finalization hash | `transcript.go:34`; `dkg.go:439` |
| `tagSignR1` | `PULSAR-SIGN-R1-V1` | Round-1 binding | `transcript.go:35` |
| `tagSignR1MAC` | `PULSAR-SIGN-R1-MAC-V1` | Round-1 MAC envelope | `transcript.go:36` |
| `tagSignR2` | *(reserved, undefined)* | Round-2 MAC (intentionally undefined so a stale rebase fails to compile) | `transcript.go:37`–`46` |
| `tagSignMask` | `PULSAR-SIGN-MASK-V1` | per-attempt Round-1 mask derivation | `transcript.go:53` |
| `tagReshareCommit` | `PULSAR-RESHARE-COMMIT-V1` | reshare commit | `transcript.go:54` |
| `tagReshareTrans` | `PULSAR-RESHARE-TRANSCRIPT-V1` | reshare transcript | `transcript.go:55` |
| `tagReshareBeacon` | `PULSAR-RESHARE-BEACON-V1` | reshare beacon | `transcript.go:56` |
| `tagExpandB` | `PULSAR-EXPANDB-V1` | matrix `B` expansion | `transcript.go:57` |
| `tagComplaint` | `PULSAR-COMPLAINT-V1` | complaint hashing | `transcript.go:58` |
| `tagSeedShare` | `PULSAR-SEED-SHARE-V1` | Shamir coeff stream + master-seed mix | `transcript.go:59`; `dkg.go:233`,`424` |

### §2.2 Literal-prefix DSTs (`PULSAR/…/v1` and friends)

| String | Purpose | Site |
|---|---|---|
| `PULSAR-DKG-DEALER-V1` | DKG Shamir coeff-stream key material | `dkg.go:225`; `large_dkg.go:184` |
| `PULSAR-DKG-ENCAPSEED-V1` | per-recipient ML-KEM-768 encap seed | `dkg.go:268`; `large_dkg.go:214` |
| `PULSAR-COMMITTEE-V1` | committee-root prefix | `dkg.go:516`; `large_dkg.go:430`,`470` |
| `PULSAR/nonce-single-use/v1` | nonce dedup key (`w1` alone) | `nonce_ledger.go:323` |
| `PULSAR/share-ledger-identity/v1` | committee-independent share identity | `nonce_ledger.go:231` |
| `PULSAR/nonce-ticket-id/v1` | nonce ticket id (folds in binding) | `nonce_ledger.go:283` |
| `PULSAR/committee-id/v1` | committee id = H(jointPKID ‖ quorum) | `nonce_ledger.go:335` |
| `PULSAR/nonce-binding-digest/v1` | `(ctx,msg)` digest in a reservation | `nonce_ledger.go:351` |
| `PULSAR/partial-auth-digest/v1` | z-partial slot+content auth digest | `distributed_bcc.go:743` |
| `PULSAR-BCC-CEF/joint-pk-id/v1` | stable group-PK id (`JointPKID`) | `distributed_bcc.go:1039` |
| `PULSAR/protocol-msg/v1` | authenticated-protocol-message TBS | `protocol_auth.go:57` |
| `PULSAR-TESTRAND-V1` | deterministic test RNG (tests only) | `dkg_test.go:264` |

---

## §3. Deliverable 3 — Participant / key-epoch binding rules

A share or certificate is bound to its context by the following identities. Each
row states **what is hashed**, the **site**, and — honestly — **where binding is
NOT yet at the kernel** (cert-layer or implicit).

| Bound to | Mechanism (what is hashed) | Site | Honest note |
|---|---|---|---|
| **group / key** | `JointPKID = SHAKE256("PULSAR-BCC-CEF/joint-pk-id/v1" ‖ mode ‖ pub.Bytes)` | `distributed_bcc.go:1033`–`1044` | the key-identity root |
| **key-epoch (generation)** | `Epoch` field in `NonceBinding` and `ProtocolContext`; recorded per reservation | `nonce_ledger.go:99`; `protocol_auth.go:34`; set via `SetNonceBinding` `distributed_bcc.go:510`–`515` | epoch is *recorded/auditable*; it is part of the auth-TBS (§3.4) and reservation, not (yet) folded into `JointPKID` |
| **participant set** | `committeeID = SHAKE256("PULSAR/committee-id/v1" ‖ JointPKID ‖ each sorted quorum NodeID)`; DKG: `committeeRoot` | `nonce_ledger.go:333`–`343`; `dkg.go:514`–`521` | binds the exact sorted quorum + key |
| **threshold `t`** | enforced by `CanonicalSignerSet(valid, threshold)` (exactly `t` distinct signers; duplicates rejected) | `distributed_bcc.go:926`; dup-reject `:892`–`894` | `t` is *enforced* at aggregation but **not hashed** into `committeeID` — a flagged gap; bind `t` at the cert layer (`PULSAR.md §7`) |
| **policy id** | `Policy [32]byte` in `NonceBinding`, canonical-encoded | `nonce_ledger.go:101`,`264`–`276` | auditable domain tag (block-cert vs warp-msg, …) |
| **transcript / domain tag** | per-purpose DSTs (§2) + `SessionID`; FIPS-204 context string in `μ` | `transcript.go`; `distributed_bcc.go:1002` | one tag per purpose, never reused |
| **message** | `Digest = SHAKE256("PULSAR/nonce-binding-digest/v1" ‖ mode ‖ μ)`, `μ = deriveMuCtx(tr,ctx,msg)` | `nonce_ledger.go:347`–`357` | binds the reservation to exactly what is signed |
| **chain / network** | via FIPS-204 `ctx` string + `Policy` | `distributed_bcc.go:1002`; `nonce_ledger.go:101` | full `chain_id` binding is the **cert-layer target** (`PULSAR.md §14` `message_digest` includes `chain_id`); the kernel binds it indirectly through `ctx`/`Policy` today |

### §3.1 Committee identity
`deriveCommitteeID(JointPKID, sortedQuorum)` (`nonce_ledger.go:333`–`343`) binds a
nonce reservation to **this committee + key**. The DKG analogue is `committeeRoot`
(`dkg.go:514`–`521`), which a colluding dealer+recipient cannot replay across
committees (`dkg.go:488`–`491`).

### §3.2 Share identity (epoch / reshare separation)
`shareIdentityKey(share) = SHAKE256("PULSAR/share-ledger-identity/v1" ‖ mode ‖
NodeID ‖ be32(EvalPoint) ‖ S1Share coeffs)` (`nonce_ledger.go:229`–`246`) is
**committee-independent on purpose**: the same secret share across any committee
resolves to ONE single-use ledger. A *re-shared* key (same `NodeID`+`EvalPoint`,
new `S1Share`) hashes to a **distinct** identity — so a proactive refresh is not
wrongly bound to the retired key's reservations. This is the epoch/generation
separation at the share level.

### §3.3 Nonce single-use binding (anti key-recovery)
The dedup key is `nonceMaterialKey(w1) = SHAKE256("PULSAR/nonce-single-use/v1" ‖
w1)` — **`w1` ALONE**, not the `nonceID` label, not `committeeID`
(`nonce_ledger.go:321`–`328`). Rationale (`nonce_ledger.go:309`–`320`): dropping
the label defeats relabel-bypass (same `ȳ` ⇒ same `w1`); dropping `committeeID`
closes cross-committee reuse (the ledger is already per-share). Reuse ⇒
`ErrNonceReused`, fail-closed, before any secret is emitted
(`nonce_ledger.go:80`; reserve at `distributed_bcc.go:626`–`635`). This is the
defence against the linear-response key-recovery `z_A − z_B = (c_A − c_B)·s1`
(`nonce_ledger.go:8`–`25`).

### §3.4 Authenticated-message slot binding
`ProtocolMessageTBS(author, ctx, payloadDigest)` (`protocol_auth.go:55`–`70`) is
SP 800-185-framed over `("PULSAR/protocol-msg/v1", author, be64(epoch),
sessionID, nonceID, {round}, payloadDigest)`. Equivocation is defined per
`(Author, Epoch, SessionID, Round)` — one author may sign at most one payload per
slot (`protocol_auth.go:22`–`23`); two valid signatures on distinct payloads for
one slot is non-repudiable misbehavior (`DetectEquivocation`,
`protocol_auth.go:97`–`127`).

---

## §4. Deliverable 4 — Share-commitment format (with the honest BDLOP flag)

Two distinct "commitment" notions exist; do not conflate them.

### §4.1 DKG-side binding (implemented) — equivocation digest, not a lattice commitment
The seed-share DKG **dropped** the v0.1 commit-and-open (CR-6 path A): the
broadcast carries **no separate commitment field**; binding comes from the
Round-2 equivocation digest over the ordered envelope set
(`dkg.go:21`–`29`, `:492`–`510`). So the *implemented* DKG "commitment" is the
32-byte `transcriptHash32(tagDKGCommit, …)` hash-commitment to the dealt
envelopes — **not** a per-coefficient hiding lattice commitment. The R_q^k
Pedersen/BDLOP binding (M-LWE-hard, `pulsar.tex §3.2/§4.1`) is explicitly the
**v0.2 future work** (`dkg.go:26`–`29`).

### §4.2 Sign-side share-commitment (the BDLOP plug point) — **nil today, flagged**
`AlgSetup.s1ShareCommit map[uint32][]byte` holds the per-party (keyed by GF(q)
eval point) hiding commitment to the dealt `s1`-share, for identifiable-abort
binding of the partial-`z` proof. **It is `nil` today**
(`distributed_bcc.go:130`–`138`). The single source of truth read by *both*
prover and verifier is:
```go
func shareCommitmentsFor(setup, nonceID, evalPoint) (dkgCommit, nonceCommit []byte)
// returns (nil, nil) today  — share_commit.go:94–106
```
The intended format (when populated) is BDLOP (`ia.cr/2017/1235` / Ajtai) under a
**separate** public matrix `B` (independent of `A`):
```
Com_s_i = B·r_s_i + embed(s1_i)      # key-share commitment   (share_commit.go:43–44)
Com_y_i = B·r_y_i + embed(y_i)       # nonce-share commitment  (share_commit.go:45)
```
hiding under M-LWE (short randomness `r_*`), so it reveals neither `A·s1_i` nor
`A·y_i` (avoids the W-LEAK / HINT-LEAK that a homomorphic-image commitment would
reopen, `share_commit.go:26`–`35`). At sign time the party would prove **three**
simultaneous linear relations `(z_i, Com_y_i, Com_s_i)` in one extended sigma
(`share_commit.go:46`–`59`).

**Honest consequence (the residual).** Because `s1ShareCommit` is nil, a
**valid-sigma but WRONG-`z`** partial is **not yet attributable** — it is bounded
to a **liveness** fault (never a forgery, never a leak: the wrong aggregate fails
FIPS-204 verify and nothing secret crosses the wire), marked by
`ErrIdentifiableAbortResidual` (`share_commit.go:70`–`75`; `blame.go:18`–`23`).
The Fiat-Shamir statement binding `(session, nonce, party, c, λ)` in
`partial_proof.go` already gives **non-transferability**; the BDLOP commitments
add **dealt-share** binding, which is the gated Residual A (`BLOCKERS.md`).

---

## §5. Deliverable 5 — Valid / invalid DKG (and signing) test vectors

The structured behavioral vectors live in
**`vectors/dkg-proof-boundary.json`** (this PR). Each vector names the scenario,
the layer, the expected outcome, the **exact code error/blame constant**, and the
`file:line` that enforces it. They are *spec-level state vectors* — distinct from
the byte-level wire KATs in `vectors/{keygen,sign,verify,threshold-sign,dkg}.json`
(§6). Summary:

**Positive (accept):**
- `dkg/happy-path` — all honest parties output the **same** `GroupPubkey`
  (`dkg.go` ↔ `TestDKG_HappyPath`, `dkg_test.go:86`–`88`).
- `dkg/seed-equivalence` — `GroupPK == KeyFromSeed(masterSeed).Pub`, and a
  reconstructed-key signature **verifies under FIPS-204**
  (`TestDKG_ProducesValidPubkey_VerifiableSign`, `dkg_test.go:206`,`215`).
- `sign/circl-roundtrip` — threshold `(c̃,z,h)` accepted by unmodified circl
  `mldsa{65,87}.Verify` (`TestBCCSignRoundTripVerifiesCIRCL`, `bcc_sign_test.go:86`).

**Negative (reject / blame), each grounded in a real constant:**
- `dkg/malformed-commitment` (equivocating Round-2 digest) → `ComplaintEquivocation`
  (`dkg.go:347`–`353`; `TestDKG_Equivocation_Detected`, `dkg_test.go:111`).
- `dkg/bad-share` (envelope fails to open / missing) → `ComplaintBadDelivery`
  (`dkg.go:379`–`385`, `:391`–`397`).
- `dkg/equivocation` (dealer ships divergent envelope sets) → `ComplaintEquivocation`
  (`large_dkg.go:292`–`298`).
- `dkg/missing-participant` → `ErrTooFewRound1` / `ErrTooFewRound2`
  (`dkg.go:54`–`55`, `:330`–`335`).
- `dkg/node-not-in-committee` → `ErrNotInCommittee` (`dkg.go:50`,`171`;
  `TestDKG_NodeNotInCommittee`, `dkg_test.go:220`).
- `dkg/duplicate-committee` → `ErrCommitteeDuplicate` (`dkg.go:49`,`151`).
- `dkg/empty-committee` → `ErrCommitteeEmpty` (`dkg.go:48`,`129`).
- `dkg/wrong-epoch` — at sign time a reused nonce re-presented under a different
  `(epoch,…)` binding → `ErrNonceBindingMismatch` (`nonce_ledger.go:87`); at DKG a
  different epoch ⇒ different `committeeRoot` ⇒ a structurally distinct `GroupPK`
  (`dkg.go:61`–`63`).
- `sign/nonce-reuse` → `ErrNonceReused` (`nonce_ledger.go:80`).
- `sign/session-mismatch` → `BlameSessionMismatch` (`blame.go:37`).
- `sign/duplicate-partyid` → `BlameDuplicatePartyID` (`blame.go:33`).
- `sign/unknown-party` → `BlameUnknownParty` (`blame.go:35`).
- `sign/malformed-partial` → `BlameMalformed` (`blame.go:31`).
- `sign/invalid-proof` → `BlameProofInvalid` (`blame.go:39`).
- `sign/forged-victim-slot` → dropped pre-attribution, victim **not** blamed
  (`distributed_bcc.go:849`–`862`).
- `keygen/dealerless-byte-fips` → `ErrDealerlessByteFIPSUnreachable` for any
  committee `parties ≥ 2` (`naive_additive_seta_obstruction.go:152`,`242`).

---

## §6. Deliverable 6 — Cross-version KATs (old wire compatibility)

The committed wire KATs are the **cross-version compatibility suite**: vectors
generated by an earlier version, replayed every CI run; drift = gate failure
(`kat_test.go:21`–`23`). Runner: `kat_test.go`, reads `vectors/*.json`.

| Vector file | Entries | Pins (hex) | Replay test |
|---|---|---|---|
| `vectors/keygen.json` | 9 | `seed → public_key, private_key` | `TestKAT_Keygen_Replay` (`kat_test.go:50`) |
| `vectors/sign.json` | 9 | `seed,msg,ctx → signature` | `TestKAT_Sign_Replay` (`kat_test.go:91`) |
| `vectors/verify.json` | 6 | `public_key,msg,signature → accept` | `TestKAT_Verify_Replay` (`kat_test.go:127`) |
| `vectors/threshold-sign.json` | 4 | `n,t,msg,public_key → signature` (Class N1 interchangeability) | `TestKAT_ThresholdSign_Replay` (`kat_test.go:159`) |
| `vectors/dkg.json` | 3 | DKG replay | `TestKAT_DKG_Replay` (`kat_test.go:197`) |

Example committed entry (`vectors/keygen.json[0]`, ML-DSA-44):
`seed = d433e36e…b6d224ee`, `public_key = d0e601a2…` — `KeyFromSeed(seed).Pub`
must reproduce these exact bytes (`kat_test.go:79`). `threshold-sign.json[0]`
(`Pulsar-65`, `n=3, t=2`) pins a *threshold* signature that the **single-party**
verifier accepts — the wire-level statement of Claim (A) across versions.

**Cross-implementation KAT.** `TestDKGVSS_RingMLDSA65_ExpandABinding_KAT`
(`dkg_vss_kat_test.go:104`) anchors the shared `luxfi/dkg` ring against pulsar's
own FIPS-204 arithmetic: pulsar's `A = ExpandA(rho)` round-trips through the dkg
ring with no spurious Montgomery factor, and the dkg ring recomputes
`t1 = Power2Round(A·s1+s2)` **byte-identical to circl**. Its header also restates
the keygen residual honestly: the stock-verifiable threshold *signature* keeps
the trusted-dealer key — the vss no-reconstruct group key `T = A·s1+B·u` (large
`s2 = B·u`) is not directly BCC-signable (`dkg_vss_kat_test.go:26`–`34`).

---

## §7. Deliverable 7 — Proof checklist (test → security property)

Assurance tags are the `PROOF-CLAIMS.md` vocabulary
(machine-checked · sound-by-reduction · interop-tested · test-proven ·
fail-closed-pending-review · open-research). The split is always
**(A) verifier-compat** vs **(B) Lux construction**.

| # | Security property | Test / artifact (file:line) | Claim | Assurance |
|---|---|---|---|---|
| 1 | **Correctness** — DKG yields a valid FIPS-204 key; its signature verifies | `TestDKG_ProducesValidPubkey_VerifiableSign` `dkg_test.go:147` (`:206` equal, `:215` verify) | B | test-proven |
| 2 | **Consistency** — all honest parties agree on `GroupPK` | `TestDKG_HappyPath` `dkg_test.go:86`–`88`; `large_e2e_test.go:100`–`103` | B | test-proven |
| 3 | **Standard-verifier compatibility** — `(c̃,z,h)` accepted by unmodified circl, with negatives | `TestBCCSignRoundTripVerifiesCIRCL` `bcc_sign_test.go:86` (`:140`,`:163`; neg `:144`,`:168`,`:172`) | **A** | **interop-tested** |
| 4 | **Secrecy / no-reconstruct** — no process forms `s1`/seed/`sk`/`c·s2`/`c·t0`/`w` | `assertBCCTranscriptNoLeak` `bcc_sign_test.go:112`,`:217`; `gate2_reachability_test.go`; Lean `Crypto.Pulsar.NoLeakAggregate` | B | machine-checked (Lean core) + test-proven; reduction = sound-by-reduction (M-LWE/M-SIS) |
| 5 | **Binding — domain separation** — per-purpose DSTs, no reuse | §2 tables; `transcript.go:33`–`66`; framing `transcript.go:170`–`194` | B | test-proven (KAT-pinned) |
| 6 | **Binding — equivocation** — one author, one payload per slot | `TestDKG_Equivocation_Detected` `dkg_test.go:111`; `DetectEquivocation` `protocol_auth.go:97` | B | test-proven |
| 7 | **Robustness / identifiable abort** — deviating partials attributed | `blame.go`; `AggregateBCCWithBlame` `distributed_bcc.go:830`; `blame_gate_test.go` | B | test-proven (semi-honest) |
| 8 | **Robustness residual** — valid-sigma wrong-`z` attribution | `share_commit.go:70`–`75` `ErrIdentifiableAbortResidual` (BDLOP) | B | **fail-closed-pending-review** |
| 9 | **Unforgeability — nonce single-use** — defeats `(c_A−c_B)·s1` recovery | `nonce_ledger.go`; `TestRED_NonceReuse_RecoversS1`, `TestRED_PoC_DefaultLedger_NonceReuse_Refused`, `TestRED_LOW_CrossCommittee_SameNonce_Deduped` (`VERSIONS.md`) | B | test-proven |
| 10 | **Unforgeability — base EUF-CMA** — output is a standard ML-DSA sig | inherits ML-DSA EUF-CMA under M-LWE/M-SIS (output bytes = FIPS-204) | A→B | sound-by-reduction (inherited) |
| 11 | **Authenticated origin** — forged victim-slot partial cannot frame/exclude | `authenticatePartial` `distributed_bcc.go:777`; `TestRED_PoC_MEDIUM_CannotFrameOrExcludeHonestVictim` (`VERSIONS.md`) | B | test-proven |
| 12 | **Cross-version wire compat** — committed KATs replay byte-identical | `kat_test.go:50`,`91`,`127`,`159`,`197` vs `vectors/*.json` | A | interop-tested / test-proven |
| 13 | **Cross-impl arithmetic** — `luxfi/dkg` ring reproduces FIPS-204 `t1` | `TestDKGVSS_RingMLDSA65_ExpandABinding_KAT` `dkg_vss_kat_test.go:104` | A | interop-tested |
| 14 | **Keygen residual — dealerless byte-FIPS obstruction (`s1`-share)** | `assessDealerlessFIPS` `naive_additive_seta_obstruction.go:196`; `DealerlessMLDSADKG` `:242` → `ErrDealerlessByteFIPSUnreachable` `:152` | B | sound-by-reduction (parameter-derived) |
| 15 | **Keygen residual — KeyGen-distribution-equivalence** (unbiased seed, hiding vs `<t`, abort-bias) | **not proven**; structural seed-equivalence only (`dkg_test.go:206`) | B | **open-research** |
| 16 | **Nonce leak-freedom (production NonceMPC)** | `DealNonceMPCDebug` is a stand-in exposing `DebugW` to tests only (`distributed_bcc.go:232`–`257`) | B | **fail-closed-pending-review** (W-LEAK residual) |

### §7.1 What the checklist deliberately does NOT claim
Rows 8, 15, 16 are **residuals**, fail-closed and tracked, not silently weakened.
No row asserts FIPS/NIST-certified threshold ML-DSA, fully-malicious-secure, or
global-`N`-validator DKG (`PROOF-CLAIMS.md §0`). Claim (A) (rows 3, 12, 13) is the
*proven* verifier-compatibility statement; Claim (B) (the rest) is the *scoped*
Lux construction. The keygen residual (§0.1) is real: SIGNING is no-reconstruct
and malicious-hardened in v0.5.0; KEYGEN remains dealerless-but-seed-reconstruct
(seed-share lineage) or trusted-dealer (`s1`-share lineage), with permissionless
dealerless safety carried by Corona.
