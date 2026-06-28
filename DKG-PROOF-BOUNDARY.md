# Pulsar — DKG Proof-Boundary Specification

> **Purpose.** This document fixes the *proof boundary* of the Pulsar DKG and
> threshold-signing protocols: the exact bytes, domain separators, binding rules,
> commitment formats, test vectors, cross-version KATs, and the test→property
> map. It is the auditable contract between "what the protocol hashes/signs" and
> "what a security claim is allowed to say."
>
> **Grounded in v0.6.3** (`git log` → commit `0650729`, `origin/main`). Every
> implementation claim cites `ref/go/pkg/pulsar/<file>:<line>`. Companion
> documents: `PROOF-CLAIMS.md` (assurance vocabulary — the gate-read file),
> `ref/go/pkg/pulsar/VERSIONS.md` (version/track ledger), `BLOCKERS.md` (open
> residuals), `PULSAR.md` (the certificate-layer architecture this kernel sits
> under).

---

## §0. Claim discipline (read first — this is the whole point)

Two claims are made, and they are **never** conflated:

- **Claim (A) — standard-verifier compatibility (PROVEN).** A Pulsar threshold
  signature `(c̃, z, h)` is byte-for-byte a FIPS-204 ML-DSA signature: the
  *unmodified* `cloudflare/circl` `mldsa65.Verify` / `mldsa87.Verify` accepts it
  with **no Pulsar code in the verify path**. This is proven, today, in **three**
  independent settings:

  | Setting | Test | Site |
  |---|---|---|
  | No-reconstruct BCC/CEF over a single group key | `TestBCCSignRoundTripVerifiesCIRCL` | `bcc_sign_test.go:86` |
  | **Dealerless RSS** key (all 15 committees N ≤ 6) | `TestMithrilRSSStockCirclVerify` | `mithril_rss_test.go:38` |
  | **Dealerless RSS** key (T = N at N > 6: n=8,t=8; n=16,t=16) | `TestMithrilRSS_LargeN_StockCircl` | `mithril_rss_n8_test.go:16` |
  | **No-reconstruct hyperball** over the RSS key | `TestHyperballStockCirclVerify` | `mithril_rss_hyperball_test.go:41` |

  All carry tamper / wrong-message / wrong-context **negatives** (verifier
  non-vacuous). Assurance tag: **interop-tested**.

- **Claim (B) — DKG / threshold-protocol construction soundness (Lux-authored,
  SCOPED).** The dealerless key generation (RSS / Mithril) and the threshold
  signing protocols (BCC/CEF/CSCP + hyperball) are a Lux construction. Their
  security is the **scoped claim** in `PROOF-CLAIMS.md §0` and `PULSAR.md §0`:

  > *Dealerless committee key generation (RSS / Mithril) + no-reconstruct signing
  > (BCC/CSCP + Mithril hyperball) + standard-ML-DSA-verifier output,
  > malicious-hardened; the full FIPS-204 KeyGen-distribution-equivalence proof
  > and the malicious-secure CSCP/identifiable-abort layer are labelled
  > residuals.*

**Never claimed** (`PROOF-CLAIMS.md §0`): FIPS/NIST-certified threshold ML-DSA ·
fully-malicious-secure-*proven* (mechanized) · global-1000-validator DKG. NIST
FIPS-204 standardises *single-party* ML-DSA only; Claim (A) is about the *output
bytes*, Claim (B) is *our* theorem.

### §0.1 The keygen residual — restated for v0.6.3 (the dealer is dead at keygen)

Pre-v0.6, keygen was the open half: signing was no-reconstruct, but the key was
either trusted-dealer (`DealAlgShares`) or dealerless-but-seed-reconstruct
(`dkg.go`). **v0.6.0+ closes the dealerless-keygen gap for Claim (A)** with
Mithril short Replicated Secret Sharing (RSS):

- **`MithrilRSSKeygen`** (`mithril_rss.go:133`) generates the FIPS-204 group key
  with **no trusted dealer**: each `M`-subset's short secret `(s1^(S), s2^(S)) ∈ S_η`
  is sampled by that subset's *leader* from the leader's contributed entropy
  (`mithrilSubsetSeed`, `:84`) and replicated to the subset's members; the key is
  `s1 = Σ_S s1^(S)`, `s2 = Σ_S s2^(S)`, with `‖s2‖∞ ≤ C(N,N−T+1)·η` **genuinely
  small** (it sidesteps the naive-additive `N·η` blow-up of §1.4). No party holds
  all subsets (`TestMithrilRSSDealerless`, `mithril_rss_test.go:91`); any T
  parties reconstruct via the balanced partition, fewer than T cannot.
- **The signature verifies under stock circl** for every viable committee N ≤ 6
  (`mithril_rss_test.go:70`) and T = N at n=8 / n=16 (`mithril_rss_n8_test.go:40`)
  — the **gold proof** of dealerless stock-FIPS-204 signability.

So the lineage table is now:

| Lineage | Keygen | Sign | Status |
|---|---|---|---|
| **RSS short-replicated** (`mithril_rss.go`) | **DEALERLESS** — no dealer, no party holds the whole `(s1,s2)`, `‖s2‖∞ ≤ C·η` small | quorum-reconstruct (`MithrilKey.Sign`, `:266`) **OR no-reconstruct** (`SignHyperball`, `mithril_rss_hyperball.go:780`) | **the v0.6 dealerless path; stock-circl-verifiable** |
| `s1` poly-share (`DealAlgShares`) | trusted dealer (bootstrap) | no-reconstruct (`AggregateBCCWithBlame`) | keygen **quarantined to `bootstrap_dealer_test.go`** — test/bootstrap only |
| Seed-share (`dkg.go` GF(257); `large_dkg.go` GF(q)) | dealerless ceremony, but **forms `sk` at keygen** | reconstruct-at-sign | `large_dkg.go` **quarantined** behind `//go:build legacy_trusted_dealer` |

**What is STILL a residual (the precise statement — do not round this off).** RSS
gives Claim (A): the dealerless `GroupPK` is a real FIPS-204 key whose threshold
signatures the stock verifier accepts. It does **not** by itself give Claim (B)'s
*distributional* statement: **full FIPS-204 KeyGen-distribution-equivalence** —
that the dealerless composite `GroupPK` is distributed identically to a single
honest `KeyGen`, with (i) an unbiased composite secret, (ii) hiding against `< t`
corruptions, and (iii) abort-bias resistance — needs a separate
simulation/hiding/abort-bias proof. The structural facts (no party holds the key;
`‖s2‖∞ ≤ C·η`; stock-circl-verifiable) are proven; the distributional equivalence
is **open-research** (§7 row 15). The *naive-additive byte-FIPS DKG* remains
correctly **fail-closed** (`ErrDealerlessByteFIPSUnreachable`, §1.4, §7 row 14) —
RSS is the named escape it always pointed to, not a weakening of it.

**Therefore:** SIGNING = no-reconstruct (BCC/CSCP and hyperball) +
malicious-hardened (v0.5); KEYGEN = **dealerless RSS** (no dealer, no party holds
the key), stock-FIPS-204-verifiable. The remaining (B) gap is the *distributional
equivalence proof*, not the existence of a dealerless committee key. Permissionless
dealerless *safety* is additionally carried by the **Corona** leg of the Quasar
AND-mode dual-PQ cert (`naive_additive_seta_obstruction.go:107`).

### §0.2 Consensus-native framing

Pulsar is **not** an all-`N`-sign protocol. Lux Avalanche-family subsampling
carries chain *safety*; Pulsar produces **compact post-quantum certificates over
consensus-finalised digests** — and it scales by **sampling many small dealerless
committees and accumulating confidence by repetition** (`PULSAR.md §7`), not by
one large committee. The default profile `Pulsar-HYBRID-PQ-v1` samples `m = 12`
committees of `n = 8` (`t = 7`), requiring `r = 8` legs: one-committee capture
`p = Pr[X ≥ 7], X ~ Binom(8, ⅓) ≈ 2⁻⁸·⁶`, certificate `P_fail ≈ 2⁻⁵⁹·⁸`. The DKG
below is therefore a **per-committee, per-epoch** ceremony, and the binding rules
(§3) pin each share/cert to its committee, epoch, and key.

---

## §1. Deliverable 1 — Protocol transcript spec (byte layout & ordering)

All Pulsar hashing routes through `transcript.go` (FIPS-202 / SP 800-185), now
backed by `github.com/luxfi/mlwe/transcript` (v0.6.1, byte-preserving). The two
framing primitives:

- **`cshake256(input, outLen, S)`** = cSHAKE256 with function-name `N = "Pulsar"`
  (`transcript.go:73`, `:79`). Pinning `N="Pulsar"` makes a cross-suite mix-up a
  deterministic mismatch.
- **`transcriptHash(S, parts…)`** → 48-byte digest, SP 800-185 TupleHash256-style;
  **`transcriptHash32`** is the 32-byte counterpart (`transcript.go:103`, `:116`).
  Length-prefixed parts ⇒ unambiguous boundaries.

### §1.1 Dealerless RSS keygen (`mithril_rss.go`)

Driven by one contributed 32-byte seed per party; deterministic in
`(mode, t, n, partySeeds)`. Fail-closed outside the Mithril viability bound
`2 ≤ T ≤ N ≤ 63` ∧ `τ·C(N,N−T+1)·η < γ2` (`rss.ValidateCommittee`).

```
rho            = SHAKE256( "pulsar.mithril.rss.rho.v1" ‖ partySeed_0 ‖ … )   # mithril_rss.go:99
A              = ExpandA(rho)                                                  # mithril_rss.go:163
for each M-subset S (M = N−T+1):                                              # mithril_rss.go:169
    leaderSeed = partySeeds[ leader(S) ]
    subSeed    = SHAKE256( "pulsar.mithril.rss.subset.v1" ‖ leaderSeed ‖ le64(maskS), 64 )  # :84
    (s1^(S), s2^(S)) = expandS(subSeed) ∈ S_η                                 # :173
    replicate (s1^(S), s2^(S)) to every member of S                          # :175
    s1 += s1^(S);  s2 += s2^(S)   (REDUCE mod q PER SUBSET — accumulateSubset) # :180, :122
t      = A·s1 + s2;  (t0, t1) = Power2Round(t)                               # computePublicKey :192
pub    = rho ‖ PackT1(t1);  tr = SHAKE256(pub)                               # :208–:215
```

**The v0.6.3 per-subset reduction (`accumulateSubset`, `:122`).** Every `χ_η`
coefficient is stored ≈ q ≈ 2²³ and `poly.add` is a raw uint32 add; reducing mod q
*per subset* keeps every accumulator < 2q ≪ 2³², so summing all `C(N,M)` subsets
never overflows (the wall at `C ≥ ⌊2³²/q⌋ = 512`, e.g. n=16,t=14 with
`C(16,3)=560`). Mod-q is additively homomorphic ⇒ small committees (n ≤ 8) are
byte-unchanged.

**Reconstruction** (`ReconstructKeyMaterial`, `:223`) sums each subset secret
exactly once via the balanced partition `rss.RSSRecover` — the threshold-gated act
a T-quorum performs to sign; the dealerless keygen never performs it.

### §1.2 No-reconstruct hyperball signing (`mithril_rss_hyperball.go`)

`SignHyperball(active, msg, ctx, rng, maxRounds)` (`:780`). Each active party holds
only its balanced-partition share `s1_(j)` (`partyShareS1`, `:870` — never summed
across parties); the party object is constructed from `mk.holdings[id]` alone
(`newHyperballParty`, `:261`, the structural no-reconstruct boundary). **μ** is the
FIPS-204 message representative `deriveMuCtx(tr, ctx, msg)`. Three rounds:

```
Round 1 (round1, :294):  for K=kReps slots, y_{j,k} ← uniform B(0,r1);          # sampleHyperballInBall :895
                         w_{j,k} = A·y_{j,k};  broadcast CommitW (hash) + CommitT(T_j)
Round 2 (round2 :321 / aggregateCommitments :430):
                         reveal w_{j,k};  verify vs CommitW (equivocation gate :466);
                         w_k = Σ_j w_{j,k};  c_k = H(μ ‖ packW1(HighBits(w_k)))   # boundary-clear slots only
Round 3 (round3 :333):   z_{j,k} = y_{j,k} + c_k·s1_(j);  Excess gate (hyperballExcess :966)
                         REJECTS (never reveals) if z leaves B(0,r)
Finalize (finalize :518): require all-accepted slot; z_k = Σ_j z_{j,k};
                         ‖z‖∞ < γ1−β;  w' = A·z − c·t1·2^d (PUBLIC);  h = FindHint(w', w1)
                         sigEncode(c̃, z, h);  FAIL-CLOSED VerifyCtx before emit (:613)
```

The **only** data crossing the wire (`HyperballRound{1,2,3}`, `:206`–`:226`) is
commitment hashes, the public `w_{j,k}` (recovering `y` is Module-SIS), and the
public `z_{j,k}`. No share `s1_(j)`, no mask `y`, no low-bits quantity is ever
serialised — asserted by `publicBytes()` (`:732`) and the no-leak oracle
(`TestHyperballNoReconstructStructural` `:100`, `TestHyperballMaskNeverOnWire`
`:529`).

### §1.3 No-reconstruct BCC/CEF signing (single group key, `distributed_bcc.go`)

Per-party key custody is **one** `AlgShare` — a poly-vector Shamir share of the
*expanded* `s1` (length `L`) over GF(q), `s1` only, never `s2`/`t0`/seed. One
online round over an offline nonce:

```
μ  = SHAKE256( tr ‖ 0x00 ‖ |ctx| ‖ ctx ‖ msg )       # FIPS-204 §5.4 (deriveMuCtx)
c̃ = SHAKE256( μ ‖ packW1(w1) )                        # deriveCTilde, distributed_bcc.go:586
c  = SampleInBall(c̃)
Round1 (:560):  bind NonceCert; reserve single-use material keyed on w1
Round2 (:603):  reserve nonce BEFORE the secret is touched, then
                z_i = partialLinearMap(λ_i, ĉ, y_i, s1_i)  (:645)  = λ_i·y_i + c·λ_i·s1_i
Finalize (AggregateBCCWithBlame, :875), fail-closed in order:
  1. authenticate origin (drop forged/unsigned partials, no blame against owner)  :883
  2. verify+attribute each sigma proof bound to (λ_p,c,z_p,session,nonce,party)
  3. canonical signer subset of exactly `threshold` distinct signers (CanonicalSignerSet)
  4. z = Σ z_p  (Lagrange-linear → ȳ + c·s1; s1 NEVER formed)
  5. ‖z‖∞ < γ1−β
  6. w' = A·z − c·t1·2^d (PUBLIC);  h = FindHint(w', w1)
  7. sigEncode(c̃, z, h)
```

`auth == nil` is **refused fail-closed** (`ErrOriginAuthRequired`,
`distributed_bcc.go:813`); the unauthenticated path is reachable only via the
explicit `UnauthenticatedAggregation` opt-out (`:836`). No share, sk, or seed
enters `AggregateBCC`'s parameter list — the load-bearing no-reconstruct boundary.

---

## §2. Deliverable 2 — Domain separators (every DST, from code)

All tags are version-pinned; rotating one invalidates every vector pinned at it.
Three encodings coexist, all the *implemented reality*:
**`PULSAR-…-V1`** (cSHAKE customisation strings, `transcript.go`),
**`PULSAR/…/v1`** (literal prefixes, ledger/auth), and
**`pulsar.mithril.*.v1`** (the RSS/hyperball SHAKE-prefix tags). The
certificate-layer `pulsar:v1:*` namespace (`PULSAR.md §14`) is the *proposed*
consensus binding, kept distinct on purpose.

### §2.1 cSHAKE256 customisation tags (`transcript.go:40`–`:66`)

| Constant | Value | Purpose | Site |
|---|---|---|---|
| `functionName` | `Pulsar` | cSHAKE `N` param (all calls) | `transcript.go:73` |
| `tagDKGCommit` | `PULSAR-DKG-COMMIT-V1` | DKG Round-2 digest + committeeRoot | `transcript.go:40` |
| `tagDKGTranscript` | `PULSAR-DKG-TRANSCRIPT-V1` | DKG transcript / finalization hash | `transcript.go:41` |
| `tagSignR1` | `PULSAR-SIGN-R1-V1` | Round-1 binding | `transcript.go:42` |
| `tagSignR2` | *(reserved, undefined)* | Round-2 MAC (intentionally undefined so a stale rebase fails to compile) | `transcript.go:44` |
| `tagReshareCommit` | `PULSAR-RESHARE-COMMIT-V1` | reshare commit | `transcript.go:61` |
| `tagExpandB` | `PULSAR-EXPANDB-V1` | matrix `B` expansion | `transcript.go:64` |
| `tagComplaint` | `PULSAR-COMPLAINT-V1` | complaint hashing | `transcript.go:65` |
| `tagSeedShare` | `PULSAR-SEED-SHARE-V1` | Shamir coeff stream + master-seed mix | `transcript.go:66` |

### §2.2 RSS / hyperball SHAKE-prefix DSTs

| String | Purpose | Site |
|---|---|---|
| `pulsar.mithril.rss.rho.v1` | RSS joint public seed `rho` | `mithril_rss.go:101` |
| `pulsar.mithril.rss.subset.v1` | RSS per-subset sampling seed (leader entropy ‖ mask) | `mithril_rss.go:86` |
| `pulsar.mithril.hyperball.nonce.v1` | hyperball per-round, per-slot nonce seed | `mithril_rss_hyperball.go:993` |
| `pulsar.mithril.hyperball.commitW.v1` | hyperball `w`-commitment binding (anti-equivocation) | `mithril_rss_hyperball.go:1006` |
| `pulsar.mithril.hyperball.commitT.v1` | hyperball `T_j = A·s1_(j)` commitment (blame-only) | `mithril_rss_hyperball.go:1021` |
| `pulsar.mithril.hyperball.sid.v1` | hyperball session id = H(pub ‖ active ‖ μ) | `mithril_rss_hyperball.go:1032` |

### §2.3 Literal-prefix DSTs (`PULSAR/…/v1` and friends)

| String | Purpose | Site |
|---|---|---|
| `PULSAR-DKG-DEALER-V1` | seed-share DKG Shamir coeff-stream key material | `dkg.go:225` |
| `PULSAR-DKG-ENCAPSEED-V1` | per-recipient ML-KEM-768 encap seed | `dkg.go:268` |
| `PULSAR-COMMITTEE-V1` | committee-root prefix | `dkg.go:516` |
| `PULSAR/nonce-single-use/v1` | nonce dedup key (`w1` alone) | `nonce_ledger.go:395` |
| `PULSAR/share-ledger-identity/v1` | committee-independent share identity | `nonce_ledger.go:303` |
| `PULSAR/committee-id/v1` | committee id = H(jointPKID ‖ quorum) | `nonce_ledger.go:407` |
| `PULSAR/nonce-binding-digest/v1` | `(ctx,msg)` digest in a reservation | `nonce_ledger.go:423` |
| `PULSAR-BCC-CEF/joint-pk-id/v1` | stable group-PK id (`JointPKID`) | `distributed_bcc.go:1096` |
| `PULSAR/protocol-msg/v1` | authenticated-protocol-message TBS | `protocol_auth.go:61` |
| `PULSAR-TESTRAND-V1` | deterministic test RNG (tests only) | `dkg_test.go` |

---

## §3. Deliverable 3 — Participant / key-epoch binding rules

A share or certificate is bound to its context by the following identities. Each
row states **what is hashed**, the **site**, and — honestly — **where binding is
NOT yet at the kernel** (cert-layer or implicit).

| Bound to | Mechanism (what is hashed) | Site | Honest note |
|---|---|---|---|
| **group / key (RSS)** | `rho = SHAKE256("pulsar.mithril.rss.rho.v1" ‖ Σ partySeeds)`; `pub = rho ‖ PackT1(t1)`; `tr = SHAKE256(pub)` | `mithril_rss.go:99`, `:208`–`:215` | the dealerless key-identity root |
| **group / key (BCC)** | `JointPKID = SHAKE256("PULSAR-BCC-CEF/joint-pk-id/v1" ‖ mode ‖ pub.Bytes)` | `distributed_bcc.go:1096` | the BCC key-identity root |
| **committee / participant set (RSS)** | per-subset secret keyed by `(leaderSeed, maskS)`; holdings indexed by party; session id `= H(pub ‖ active ‖ μ)` | `mithril_rss.go:84`, `mithril_rss_hyperball.go:1032` | binds the run to (pub, exact active set, message) |
| **participant set (BCC)** | `committeeID = SHAKE256("PULSAR/committee-id/v1" ‖ JointPKID ‖ sorted quorum)`; DKG: `committeeRoot` | `nonce_ledger.go`; `dkg.go:516` | binds the exact sorted quorum + key |
| **threshold `t`** | enforced by `CanonicalSignerSet(valid, threshold)` (BCC) / `validateActive` (hyperball, `:1054`) — exactly `t` distinct signers | `distributed_bcc.go`; `mithril_rss_hyperball.go:1054` | `t` is *enforced* at aggregation but not hashed into the committee id — bind `t` at the cert layer (`PULSAR.md §11`) |
| **policy id** | `Policy [32]byte` in `NonceBinding`, canonical-encoded | `nonce_ledger.go` | auditable domain tag (block-cert vs warp-msg, …) |
| **message** | `μ = deriveMuCtx(tr, ctx, msg)` folded into `c̃`/session id; BCC reservation `Digest = SHAKE256("PULSAR/nonce-binding-digest/v1" ‖ mode ‖ μ)` | `mithril_rss_hyperball.go:799`; `nonce_ledger.go` | binds the run to exactly what is signed |
| **chain / network** | via FIPS-204 `ctx` string + `Policy` | `distributed_bcc.go:586` | full `chain_id` + `committee_plan_hash` binding is the **cert-layer target** (`PULSAR.md §8`, §13) |

### §3.1 Nonce single-use binding (anti key-recovery)
- **BCC.** Dedup key `nonceMaterialKey(w1) = SHAKE256("PULSAR/nonce-single-use/v1"
  ‖ w1)` — **`w1` ALONE** (`nonce_ledger.go:395`): dropping the label defeats
  relabel-bypass; dropping `committeeID` closes cross-committee reuse. Reuse ⇒
  `ErrNonceReused` (`:80`), fail-closed, before any secret is emitted. Defends
  against `z_A − z_B = (c_A − c_B)·s1`.
- **Hyperball.** Per-round, per-slot nonce seed
  `hyperballNonceSeed(roundEntropy, sid, id, slot)` (`mithril_rss_hyperball.go:991`)
  is fresh per round (distinct entropy ⇒ distinct mask) and deterministic within a
  round (so the Round-1 commitment binds the mask before the challenge is known).
  `TestHyperballNonceReuseFatal` (`:419`) proves reuse would recover the share and
  that the derivation prevents it.

### §3.2 Authenticated-message slot binding
`ProtocolMessageTBS(author, ctx, payloadDigest)` (`protocol_auth.go:59`) is
SP 800-185-framed over `("PULSAR/protocol-msg/v1", author, be64(epoch), sessionID,
nonceID, {round}, payloadDigest)`. Equivocation is per `(Author, Epoch, SessionID,
Round)`; two valid signatures on distinct payloads for one slot is non-repudiable
(`DetectEquivocation`, `protocol_auth.go:101`).

---

## §4. Deliverable 4 — Share-commitment format (with the honest BDLOP flag)

Three distinct "commitment" notions exist; do not conflate them.

### §4.1 RSS replicated-share commitment (implemented) — the dealerless key root
The RSS key's binding is the published FIPS-204 public key itself: `pub = rho ‖
PackT1(t1)` with `t1 = HighBits(A·s1 + s2)` (`mithril_rss.go:192`–`:215`). Each
subset secret is a short `χ_η` value keyed by `(leaderSeed, maskS)`; the
**dealerless guarantee** is structural (no party holds all subsets,
`TestMithrilRSSDealerless` `mithril_rss_test.go:91`), and the **norm bound**
`‖s2‖∞ ≤ C·η` keeps it stock-FIPS-204-signable. This is **not** a hiding
per-coefficient lattice commitment; it is the public-key root + structural
replication.

### §4.2 Hyperball `w`/`T` commitments (implemented) — binding, not hiding
- `CommitW = hyperballCommitW(sid, id, slot, μ, w_{j,k})` (`:1004`): a SHAKE
  hash-commitment binding each per-slot `w` so a rushing adversary cannot choose
  `w` after seeing others (verified at `:466`).
- `CommitT = hyperballCommitT(sid, id, T_j)` (`:1019`): commitment to the
  share-verification value `T_j = A·s1_(j)`, revealed **only on blame** — in the
  honest path `T_j` is never revealed, because `Σ_active T_j = A·s1 = t − s2` would
  leak `s2`.

### §4.3 BCC sign-side share-commitment (the BDLOP plug point) — **nil today, flagged**
`AlgSetup.s1ShareCommit` holds the per-party hiding commitment to the dealt
`s1`-share for identifiable-abort binding. **It is `nil` today**; the single source
of truth read by both prover and verifier is `shareCommitmentsFor` (returns
`(nil, nil)`, `share_commit.go:94`–`:96`). The intended format is BDLOP
(`ia.cr/2017/1235` / Ajtai) under a **separate** public matrix `B` hiding under
M-LWE (`Com_s_i = B·r_s_i + embed(s1_i)`, `share_commit.go:42`).

**Honest consequence (the residual).** Because `s1ShareCommit` is nil, a
**valid-sigma but WRONG-`z`** partial is **not yet attributable** — it is bounded
to a **liveness** fault (never forgery, never leak: the wrong aggregate fails
FIPS-204 verify and nothing secret crosses the wire), marked by
`ErrIdentifiableAbortResidual` (`share_commit.go:73`). The hyperball signer has the
**same** residual at `blameSlot` (`mithril_rss_hyperball.go:633`–`637`): a share
inconsistent with keygen but self-consistent with its own equivocated `T_j` passes
the per-party check, is caught by the fail-closed release gate (no bad signature
emitted), but is not pinpointed.

---

## §5. Deliverable 5 — Valid / invalid DKG (and signing) test vectors

The structured behavioral vectors live in **`vectors/dkg-proof-boundary.json`**.
Each names the scenario, the layer, the expected outcome, the **exact code
error/blame constant**, and the `file:line` that enforces it. They are *spec-level
state vectors* — distinct from the byte-level wire KATs (§6). Summary:

**Positive (accept):**
- `keygen/rss-dealerless-stock-circl` — dealerless RSS key signs under unmodified
  circl `mldsa65.Verify` for all 15 committees N ≤ 6
  (`TestMithrilRSSStockCirclVerify`, `mithril_rss_test.go:38`,`:70`) and T=N at
  n=8/n=16 (`mithril_rss_n8_test.go:40`). **The gold proof of dealerless
  stock-FIPS-204 signability.**
- `keygen/rss-dealerless-structural` — no party holds all subsets; no
  `(T−1)`-coalition covers all subsets (`TestMithrilRSSDealerless`,
  `mithril_rss_test.go:91`).
- `sign/hyperball-no-reconstruct` — the 3-round hyperball signature over the RSS
  key verifies under stock circl with NO key reconstruction; AST + transcript
  oracles prove no `s1`/`s2`/`y` ever forms (`TestHyperballStockCirclVerify`
  `mithril_rss_hyperball_test.go:41`; `TestHyperballNoReconstructStructural` `:100`).
- `sign/circl-roundtrip` — no-reconstruct BCC/CEF `(c̃,z,h)` accepted by circl
  (`TestBCCSignRoundTripVerifiesCIRCL`, `bcc_sign_test.go:86`; no-leak oracle
  `:217`).
- `dkg/seed-equivalence` (legacy seed-share lineage) — `GroupPK ==
  KeyFromSeed(masterSeed).Pub`, reconstructed-key sig verifies under FIPS-204
  (`TestDKG_ProducesValidPubkey_VerifiableSign`, `dkg_test.go:147`,`:206`).

**Negative (reject / blame), each grounded in a real constant:**
- `keygen/rss-bad-committee` (non-viable `(T,N)`: norm-blown or structural) →
  `rss.ValidateCommittee` error (`TestMithrilRSSRejectsBadCommittee`,
  `mithril_rss_test.go:177`).
- `sign/hyperball-sub-threshold` (too few / too many / unsorted / duplicate /
  out-of-range active) → `ErrHyperballActive` / `validateActive`
  (`TestHyperballSubThresholdFailsClosed`, `mithril_rss_hyperball_test.go:298`).
- `sign/hyperball-biased-partial` → no slot verifies (fail-closed release gate);
  `blameSlot` pinpoints the culprit leak-free
  (`TestHyperballBiasedPartialCaughtAndBlamed`, `:329`).
- `sign/hyperball-equivocation` (party changes `w` between rounds) → binding
  mismatch (`TestHyperballEquivocationCaught`, `:404`,
  `aggregateCommitments` `:466`).
- `sign/hyperball-mask-on-wire` (the secret mask `y` must not appear on the wire)
  → asserted absent (`TestHyperballMaskNeverOnWire`, `:529`).
- `sign/nonce-reuse` (BCC) → `ErrNonceReused` (`nonce_ledger.go:80`).
- `sign/session-mismatch` → `BlameSessionMismatch` (`blame.go:38`).
- `sign/duplicate-partyid` → `BlameDuplicatePartyID` (`blame.go:34`).
- `sign/unknown-party` → `BlameUnknownParty` (`blame.go:36`).
- `sign/malformed-partial` → `BlameMalformed` (`blame.go:32`).
- `sign/invalid-proof` → `BlameProofInvalid` (`blame.go:40`).
- `sign/forged-victim-slot` → dropped pre-attribution, victim **not** blamed
  (`distributed_bcc.go:883`).
- `sign/valid-sigma-wrong-z` → liveness fault, not yet attributable
  (`ErrIdentifiableAbortResidual`, `share_commit.go:73`).
- `keygen/naive-additive-byte-fips` → `ErrDealerlessByteFIPSUnreachable` for any
  committee `parties ≥ 2` (`naive_additive_seta_obstruction.go:152`,`:242`). RSS is
  the named escape; the naive additive lift stays correctly fail-closed.
- `dkg/equivocation`, `dkg/bad-share`, `dkg/missing-participant`,
  `dkg/node-not-in-committee`, `dkg/duplicate-committee`, `dkg/empty-committee`
  (legacy seed-share lineage) → `ComplaintEquivocation` / `ComplaintBadDelivery` /
  `ErrTooFew*` / `ErrNotInCommittee` / `ErrCommitteeDuplicate` /
  `ErrCommitteeEmpty` (`dkg.go`, `types.go:285`,`:290`).

---

## §6. Deliverable 6 — Cross-version KATs (old wire compatibility)

The committed wire KATs are the **cross-version compatibility suite**: vectors
generated by an earlier version, replayed every CI run; drift = gate failure.
Runner `kat_test.go`, reads `vectors/*.json`. The v0.6.1/.2 mlwe de-dup was
**byte-preserving** — these KATs replay identically after the refactor.

| Vector file | Entries | Pins | Replay test |
|---|---|---|---|
| `vectors/keygen.json` | 9 | `seed → public_key, private_key` | `TestKAT_Keygen_Replay` (`kat_test.go:50`) |
| `vectors/sign.json` | 9 | `seed,msg,ctx → signature` | `TestKAT_Sign_Replay` (`kat_test.go:91`) |
| `vectors/verify.json` | 6 | `public_key,msg,signature → accept` | `TestKAT_Verify_Replay` (`kat_test.go:127`) |
| `vectors/threshold-sign.json` | 4 | `n,t,msg,public_key → signature` (Class N1 interchangeability) | `TestKAT_ThresholdSign_Replay` (`kat_test.go:159`) |
| `vectors/dkg.json` | 3 | DKG replay | `TestKAT_DKG_Replay` (`kat_test.go:197`) |

`threshold-sign.json[0]` (`Pulsar-65`, `n=3, t=2`) pins a *threshold* signature
that the **single-party** verifier accepts — the wire-level statement of Claim (A)
across versions.

**Cross-implementation KAT.** `TestDKGVSS_RingMLDSA65_ExpandABinding_KAT`
(`dkg_vss_kat_test.go:104`) anchors the shared `luxfi/dkg` ring against pulsar's own
FIPS-204 arithmetic: `A = ExpandA(rho)` round-trips with no spurious Montgomery
factor and the dkg ring recomputes `t1 = Power2Round(A·s1+s2)` **byte-identical to
circl**. Its header (`:30`–`:35`) restates the historical residual honestly: the
*vss* no-reconstruct group key `T = A·s1 + B·u` (large `s2 = B·u`) is not directly
BCC-signable — which is exactly why **RSS** (small `s2 = Σ χ_η`), not vss, is the
dealerless keygen that beats the wall.

---

## §7. Deliverable 7 — Proof checklist (test → security property)

Assurance tags are the `PROOF-CLAIMS.md` vocabulary (machine-checked ·
sound-by-reduction · interop-tested · test-proven · fail-closed-pending-review ·
open-research). The split is always **(A) verifier-compat** vs **(B) Lux
construction**.

| # | Security property | Test / artifact (file:line) | Claim | Assurance |
|---|---|---|---|---|
| 1 | **Standard-verifier compat — no-reconstruct BCC** — `(c̃,z,h)` accepted by circl + negatives | `TestBCCSignRoundTripVerifiesCIRCL` `bcc_sign_test.go:86` | **A** | **interop-tested** |
| 2 | **Standard-verifier compat — dealerless RSS key** — stock circl accepts (all N ≤ 6; T=N n=8/n=16) | `TestMithrilRSSStockCirclVerify` `mithril_rss_test.go:38`; `TestMithrilRSS_LargeN_StockCircl` `mithril_rss_n8_test.go:16` | **A** | **interop-tested** |
| 3 | **Standard-verifier compat — no-reconstruct hyperball over RSS** | `TestHyperballStockCirclVerify` `mithril_rss_hyperball_test.go:41` | **A** | **interop-tested** |
| 4 | **Dealerless keygen (structural)** — no party holds all subsets; no `(T−1)` covers all | `TestMithrilRSSDealerless` `mithril_rss_test.go:91` | B | test-proven |
| 5 | **Secrecy / no-reconstruct (hyperball)** — no `s1`/`s2`/`y`/`w0`/`sk` forms; no `ReconstructKeyMaterial` call; mask never on wire | `TestHyperballNoReconstructStructural` `:100`; `TestHyperballMaskNeverOnWire` `:529` | B | test-proven (AST + transcript oracle) |
| 6 | **Secrecy / no-reconstruct (BCC)** — no `s1`/seed/`sk`/`c·s2`/`c·t0`/`w` forms | `assertBCCTranscriptNoLeak` `bcc_sign_test.go:217`; `gate2_reachability_test.go`; Lean `Crypto.Pulsar.NoLeakAggregate` | B | machine-checked (Lean core) + test-proven; reduction sound-by-reduction (M-LWE/M-SIS) |
| 7 | **Any-quorum consistency** — every T-quorum reconstructs the identical key | `TestMithrilRSSAnyQuorumSameKey` `mithril_rss_test.go:122` | B | test-proven |
| 8 | **Binding — domain separation** — per-purpose DSTs, no reuse | §2 tables; `transcript.go:40`–`:66`; RSS/hyperball prefixes | B | test-proven (KAT-pinned) |
| 9 | **Binding — equivocation** — one author/commitment per slot | `TestHyperballEquivocationCaught` `:404`; `DetectEquivocation` `protocol_auth.go:101`; `TestDKG_Equivocation_Detected` `dkg_test.go:111` | B | test-proven |
| 10 | **Robustness / identifiable abort + fail-closed** — sub-threshold/biased/malformed rejected & (where possible) attributed | `TestHyperballSubThresholdFailsClosed` `:298`, `TestHyperballBiasedPartialCaughtAndBlamed` `:329`; `AggregateBCCWithBlame` `distributed_bcc.go:875`; `blame_gate_test.go` | B | test-proven (semi-honest) |
| 11 | **Robustness residual** — valid-sigma wrong-`z` / equivocated-keygen-share attribution | `share_commit.go:73` `ErrIdentifiableAbortResidual`; `mithril_rss_hyperball.go:633` | B | **fail-closed-pending-review** (BDLOP) |
| 12 | **Unforgeability — nonce single-use** — defeats `(c_A−c_B)·s1` recovery | BCC `nonce_ledger.go:80`; hyperball `TestHyperballNonceReuseFatal` `:419` | B | test-proven |
| 13 | **Unforgeability — base EUF-CMA** — output is a standard ML-DSA sig | inherits ML-DSA EUF-CMA under M-LWE/M-SIS (output bytes = FIPS-204) | A→B | sound-by-reduction (inherited) |
| 14 | **Authenticated origin** — forged victim-slot partial cannot frame/exclude | `distributed_bcc.go:883`; `ErrOriginAuthRequired` `:813` | B | test-proven |
| 15 | **Cross-version wire compat** — committed KATs replay byte-identical (incl. post-mlwe-dedup) | `kat_test.go:50`,`:91`,`:127`,`:159`,`:197` vs `vectors/*.json` | A | interop-tested |
| 16 | **Cross-impl arithmetic** — `luxfi/dkg` ring reproduces FIPS-204 `t1` | `TestDKGVSS_RingMLDSA65_ExpandABinding_KAT` `dkg_vss_kat_test.go:104` | A | interop-tested |
| 17 | **Keygen — naive-additive byte-FIPS obstruction (correctly fail-closed)** | `assessDealerlessFIPS` `naive_additive_seta_obstruction.go:196`; `DealerlessMLDSADKG` `:242` → `ErrDealerlessByteFIPSUnreachable` `:152` | B | sound-by-reduction (parameter-derived) |
| 18 | **Keygen residual — FIPS-204 KeyGen-distribution-equivalence** (unbiased composite secret, hiding vs `<t`, abort-bias) for the RSS key | **not proven**; structural facts + stock-circl-verifiability only (rows 2,4) | B | **open-research** |

### §7.1 What the checklist deliberately does NOT claim
Rows 11, 18 are **residuals**, fail-closed and tracked, not silently weakened. No
row asserts FIPS/NIST-certified threshold ML-DSA, fully-malicious-secure-*proven*,
or global-`N`-validator DKG (`PROOF-CLAIMS.md §0`). Claim (A) (rows 1, 2, 3, 13,
15, 16) is the *proven* verifier-compatibility statement; Claim (B) (the rest) is
the *scoped* Lux construction. The keygen story for v0.6.3: KEYGEN is **dealerless
RSS** (no dealer; no party holds the key; stock-FIPS-204-verifiable — rows 2, 4),
and the remaining (B) gap is the *distributional* KeyGen-equivalence proof (row
18), not the existence of a dealerless committee key.
