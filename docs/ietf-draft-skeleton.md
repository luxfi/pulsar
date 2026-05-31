# Threshold ML-DSA for Distributed Signing and Blockchain Applications

```
Internet-Draft                                          Lux Industries
Intended status: Informational                         Z. Kelling, Ed.
Expires: 18 November 2026                                   2026-05-18

draft-hanzo-pulsar-threshold-mldsa-00
```

## Abstract

This document specifies Pulsar, a public-DKG threshold profile for
the FIPS 204 Module-Lattice-Based Digital Signature Algorithm
(ML-DSA). Pulsar produces signatures byte-identical to single-party
FIPS 204 ML-DSA signatures, accepted without modification by any
FIPS 204 conformant verifier. The protocol consists of a public
distributed key generation (DKG) phase with Pedersen verifiable
secret sharing, a two-round threshold signing protocol, optional
proactive resharing preserving the group public key, and an
identifiable abort protocol with third-party-verifiable evidence
suitable for on-chain slashing. The construction is part of the
**Hanzo PQ Threshold Suite**.

## Status of This Memo

This Internet-Draft is submitted in full conformance with the
provisions of BCP 78 and BCP 79.

Internet-Drafts are working documents of the Internet Engineering
Task Force (IETF). Note that other groups may also distribute
working documents as Internet-Drafts. The list of current
Internet-Drafts is at <https://datatracker.ietf.org/drafts/current/>.

Internet-Drafts are draft documents valid for a maximum of six
months and may be updated, replaced, or obsoleted by other
documents at any time. It is inappropriate to use Internet-Drafts
as reference material or to cite them other than as "work in
progress."

## Copyright Notice

Copyright (c) 2026 IETF Trust and the persons identified as the
document authors. All rights reserved.

This document is subject to BCP 78 and the IETF Trust's Legal
Provisions Relating to IETF Documents
(<https://trustee.ietf.org/license-info>) in effect on the date of
publication of this document.

---

## Table of Contents

1. Introduction
2. Conventions and Terminology
3. Parameter Sets
4. Threat Model
5. Security Goals
6. Public Distributed Key Generation (DKG)
7. Threshold Signing
8. Verification
9. Proactive Resharing
10. Identifiable Abort and Slashing Evidence
11. Transcript Construction and Domain Separation
12. Wire Formats
13. Public-Chain Deployment Profile
14. Test Vectors
15. Security Considerations
16. Implementation Considerations
17. Known Limitations
18. IANA Considerations
19. References
Appendix A. Worked Example
Appendix B. Conformance Test Plan
Author's Address

---

## 1. Introduction

### 1.1 Motivation

Blockchain validator sets, certificate-authority back-ends,
treasury custody systems, and any setting where a single
signing-key custodian is unacceptable benefit from threshold
signing. This document specifies a threshold-signing protocol for
the NIST-standardized post-quantum signature algorithm ML-DSA
(FIPS 204 [FIPS204]) such that:

- No single party holds the centralized signing key at any time;
- Any t-of-n quorum can produce a valid signature;
- The signature byte string is bit-identical to a single-party
  FIPS 204 ML-DSA signature, and verifies under any unmodified
  FIPS 204 conformant verifier;
- A public DKG produces the group public key with no trusted dealer;
- Identifiable abort with third-party-verifiable evidence enables
  on-chain slashing of malicious participants.

### 1.2 Position in the Hanzo PQ Threshold Suite

| Tier | Construction | This document |
|---|---|---|
| Tier 1 | Pulsar — Public-DKG Threshold ML-DSA | **Specified here.** |
| Tier 2 | SLH-DSA single-party compatibility | Out of scope — use FIPS 205 directly. |
| Tier 3 | Magnetar — Public-DKG MPC Threshold SLH-DSA | Research profile; separate draft. |

### 1.3 Relationship to FIPS 204

This document specifies a threshold protocol that PRODUCES a FIPS
204 ML-DSA signature. It does NOT modify the FIPS 204 algorithm.
Verifiers conforming to FIPS 204 verify Pulsar signatures without
modification.

### 1.4 Requirements Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in
this document are to be interpreted as described in BCP 14
[RFC2119] [RFC8174] when, and only when, they appear in all
capitals.

## 2. Conventions and Terminology

### 2.1 Mathematical notation

- `Z_q` denotes the integers modulo q, where q = 8380417 (FIPS 204).
- `R_q = Z_q[X]/(X^256 + 1)` is the polynomial ring used by ML-DSA.
- `R_q^k` and `R_q^l` denote polynomial-vector spaces.
- `f.degree` denotes the degree of polynomial `f`.
- `f.eval(x)` denotes evaluation of polynomial `f` at point `x`.
- `||v||∞` is the infinity-norm (maximum absolute coefficient).
- `+`, `·` on R_q elements / vectors are the ring/scalar
  operations defined in FIPS 204 §3.

### 2.2 Protocol terminology

- **Party**: a single computing entity participating in the
  threshold protocol.
- **Party index**: an integer `i ∈ Z_q \ {0}` uniquely identifying
  a party.
- **Quorum** `Q`: a subset of parties of size at least `t`.
- **Threshold** `t`: the minimum number of parties required to
  produce a signature.
- **Total parties** `n`: the number of parties in the full
  committee.
- **Share** `s_i`: party i's secret share, encoded as a R_q^l
  polynomial vector matching the FIPS 204 secret-key `s_1`
  component.
- **Group public key** `pk`: the shared FIPS 204 public key
  produced by the DKG; identical for all parties; verifiable by
  any standard verifier.
- **Sharing polynomial** `f`: a polynomial in R_q^l[X] of degree
  `t − 1` such that `f.eval(0)` is the implicit centralized
  secret and `f.eval(i)` is party i's share for each party index
  i ∈ Q.
- **Session identifier** `sid`: a 32-byte cryptographic nonce
  binding a signing session against replay; see §11.
- **κ-counter**: the FIPS 204 §6.2 rejection-loop attempt counter,
  shared across all parties in a signing round.
- **Lagrange coefficient at zero** `λ_i^Q`: the standard
  Lagrange-interpolation weight for party `i` in quorum `Q`,
  computed in Z_q.

## 3. Parameter Sets

This document specifies three parameter sets, derived from FIPS 204
§4 Table 1:

| Set | NIST Category | t typical | n typical | pk bytes | sk_i bytes | sig bytes |
|---|---|---|---|---|---|---|
| PULSAR-THRESHOLD-ML-DSA-44 | 2 | 2 | 3 | 1312 | 2616 | 2420 |
| PULSAR-THRESHOLD-ML-DSA-65 | 3 (RECOMMENDED) | 3 | 5 | 1952 | 4088 | 3309 |
| PULSAR-THRESHOLD-ML-DSA-87 | 5 | 5 | 7 | 2592 | 4952 | 4627 |

The `sk_i` size includes:
- 32 bytes for the FIPS 204 ρ matrix seed (public);
- 32 bytes for the FIPS 204 K randomness seed (per-party);
- 32 bytes for the FIPS 204 tr public-key hash (public);
- The `s_1` share component as R_q^l polynomial vector (per-party);
- The `s_2` share component as R_q^k polynomial vector (per-party);
- The `t_0` share component as R_q^k polynomial vector (public);
- A 24-byte threshold-protocol metadata block (party index,
  threshold, total parties).

Implementations MUST support PULSAR-THRESHOLD-ML-DSA-65.
Implementations SHOULD support PULSAR-THRESHOLD-ML-DSA-44 and
PULSAR-THRESHOLD-ML-DSA-87.

The choice of `(t, n)` is an application-level parameter
constrained by `1 ≤ t ≤ n` and `t < q`. Typical deployments use
`t = ⌈2n/3⌉` (BFT-style) or `t = ⌈n/2⌉ + 1` (honest-majority).

## 4. Threat Model

### 4.1 Adversary capabilities

The adversary `A`:

- **Statically corrupts** at most `t − 1` parties before protocol
  start. Adaptive corruption is OUT OF SCOPE for this draft.
- **Sees the full public transcript** of every DKG, signing, and
  resharing session (including all broadcast messages, commitments,
  challenges, and abort evidence).
- **Is rushing**: in each round, A observes honest parties'
  messages before sending its own.
- **Is Byzantine** with respect to the corrupted parties: they may
  send arbitrary messages, withhold messages, equivocate, or
  collude.
- **Cannot break FIPS 204 ML-DSA hardness** (M-LWE / M-SIS); this
  is an assumed-hardness setting per FIPS 204 [FIPS204].
- **Cannot break the underlying SHAKE128/SHAKE256 collision /
  preimage resistance** (FIPS 202 [FIPS202]).

### 4.2 Network model

- **Synchronous**: a known upper bound `Δ` on inter-party message
  delivery is assumed. The protocol aborts and triggers blame on
  `Δ`-timeout.
- **Authenticated channels**: each party has a long-term identity
  key pair; all per-party messages are signed under that key.
  Authentication outside the ML-DSA primitive is not specified
  here (any post-quantum signature scheme suffices; Ed25519 +
  ML-DSA hybrid is RECOMMENDED).

### 4.3 Trust assumptions

- **Honest-quorum assumption**: at most `t − 1` parties are
  corrupted at any time during the lifecycle of a single shared
  key (across DKG → many signing sessions → optional reshares).
- **Public-coin DKG**: the DKG uses public randomness (no trusted
  setup); implementations bind a publicly-verifiable randomness
  beacon (chain block hash, drand round, or commit-reveal
  protocol) as the DKG nonce contribution.

## 5. Security Goals

### 5.1 Threshold unforgeability (EUF-CMA-Threshold)

For any PPT adversary `A` corrupting at most `t − 1` parties and
making at most `Q_sign` queries to an honest-quorum signing oracle
on chosen messages, `A`'s probability of producing a valid
signature `σ*` on a previously-unqueried message `M*` under the
group public key `pk` is at most the standard ML-DSA EUF-CMA
advantage bound for `Q_sign + 1` queries.

This is a tight reduction to FIPS 204 ML-DSA's underlying EUF-CMA
property, assuming an honest DKG output. The DKG soundness +
threshold-aggregation correctness implies that an `A`-controlled
quorum's view of the protocol is computationally indistinguishable
from a centralized signing oracle's view.

### 5.2 Output interchangeability (Class N1, NIST MPTC)

For every signature `σ` produced by an honest-quorum Pulsar
execution on inputs `(M, ctx)`, `σ` is bit-identical to a
signature produced by single-party FIPS 204 ML-DSA Sign on the
implicit centralized secret `f.eval(0)` reconstructed from the
quorum's shares. Any FIPS 204 conformant verifier accepts `σ`
without modification.

This is the load-bearing operational property: deployed verifiers
need no Pulsar-specific code path.

### 5.3 Public-key preservation across resharing (Class N4, NIST MPTC)

The proactive-resharing protocol (§9) produces new per-party
shares `s_i'` such that the implicit centralized secret
`f'.eval(0)` is identical to `f.eval(0)`. The group public key is
preserved across reshare boundaries — committee membership rotates,
but the long-lived public identity does not.

### 5.4 Identifiable abort

If the protocol aborts during a signing round, the abort-evidence
record (§10) is sufficient for any third party with only the
public transcript to identify the deviating party. Honest parties
are not falsely accused (sound). The protocol does NOT guarantee
asynchronous identifiable abort under network partition — see §17.

### 5.5 Robustness

If at least `t` honest parties complete the protocol within `Δ`,
they produce a valid signature with overwhelming probability
(modulo FIPS 204's rejection-sampling tail, which terminates in
expected ≤ 256 / (1 − (3/4)^256) ≈ 256 attempts).

## 6. Public Distributed Key Generation (DKG)

### 6.1 Overview

The DKG produces:

- A FIPS 204-format group public key `pk = (ρ, t_1)` (~1952 bytes
  for ML-DSA-65);
- Per-party secret shares `(s_{1,i}, s_{2,i})` for i = 1..n such
  that:
  - Any `t`-subset Q reconstructs the implicit centralized secret
    `s_1 = f.eval(0)` via Lagrange interpolation at zero;
  - The public key `pk` is the FIPS 204 derived public key of the
    implicit `s_1`;
  - The DKG transcript is publicly verifiable: any third party can
    confirm the DKG ran honestly.

### 6.2 Setup

All parties have:
- A common ciphersuite identifier (e.g., `PULSAR-THRESHOLD-ML-DSA-65`).
- A common session identifier `sid_dkg` (32 bytes, derived from a
  public randomness beacon).
- A common (`n`, `t`) parameter pair.
- A list of party identities `{ID_1, ..., ID_n}` with corresponding
  long-term authentication public keys.

### 6.3 Round 1 — commitment

Each party `i ∈ {1, ..., n}`:

1. Samples a sharing polynomial `f_i ∈ R_q^l[X]` of degree `t − 1`
   uniformly at random:
   ```
   f_i(X) = f_i^(0) + f_i^(1) · X + ... + f_i^(t−1) · X^(t−1)
   ```
   where each `f_i^(j) ∈ R_q^l` is sampled uniformly.

2. Computes Pedersen-style commitments to each coefficient
   `f_i^(j)`:
   ```
   C_i^(j) = G^(f_i^(j)) · H^(r_i^(j))
   ```
   where `G, H` are public R_q^l generators (derived from `sid_dkg`),
   and `r_i^(j) ∈ R_q^l` is a fresh blinding factor.

3. Broadcasts `{C_i^(0), C_i^(1), ..., C_i^(t−1)}` to all parties
   over authenticated channels.

4. Computes per-party share encryptions `enc_{i→j}(f_i.eval(j))`
   for each j ∈ {1, ..., n} \ {i} using each recipient's long-term
   encryption public key (HPKE [RFC9180] with a PQ-safe KEM such
   as ML-KEM-768 [FIPS203] is RECOMMENDED). Sends encrypted shares
   over authenticated channels.

### 6.4 Round 2 — verification and complaint

Each party `j`:

1. Decrypts each `enc_{i→j}(f_i.eval(j))` it received.

2. For each `i ≠ j`, verifies the share against the public
   commitments:
   ```
   G^(f_i.eval(j)) · H^(r_i.eval(j)) =? Π_{k=0}^{t−1} (C_i^(k))^(j^k)
   ```

3. If verification fails for some i, broadcasts a `Complaint(i, j)`
   message including the decryption transcript proof (HPKE
   open-then-prove construction).

4. Each party `i` accused by a complaint either:
   - Reveals the correct share publicly (allowing all parties to
     accept it), OR
   - Is excluded from the qualified set.

### 6.5 Qualified set determination

After the complaint round:

- The **qualified set** `QSET ⊆ {1, ..., n}` is the maximal
  subset such that:
  - Every party in QSET broadcast valid commitments;
  - No party in QSET was successfully complained against;
  - `|QSET| ≥ t`.

- If `|QSET| < t`, the DKG ABORTS.

- Each party `j` computes its final share:
  ```
  s_{1,j} = Σ_{i ∈ QSET} f_i.eval(j)
  s_{2,j} = (per-party s_2 derivation; see §6.6)
  ```

### 6.6 Group public-key derivation

Each party computes the group public key:

1. The implicit centralized secret is:
   ```
   s_1 = Σ_{i ∈ QSET} f_i^(0)
   ```
   (NOT directly computed by any single party — only the per-party
   shares `s_{1,j}` are known to parties.)

2. The FIPS 204 secret `s_2` is sampled jointly via a similar VSS
   protocol with the qualified-set parties.

3. Each party can compute the public commitment to `s_1`:
   ```
   T_0_committed = Σ_{i ∈ QSET} C_i^(0)
   ```
   which is the public commitment to `s_1`.

4. The group public key components `(ρ, t_1)` are derived per FIPS
   204 §3.5.4 ExpandA and KeyGen, with ρ being a publicly-fixed
   value derived from `sid_dkg` (so all parties agree on A).

5. All parties verify by reconstructing the public key from QSET
   commitments and confirming agreement.

### 6.7 DKG output

The DKG outputs:
- A public group key `pk` agreed by all qualified parties;
- A per-party share bundle `(s_{1,i}, s_{2,i})` for each i ∈ QSET;
- A public DKG transcript `T_dkg` containing:
  - `sid_dkg`, `(n, t)`, `QSET`
  - All commitments `{C_i^(0), ..., C_i^(t−1)} for i ∈ QSET`
  - The derived `pk`
  - All complaint records (if any)

`T_dkg` is publicly verifiable: any third party can confirm
correctness given `T_dkg + pk`.

## 7. Threshold Signing

### 7.1 Inputs

To produce a signature on message `M` with context `ctx`:

- A quorum `Q ⊆ QSET` of size `|Q| ≥ t`.
- A signing session identifier `sid_sign` (32 bytes, fresh).
- A per-call randomness contribution from each party (see §11.3).
- The message `M` and context `ctx` (per FIPS 204 §5.4.1).

### 7.2 Round 1 — commitment

Each party `i ∈ Q`:

1. Computes the per-party randomness seed:
   ```
   rho_prime_i = SHAKE256(K_i || rho_rnd_i || mu_ext || κ, 64)
   ```
   where:
   - `K_i` is party i's FIPS 204 K-component (per-party);
   - `rho_rnd_i` is fresh entropy (32 bytes);
   - `mu_ext = SHAKE256(0x00 || |ctx| || ctx || M, 64)` is the
     FIPS 204 §5.4.1 ExternalMu;
   - `κ` is the current rejection-loop counter (initially 0).

2. Samples the mask polynomial vector:
   ```
   y_i = ExpandMask(rho_prime_i, 0)
   ```
   per FIPS 204 §3.5.4.

3. Computes the commitment:
   ```
   w_i = A · y_i        (mod q, in R_q^k)
   w1_i = HighBits(w_i, 2γ_2)
   ```
   where A is the public matrix derived from the group ρ via
   FIPS 204 ExpandA.

4. Broadcasts `(sid_sign, κ, ID_i, w1_i)` to all parties in Q,
   authenticated under party i's long-term key.

### 7.3 Aggregator: challenge derivation

After receiving all `|Q|` commitments (or after `Δ`-timeout):

1. **If fewer than `t` commitments received within Δ**: invoke
   the abort protocol (§10).

2. Aggregate:
   ```
   w1_agg = Σ_{i ∈ Q} λ_i^Q · w1_i        (coordinate-wise in R_q^k)
   ```
   where λ_i^Q are Lagrange coefficients on Q evaluated at 0.

3. Compute the challenge:
   ```
   c_tilde = SHAKE256(mu_ext || w1Encode(w1_agg), 32)
   ```

4. Broadcast `(sid_sign, κ, c_tilde)` to all parties in Q.

### 7.4 Round 2 — response

Each party `i ∈ Q`:

1. Computes the challenge ring element:
   ```
   c = SampleInBall(c_tilde)        (per FIPS 204 §3.5.1)
   ```

2. Computes the partial response:
   ```
   z_i = y_i + c · s_{1,i}        (in R_q^l)
   ```

3. Broadcasts `(sid_sign, κ, ID_i, z_i)` to the aggregator,
   authenticated.

### 7.5 Aggregator: combine

After receiving all `|Q|` partial responses:

1. Aggregate:
   ```
   z = Σ_{i ∈ Q} λ_i^Q · z_i
   ```

2. Compute auxiliary aggregate values:
   ```
   cs2_agg = c · Σ_{i ∈ Q} λ_i^Q · s_{2,i}
   ct0_agg = c · t_0   (public)
   w_low_agg = LowBits(w_agg − cs2_agg, 2γ_2)
   h = MakeHint(−ct0_agg, w_agg − cs2_agg + ct0_agg, 2γ_2)
   ```

3. Evaluate FIPS 204 §6.2 rejection conditions:
   - **R1**: `||z||∞ < γ_1 − β`
   - **R2**: `||w_low_agg||∞ < γ_2 − β`
   - **R3**: `||ct0_agg||∞ < γ_2`
   - **R4**: `weight(h) ≤ ω`

4. If any condition fails:
   - Increment κ;
   - Restart from Round 1 (each party re-derives a fresh y_i
     with the new κ).

5. If all conditions pass:
   - Pack `σ = sigEncode(c_tilde, z, h)` per FIPS 204 §3.5.5;
   - Broadcast `(sid_sign, κ_accept, σ)` to all parties in Q;
   - Honest parties verify `Verify(pk, M, ctx, σ) = true` per
     FIPS 204 §6.3 and terminate.

### 7.6 Output

The output is a single byte string `σ` of length `sig_bytes`
(see §3 table) that:
- Verifies under any FIPS 204 conformant `Verify(pk, M, ctx, σ)`;
- Is bit-identical to a single-party FIPS 204 ML-DSA Sign call on
  the implicit centralized secret with the same `M`, `ctx`, and
  appropriate aggregated randomness.

## 8. Verification

The verification algorithm is **unmodified FIPS 204 §6.3 Verify**.
This document does NOT specify a Pulsar-specific verifier.
Implementations MUST use a FIPS 204 conformant Verify primitive.

```
def verify(pk, M, ctx, sigma):
    return FIPS204.ML_DSA_Verify(pk, M, ctx, sigma)
```

This is the load-bearing operational property of Pulsar: deployed
verifiers (BoringSSL FIPS, AWS-LC, OpenSSL 3.0 PQ provider,
cloudflare/circl, pq-crystals reference) accept Pulsar signatures
without modification.

## 9. Proactive Resharing

### 9.1 Overview

Proactive resharing rotates per-party shares without changing the
group public key. Used for committee rotation, key-compromise
recovery, and periodic refresh.

### 9.2 Protocol

Inputs:
- Current quorum `Q_old` with shares `{s_{1,i}}_{i ∈ Q_old}`
- New committee `Q_new` of size `n_new`
- New threshold `t_new` (may equal or differ from `t_old`)
- Reshare session identifier `sid_reshare`

Each party `i ∈ Q_old` (where `|Q_old| ≥ t_old`):

1. Samples a zero-secret polynomial:
   ```
   g_i ∈ R_q^l[X]   of degree (t_new − 1)
   such that g_i.eval(0) = 0
   ```

2. Sends shares `g_i.eval(j)` to each `j ∈ Q_new` via the same
   VSS construction as DKG (Pedersen commitments + per-pair
   encryption + complaint round).

3. After verification, each new-quorum party `j` computes:
   ```
   s_{1,j}' = Σ_{i ∈ Q_old} λ_i^{Q_old} · s_{1,i}_at_j + Σ_{i ∈ Q_old} g_i.eval(j)
   ```
   where `λ_i^{Q_old}` are Lagrange coefficients on Q_old
   evaluated at j.

4. Old-quorum parties' shares are decommissioned (zeroized).

### 9.3 Public-key preservation

By construction:
- `Σ_{i ∈ Q_old} g_i.eval(0) = 0` (zero-secret property);
- `Σ_{i ∈ Q_old} λ_i^{Q_old} · f.eval(i)_at_0 = f.eval(0)` (Lagrange);
- Therefore `f'.eval(0) = f.eval(0)`, and the FIPS 204 derived
  public key is unchanged.

### 9.4 Verification

A public observer with the reshare transcript can verify:
- Each `g_i` is correctly zero-secret (via commitments);
- New-quorum shares are correctly derived from old-quorum shares.

The group public key `pk` is unchanged across the reshare; any
FIPS 204 verifier accepts post-reshare signatures with the same
`pk`.

## 10. Identifiable Abort and Slashing Evidence

### 10.1 Abort triggers

The protocol invokes the abort sub-protocol if any of:
- A party times out on a required Round-1 or Round-2 message
  (after `Δ`).
- A party broadcasts equivocating messages (two different `w1_i`
  values for the same `(sid_sign, κ)`).
- A party's partial response `z_i` fails verification against the
  public commitment `w_i`.
- A party's commitment `w1_i` fails the consistency check after
  aggregation.

### 10.2 Abort-evidence record

Each abort triggers an **abort-evidence record** (TLV-encoded)
sufficient for any third party with the public transcript to
verify the abort cause:

```
AbortEvidence ::= SEQUENCE {
    version         INTEGER (0),
    sid             OCTET STRING (32),
    kappa           INTEGER,
    accused         INTEGER,            -- party index
    kind            INTEGER {
                       equivocation(1),
                       bad_delivery(2),
                       mac_failure(3),
                       range_failure(4)
                    },
    fields          OctetString          -- per-kind structured fields
}
```

Per-kind `fields`:

- **equivocation**: two signed messages from the same accused party
  with the same `(sid, kappa)` but different content.
- **bad_delivery**: a recipient-decryptable HPKE ciphertext + the
  decrypted content + proof of decryption + proof the content
  fails verification against the accused's commitments.
- **mac_failure**: a message signed under the accused's
  long-term key but failing inner-MAC verification.
- **range_failure**: a partial response `z_i` failing the FIPS 204
  R-condition check.

### 10.3 Verification by third party

Any third party with only `(pk, T_dkg, AbortEvidence)` can:
1. Verify the accused's long-term signature on the included
   messages;
2. Verify the cryptographic evidence (HPKE proof, R-condition
   norm computation, MAC value);
3. Conclude that the accused deviated.

The protocol guarantees:
- **Soundness**: an honest party cannot be successfully blamed.
- **Completeness** (under synchronous network): a deviating party
  IS successfully blamed within Δ.

### 10.4 Slashing

For on-chain deployment:
- The abort-evidence record is submitted to a slashing contract;
- The contract verifies the evidence using the (publicly known)
  group state;
- On verification success, the contract slashes the accused
  party's stake.

Evidence sizes are bounded: typical record < 1.5 KB, fitting in a
single transaction calldata field on Ethereum-class chains.

## 11. Transcript Construction and Domain Separation

### 11.1 Domain-separation prefix

All Pulsar hashes use a domain-separation prefix:

```
DOMAIN_PREFIX = "HANZO-PULSAR-MLDSA-v0.1"
```

This prefix MUST appear at the start of every SHAKE input to
prevent cross-protocol replay.

### 11.2 Transcript hashing

Each protocol session maintains a running transcript:

```
T = SHAKE256(
      DOMAIN_PREFIX
   || ciphersuite_id              -- "PULSAR-THRESHOLD-ML-DSA-65"
   || version                     -- "0.1"
   || sid                         -- session identifier (32 bytes)
   || chain_id                    -- application-bound identifier
   || epoch                       -- monotonic counter
   || (n, t)                      -- threshold parameters
   || qualified_set_hash          -- hash of sorted QSET
   || message_hash                -- hash of M
   || context_hash                -- hash of ctx
   || round_messages              -- concatenated per-round broadcasts
)
```

Each per-round message in the transcript includes:
- `round_number`
- `sender_index`
- `kappa` (signing only)
- `payload`
- `signature_over_payload`

### 11.3 Session identifier derivation

The session identifier `sid` MUST be derived from a
publicly-verifiable randomness source:

- **On-chain deployments**: `sid = SHAKE256(chain_id || block_hash || block_height || tx_index, 32)`
- **Off-chain deployments**: `sid` MUST come from a
  publicly-verifiable randomness beacon (e.g., drand, RANDAO).
  Implementations MUST NOT use party-controlled randomness for
  `sid` to prevent biased-coin attacks against the DKG.

### 11.4 Replay prevention

The transcript binding prevents:
- **Cross-chain replay**: `chain_id` differs.
- **Cross-session replay**: `sid` differs.
- **Cross-epoch replay**: `epoch` differs.
- **Cross-protocol replay**: `DOMAIN_PREFIX` differs from any
  other PQ-signature protocol.

## 12. Wire Formats

### 12.1 Encoding

All wire-level integers are little-endian byte sequences. All
polynomial-vector elements are encoded per FIPS 204 §3.5.

### 12.2 Message types

```
PulsarMessage ::= SEQUENCE {
    version           INTEGER (0),
    ciphersuite_id    UTF8String,        -- e.g., "PULSAR-THRESHOLD-ML-DSA-65"
    sid               OCTET STRING (32),
    epoch             INTEGER,
    sender_index      INTEGER,
    msg_type          INTEGER {
                          DKG_R1_Commit(1),
                          DKG_R1_EncShare(2),
                          DKG_R2_Complaint(3),
                          DKG_R2_Reveal(4),
                          SIGN_R1_Commit(5),
                          SIGN_AGG_Challenge(6),
                          SIGN_R2_Response(7),
                          SIGN_Final(8),
                          RESHARE_Commit(9),
                          RESHARE_EncShare(10),
                          ABORT_Evidence(11)
                      },
    kappa             INTEGER,            -- present for SIGN_R1 / SIGN_R2 / SIGN_AGG_Challenge
    payload           OctetString,
    signature         OctetString          -- sender's long-term-key signature
}
```

### 12.3 Public verifier interface

Verifiers receive only the final FIPS 204 signature `σ` and the
group public key `pk`. The full Pulsar protocol transcript is
irrelevant to the verifier — see §8.

## 13. Public-Chain Deployment Profile

### 13.1 On-chain transcript

For public-blockchain deployments:

- The DKG transcript `T_dkg` SHOULD be posted on-chain (or
  committed to via a Merkle root + IPFS off-chain storage with
  on-chain root).
- Each signing session's `sid_sign` MUST be bound to a block hash
  or transaction identifier.
- Abort-evidence records (§10) MUST be submitted as on-chain
  transactions for slashing.

### 13.2 Validator set rotation

For blockchain validator sets:

- A new validator set triggers a `RESHARE` event (§9).
- The new validator set's qualified subset becomes the new
  signing committee.
- The group public key `pk` is preserved across rotation,
  enabling persistent on-chain identity.

### 13.3 Reorg behavior

Under chain reorganizations:
- A signing session that completed on a now-orphaned block MUST
  be replayed on the new chain head (with a fresh `sid_sign`
  derived from the new block hash).
- A signing session in progress at the reorg point MAY be aborted
  and re-initiated, or MAY complete with the original `sid_sign`
  and be submitted to both chains (the signature itself is replay-
  safe via FIPS 204 verification on the application-level message,
  which typically includes a chain-state commitment).

### 13.4 Gas / calldata bounds

- A typical Pulsar signature is 3309 bytes (ML-DSA-65). Fits in
  a single Ethereum calldata transaction.
- Abort-evidence records are typically < 1.5 KB.
- Full DKG transcripts can exceed 50 KB for `n = 21, t = 14`;
  recommended on-chain storage is Merkle root only with off-chain
  full transcript availability.

## 14. Test Vectors

Conformance test vectors are published at:
- <https://github.com/luxfi/pulsar/tree/main/vectors/>

Vector categories:

| Category | Coverage |
|---|---|
| Single-party ML-DSA | KAT vectors matching pq-crystals reference at (n, t) = (1, 1) |
| DKG success | Transcripts at (n, t) ∈ {(3, 2), (5, 3), (7, 4), (10, 7), (21, 14)} |
| DKG complaint | Adversarial dealer scenarios with successful blame |
| DKG abort | Insufficient qualified set scenarios |
| Threshold signing | Full transcripts for honest quorum at the same (n, t) sweep |
| Replay negative | Cross-chain, cross-session, cross-epoch replay attempts (all rejected) |
| Malformed negative | Invalid commitments, shares, signatures (all rejected) |
| Reshare preservation | Pre- and post-reshare public keys match |

Each test vector includes the fields listed in §15 of the
companion `evaluation.md`.

## 15. Security Considerations

### 15.1 Post-quantum hardness

Pulsar inherits the M-LWE / M-SIS hardness of FIPS 204 ML-DSA.
This document does NOT establish post-quantum hardness
independently. See FIPS 204 [FIPS204] Appendix B for the hardness
analysis.

### 15.2 Threshold-specific security

Threshold-specific reductions:
- **DKG soundness**: standard Pedersen-VSS soundness reduces to
  discrete-log hardness over R_q^l (assumed; analogous to standard
  threshold-cryptography literature).
- **Signing unforgeability**: tight reduction to ML-DSA EUF-CMA
  under honest-quorum assumption + DKG soundness.
- **Output interchangeability**: established by the v0.1 EasyCrypt
  proof artifact (`proofs/easycrypt/Pulsar_N1_Extracted.ec`).

Machine-checked proof artifacts at
<https://github.com/luxfi/pulsar/tree/main/proofs/>.

### 15.3 Constant-time

Implementations MUST be constant-time on:
- Per-party share material (`s_{1,i}`, `s_{2,i}`);
- Per-call randomness `rho_rnd_i` and derived mask `y_i`;
- Any code path branching on rejection-condition outcomes when
  the rejection has not yet been broadcast.

Implementations MAY be variable-time on:
- Final accept/reject decision (per FIPS 204 §3.3 — the κ counter
  is not secret-dependent on long-term keys);
- Pure-public verification (calls FIPS 204 Verify).

The Pulsar reference Jasmin implementation
(`jasmin/threshold/*.jazz`) is constant-time-clean under jasmin-ct.

### 15.4 Replay and session binding

Implementations MUST bind every signing session to a unique `sid`
derived from a publicly-verifiable randomness source (§11.3).
Implementations MUST reject duplicate or stale sessions.

### 15.5 Identifiable abort under network partition

Identifiable abort is guaranteed ONLY under synchronous network
assumptions (§4.2). Under network partition, deviating parties may
be indistinguishable from delayed parties. Production deployments
SHOULD bind the synchronous-network timer `Δ` to consensus-layer
finality, e.g., 2 block intervals on Ethereum-class chains.

### 15.6 Side-channel hardening

The Jasmin reference is constant-time-clean. Production-grade
implementations require:
- Static constant-time analysis on the production binary
  (jasmin-ct, ct-verif, or equivalent);
- Dynamic timing-leak testing (dudect at 10⁹ samples per target
  on a pinned CPU);
- Secret-key zeroization on heap, stack, and registers;
- Defense against power / EM side-channels (deployment-specific).

### 15.7 Domain separation

The `DOMAIN_PREFIX` "HANZO-PULSAR-MLDSA-v0.1" MUST appear at the
start of every SHAKE input (§11.1). Failure to include the prefix
opens cross-protocol replay attacks against any other ML-DSA
profile or other Pulsar version.

### 15.8 Rogue-key attacks

The DKG's Pedersen commitments (§6.3) bind each party's
contribution to the qualified-set polynomial. Without commitment
binding, a malicious party could adaptively choose its
contribution after seeing other parties' shares (a rogue-key
attack). The qualified-set determination (§6.5) excludes any
party whose commitments cannot be verified.

## 16. Implementation Considerations

### 16.1 Reference implementation

A Go reference implementation is at:
- <https://github.com/luxfi/pulsar/tree/main/ref/go>

Licensed under Apache-2.0. Includes:
- Full DKG, signing, verification, reshare, and abort flows.
- KAT test harness.
- Differential tests against three independent ML-DSA verifiers.
- Adversarial DKG simulator.

### 16.2 Jasmin high-assurance implementation

The threshold-layer Jasmin sources at
`jasmin/threshold/{round1,round2,combine}.jazz` are
constant-time-clean under jasmin-ct (3/3 blocking gate). They
extract to EasyCrypt for the formal refinement proof.

### 16.3 Bindings

Recommended bindings for production use:
- **Rust**: ABI-stable crate exposing the C ABI.
- **C**: header + library for FFI consumers.
- **Python**: ctypes wrapper for testing.
- **Go**: pure Go reference for protocol-level work.
- **WASM**: browser / blockchain VM targets.

### 16.4 Build reproducibility

The reference build is deterministic from a 48-byte seed.
`scripts/build.sh` produces byte-identical outputs across reruns.
This property is enforced on every CI commit.

## 17. Known Limitations

| Limitation | Workaround |
|---|---|
| No asynchronous identifiable abort | Production: bind Δ to consensus-layer finality |
| No 1-round signing | FIPS 204 rejection sampling precludes; use preprocessing for amortization |
| DKG bias resistance under collusion | Bind `sid_dkg` to a randomness beacon (drand, RANDAO) |
| Adaptive corruption (out of scope this draft) | Use static-corruption assumption |
| Threshold SLH-DSA | Magnetar — separate research-track draft |
| Cross-committee resharing without external state binding | Bind reshare epoch to consensus-layer state |
| Full mechanized closure of all EC residual axioms | Multi-month research; not blocking submission |

## 18. IANA Considerations

This document requests no IANA actions. The ciphersuite
identifiers ("PULSAR-THRESHOLD-ML-DSA-{44,65,87}") are
human-readable strings used in the protocol's `ciphersuite_id`
field; they are NOT registered with IANA at this draft revision.

A future revision MAY register the ciphersuite identifiers under
the Cryptographic Algorithm Identifiers registry if community
adoption warrants.

## 19. References

### 19.1 Normative References

- **[FIPS204]** National Institute of Standards and Technology,
  "Module-Lattice-Based Digital Signature Standard", FIPS 204,
  August 2024,
  <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf>.

- **[FIPS202]** National Institute of Standards and Technology,
  "SHA-3 Standard: Permutation-Based Hash and Extendable-Output
  Functions", FIPS 202, August 2015.

- **[FIPS203]** National Institute of Standards and Technology,
  "Module-Lattice-Based Key-Encapsulation Mechanism Standard",
  FIPS 203, August 2024.

- **[RFC2119]** Bradner, S., "Key words for use in RFCs to
  Indicate Requirement Levels", BCP 14, RFC 2119,
  DOI 10.17487/RFC2119, March 1997.

- **[RFC8174]** Leiba, B., "Ambiguity of Uppercase vs Lowercase
  in RFC 2119 Key Words", BCP 14, RFC 8174,
  DOI 10.17487/RFC8174, May 2017.

- **[RFC9180]** Barnes, R., Bhargavan, K., Lipp, B., and C. Wood,
  "Hybrid Public Key Encryption", RFC 9180,
  DOI 10.17487/RFC9180, February 2022.

### 19.2 Informative References

- **[FROST]** Komlo, C. and Goldberg, I., "FROST: Flexible
  Round-Optimized Schnorr Threshold Signatures", in Selected
  Areas in Cryptography 2020.

- **[PULSAR-SPEC]** Lux Industries, "Pulsar Threshold ML-DSA
  Specification v0.1",
  <https://github.com/luxfi/pulsar/blob/main/spec/pulsar.pdf>.

- **[PULSAR-PROOFS]** Lux Industries, "Pulsar EasyCrypt + Lean
  Refinement Proofs",
  <https://github.com/luxfi/pulsar/tree/main/proofs>.

- **[NIST-MPTC]** National Institute of Standards and Technology,
  "NIST IR 8214C: NIST First Call for Multi-Party Threshold
  Schemes", <https://csrc.nist.gov/pubs/ir/8214/c/iprd>.

- **[Magnetar]** Lux Industries, "Magnetar: Public-DKG MPC
  Threshold SLH-DSA (research profile)",
  <https://github.com/luxfi/pulsar/blob/main/docs/magnetar.md>.

## Appendix A. Worked Example

A complete worked example for a 5-party DKG and signing session
under PULSAR-THRESHOLD-ML-DSA-65 (n=5, t=3):

1. **Setup**: parties 1..5, threshold 3, sid_dkg derived from
   block hash 0xabc...
2. **DKG R1**: each party broadcasts 3 commitments (t coefficients)
   and 4 encrypted shares (n−1 recipients).
3. **DKG R2**: party 4 sends a malformed share to party 2; party
   2 broadcasts a complaint; party 4 reveals the correct share
   publicly; complaint resolved; QSET = {1, 2, 3, 4, 5}.
4. **Group public key derivation**: all parties compute
   pk = (ρ, t_1) from QSET commitments.
5. **Signing session**: quorum Q = {1, 2, 3}, sid_sign derived
   from a new block hash, message M = "transfer 100 LUX to ...",
   ctx = "PULSAR-DEMO-v0".
6. **Sign R1**: parties 1, 2, 3 broadcast w1_i.
7. **Aggregator (party 1)**: computes c_tilde and broadcasts.
8. **Sign R2**: parties 1, 2, 3 broadcast z_i.
9. **Combine**: aggregator computes z, h, evaluates R1-R4 (all
   pass on the first κ=0), packs σ = sigEncode(c_tilde, z, h),
   broadcasts.
10. **Verify**: any FIPS 204 verifier confirms σ verifies against
    pk on (M, ctx).

Full transcripts: `vectors/transcripts/n5-t3-mldsa65-sign.jsonl`.

## Appendix B. Conformance Test Plan

A conforming implementation MUST pass:

1. All KAT vectors in `vectors/sign.json` and `vectors/verify.json`.
2. All threshold-signing transcripts in
   `vectors/threshold-sign.json`.
3. All malformed-input rejection tests in `test/negative/`.
4. Cross-validation against `cloudflare/circl` (or another
   independent FIPS 204 implementation) on every KAT vector.
5. Adversarial DKG simulator scenarios in `test/adversarial/`.

Suggested test-runner integration: invoke `scripts/test.sh` from
the reference repository as the conformance gate.

## Authors' Addresses

```
Z. Kelling (Editor)
Lux Industries, Inc.
Email: z@lux.network

Pulsar maintainers
Lux Industries, Inc.
Email: mptc@lux.network
```

---

**Document metadata**

- IETF document name: `draft-hanzo-pulsar-threshold-mldsa-00`
- Version: v0.1 (skeleton-complete; ready for CFRG review)
- Date: 2026-05-18
- Conversion path: this Markdown converts to xml2rfc XML via
  `mmark` or `kramdown-rfc` for IETF datatracker submission.
- License of this document: contributed under the IETF Trust
  Legal Provisions (`https://trustee.ietf.org/license-info`).
