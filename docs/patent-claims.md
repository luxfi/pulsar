# Pulsar — Patent Claim Drafts (Attorney Review)

> **Internal working document.** This file is the technical substrate
> for a patent attorney to draft formal claims from. It is **not** a
> filed patent application or a legal opinion. It enumerates the
> Pulsar contributions that we consider patentable, with claim
> language, prior-art mapping, and proof-artifact citations.
>
> Public-facing IP terms are in `../PATENTS.md`. The royalty-free
> grant in PATENTS.md §3 covers all claims listed below, present
> and future.

## §0 Drafting notes for the attorney

- **Inventors**: Lux Industries cryptography team. Specific
  named inventors to be assigned per claim group based on
  contribution records (commit history in `git log`).
- **Priority date**: file as a US provisional within 12 months of
  the NIST MPTC submission's public date (currently anticipated:
  2026-Nov-16). File BEFORE the NIST submission becomes public to
  preserve foreign-filing rights.
- **Prior art search scope**: NIST PQC / MPTC submissions
  (Dilithium, Kyber, Falcon, SPHINCS+, FROST, GG18, CGGMP21), IACR
  ePrint archive 2018-2026, FIPS 204 / 205 / 206 standards, ML-DSA
  ACVP test vectors, libjade-Dilithium implementations, OpenSSL +
  BoringSSL FIPS PQ providers.
- **Patent family**: file as one provisional with multiple claim
  groups; split into independent applications at PCT entry if claim
  diversity warrants.
- **Co-pending work**: the EasyCrypt / Lean / Jasmin proof artifacts
  in this repository (`proofs/easycrypt/`, `proofs/lean-easycrypt-bridge.md`)
  document the technical substance and can support enablement /
  written-description requirements (35 USC §112).

## §1 Claim group A — Byte-identical output interchangeability

### §1.1 Independent claim (Claim 1, draft)

> **Claim 1.** A method for distributed signing of a message under a
> module-lattice digital signature scheme conformant to FIPS 204
> ML-DSA at parameter set ML-DSA-65, the method comprising:
>
> (a) distributing, by a dealer, secret-key shares to a quorum of
>     `n` parties such that each party's share is the evaluation of
>     a secret-sharing polynomial `f` of degree `< t` at the party's
>     index, where `f.eval(0)` is the centralized FIPS 204
>     ML-DSA-65 secret key;
>
> (b) at each party `i` in a quorum subset `Q` of size at least `t`:
>
>     (b1) sampling, deterministically from a per-call randomness
>          seed and a per-party expansion seed, a mask polynomial
>          vector `y_i`;
>
>     (b2) computing a per-party commitment to `y_i` (specifically:
>          the high-bits decomposition `w1_i` of the polynomial-
>          vector product `A · y_i` where `A` is the public matrix
>          expanded from the public-key seed via FIPS 204 §3.5.3
>          ExpandA);
>
>     (b3) broadcasting `w1_i` to the other parties in `Q`;
>
> (c) computing, by an aggregator, a challenge `c_tilde` from the
>     SHAKE256 digest of the FIPS 204 §5.4.1 ExternalMu byte layout
>     concatenated with the Lagrange-aggregated `w1` at the
>     quorum-Lagrange-coefficients applied coordinate-wise;
>
> (d) at each party `i`:
>
>     (d1) computing a per-party partial response
>          `z_i = y_i + c · s_i`, where `c = SampleInBall(c_tilde)`
>          and `s_i` is the party's share of the FIPS 204 `s_1`
>          secret;
>
>     (d2) broadcasting `z_i` to the aggregator;
>
> (e) computing, by the aggregator, a Lagrange-aggregated response
>     `z = Σᵢ λ_i · z_i` over the quorum `Q`, where `λ_i` are the
>     Lagrange interpolation coefficients evaluated at zero for the
>     quorum's party indices;
>
> (f) computing, by the aggregator, a hint vector `h` from the
>     low-bits decomposition of `A · z - c · t1 · 2^d` (where `t1`
>     is the public-key high-bits) per FIPS 204 §3.4.3 MakeHint;
>
> (g) packing the triple `(c_tilde, z, h)` per FIPS 204 §3.5.5
>     `sigEncode` to produce a signature byte string `σ`,
>
> wherein the signature `σ` is bit-identical to a signature
> produced by single-party FIPS 204 ML-DSA-65 Sign on inputs
> `(sk, m, ctx)` where `sk` is the centralized secret key
> reconstructed via Lagrange interpolation of the shares in `Q`,
> and where any FIPS 204 conformant verifier accepts `σ` without
> modification.

### §1.2 Reference to spec and proof

- Spec section: `spec/pulsar.tex` §4 (protocol) + §6 (output-interchangeability proof, Theorem 6.1)
- EC mechanization: `proofs/easycrypt/Pulsar_N1.ec` (theorem `pulsar_n1_byte_equality_extracted`)
- Lean correctness identity: `lean/Crypto/Threshold_Lagrange.lean:121` (theorem `threshold_partial_response_identity`)
- Bridge: `proofs/lean-easycrypt-bridge.md` Axiom 5

### §1.3 Dependent claims

**Claim 2.** The method of claim 1, wherein the per-call randomness
seed is derived from a per-party FIPS 204 K-value combined with a
session-randomness input via SHAKE256, providing a deterministic
signing mode.

**Claim 3.** The method of claim 1, wherein the per-call randomness
seed is a 64-byte uniformly random sample, providing a randomized
signing mode.

**Claim 4.** The method of claim 1, wherein step (e) (Lagrange
aggregation) is performed coordinate-wise on each polynomial in the
response vector, and the Lagrange coefficients `λ_i` are precomputed
and cached per-quorum to amortize aggregation cost across signing
sessions.

**Claim 5.** The method of claim 1, wherein step (c) (computing
`c_tilde`) further comprises:

(c0) computing an external mu binder `mu_ext` as the SHAKE256
     digest of `IntegerToBytes(0,1) || IntegerToBytes(|ctx|,1) ||
     ctx || M` per FIPS 204 §5.4.1; and

(c1) hashing `mu_ext || w1Encode(w1)` to produce `c_tilde`.

**Claim 6.** The method of claim 1, further comprising re-running
steps (b1)-(g) with an incremented kappa value if any of the FIPS
204 §6.2 R1-R4 rejection conditions (norm bounds on `z`, `r0`, `ct0`,
and the hint weight) fail on the aggregated values, until
acceptance.

**Claim 7.** The method of claim 6, wherein the rejection-loop kappa
counter is broadcast among quorum members so that all parties agree
on which kappa attempt the signature was produced under.

**Claim 8.** The method of claim 1, wherein the dealer in step (a)
is replaced by a distributed key generation (DKG) protocol comprising:

- a verifiable secret sharing (VSS) commitment broadcast;
- per-pair encrypted-share exchange;
- a complaint round permitting honest parties to expose malformed
  share encryptions;
- a public-key commitment that binds the DKG output to the resulting
  FIPS 204 public key,

such that no single party knows the centralized secret `f.eval(0)`.

**Claim 9.** The method of claim 8, wherein the DKG protocol
preserves the FIPS 204 public-key format such that the resulting
group public key is byte-identical to a FIPS 204 KeyGen output on
the implicit secret `f.eval(0)`.

**Claim 10.** A computer-readable storage medium containing
instructions that, when executed by a plurality of computing devices
in a quorum, cause the devices to perform the method of any of
claims 1-9.

### §1.4 Prior-art mapping

| Prior-art reference | Distinguishing feature |
|---|---|
| FROST (Komlo, Goldberg 2020) | FROST is a threshold scheme for Schnorr-family signatures (Ed25519, BLS). It does NOT apply to lattice-based signatures, does NOT handle rejection sampling, and does NOT produce byte-identical outputs to a NIST-standardized PQ signature. Pulsar's novelty is the specific composition of FROST-style Lagrange aggregation with FIPS 204's kappa rejection loop while preserving byte-identical output. |
| Dilithium / ML-DSA single-party (FIPS 204) | The single-party signing algorithm is in the public domain (NIST standard). Pulsar adds the threshold structure on top while preserving the centralized signature format. |
| GG18 / CGGMP21 (threshold ECDSA) | Threshold schemes for ECDSA — a different signature family (DLP, not LWE). Different security analysis, different aggregation primitive (multiplicative blinding, not Lagrange). Inapplicable as prior art for the lattice case. |
| Damgård et al., "Threshold Dilithium" (IACR ePrint 2020/xxx if applicable) | TBD — patent attorney to perform a precise prior-art search on the IACR ePrint archive. Pulsar's specific output-interchangeability technique with byte-identical FIPS 204 output should be distinguished from any prior threshold-Dilithium work that did not achieve byte-identical output. |
| Raccoon (NIST PQC submission) | Compatible verification but does NOT claim byte-identical output to ML-DSA, and is a 3-round protocol. Pulsar's 2-round byte-identical structure is the novelty. |

### §1.5 Enablement support

35 USC §112 (a) requires that the patent disclosure enable a person
of ordinary skill in the art to make and use the claimed invention.
Pulsar's enablement support is exceptionally strong:

- A complete Go reference implementation in `ref/go/` (~3500 lines).
- Bit-level test vectors in `vectors/` cross-validated against three
  independent ML-DSA implementations (pq-crystals reference,
  BoringSSL FIPS, OpenSSL 3.0 PQ provider).
- A high-assurance EasyCrypt proof package in `proofs/easycrypt/`
  with the Class N1 byte-equality theorem mechanically derived (no
  admits).
- A Lean 4 proof package in `~/work/lux/proofs/lean/Crypto/` with
  the Lagrange algebraic identities mechanized against Mathlib.
- A Jasmin high-assurance implementation in `jasmin/threshold/`
  with constant-time verification (`jasmin-ct`) passing on the
  threshold layer.

## §2 Claim group B — Class N4 reshare with public-key preservation

### §2.1 Independent claim (Claim 11, draft)

> **Claim 11.** A method for proactive secret-sharing rotation in a
> threshold signing system based on FIPS 204 ML-DSA, the method
> comprising:
>
> (a) at a current quorum `Q_old` of `n_old` parties each holding a
>     share `s_i^old` of a secret `f.eval(0)`, sampling a
>     zero-secret polynomial `g` of degree `< t_new` such that
>     `g.eval(0) = 0`;
>
> (b) distributing zero-shares `g.eval(j)` to each party `j` in a
>     new quorum `Q_new` of `n_new` parties via VSS;
>
> (c) at each new-quorum party `j`:
>
>     (c1) computing a new share `s_j^new = Σᵢ λ_i · s_i^old + g.eval(j)`
>          where `λ_i` are Lagrange coefficients on `Q_old`
>          evaluated at `j`;
>
>     (c2) verifying the new share matches the VSS commitments;
>
> (d) decommissioning the old quorum's shares,
>
> wherein the secret `f.eval(0)` is preserved (i.e.,
> `reconstruct(Q_new, s_j^new) = reconstruct(Q_old, s_i^old)`),
> the FIPS 204 group public key derived from the secret is
> preserved (i.e., `derive_pk(f.eval(0))` is unchanged), and no
> single party at any time during the reshare protocol gains
> sufficient share material to reconstruct `f.eval(0)`.

### §2.2 Reference to spec and proof

- Spec section: `spec/pulsar.tex` §4.5 (Reshare protocol)
- EC mechanization: `proofs/easycrypt/Pulsar_N4.ec` (theorem
  `reshare_preserves_secret_honest`)
- Lean correctness identity: `lean/Crypto/Threshold/Reshare.lean`

### §2.3 Dependent claims

**Claim 12.** The method of claim 11, wherein the zero-secret
polynomial `g` is sampled via a distributed coin-toss protocol such
that no single old-quorum party controls `g`.

**Claim 13.** The method of claim 11, further comprising rotating
the per-party FIPS 204 K-values (used for deterministic signing
randomness) at the same time as the share rotation, such that any
secret-key material that left the old quorum (e.g., via session
state) is also invalidated.

**Claim 14.** The method of claim 11, wherein `t_new = t_old`,
preserving the threshold across rotation; or `t_new ≠ t_old`,
permitting threshold adjustment alongside committee rotation.

## §3 Claim group C — Identifiable abort with third-party-verifiable evidence

### §3.1 Independent claim (Claim 15, draft)

> **Claim 15.** A method for producing third-party-verifiable abort
> evidence in a threshold signing protocol comprising:
>
> (a) detecting a protocol-deviation event of one of: (i)
>     equivocation, (ii) bad message delivery, (iii) MAC failure,
>     (iv) range/norm-bound failure;
>
> (b) constructing a TLV-encoded abort-evidence record comprising:
>
>     (b1) a one-byte kind tag identifying the deviation type;
>     (b2) per-kind structured fields proving the deviation;
>     (b3) all signatures or MACs necessary for a third party to
>          verify the evidence without access to the threshold
>          session's private state;
>
> (c) broadcasting the abort-evidence record,
>
> wherein the record is independently verifiable by any third party
> in possession of (i) the threshold session's public transcript
> and (ii) the public keys of the implicated parties, and wherein
> the verification of the record by a third party is field-count-
> validated such that an abort-evidence record valid for one kind
> is rejected under verification for any other kind (preventing
> evidence reuse across deviation types).

### §3.2 Reference to spec and code

- Spec section: `spec/pulsar.tex` §5.2 (Identifiable abort)
- Reference impl: `ref/go/pkg/pulsar/abort.go`
- Tests: `test/negative/abort_evidence_test.go` (10 negative tests,
  fuzz harness `FuzzAbortEvidence_PerKindValidation` at 627K execs)
- Commit history: `effc648` (abort evidence per-kind validators)

### §3.3 Dependent claims

**Claim 16.** The method of claim 15, wherein step (b3) further
comprises including a chain-of-custody Merkle proof binding the
evidence to a public blockchain transcript.

**Claim 17.** The method of claim 15, wherein the equivocation
kind's structured fields comprise two contradictory signed messages
from the same signer over the same session-round identifier.

## §4 Claim group D — Specific FIPS 204 / FROST hybrid composition

### §4.1 Independent claim (Claim 18, draft)

> **Claim 18.** A method for composing FROST-style threshold
> aggregation with the FIPS 204 ML-DSA rejection-sampling loop,
> the method comprising:
>
> (a) executing per-party commitment broadcast outside the
>     rejection-loop scope, such that the kappa rejection counter
>     advances only on the aggregator's side after Round-2 partial
>     responses are received;
>
> (b) for each kappa attempt at the aggregator:
>
>     (b1) aggregating per-party responses `z_i`, partial commitments
>          `w0_i`, and partial `c · s_2,i` contributions via
>          Lagrange-at-zero over the quorum;
>
>     (b2) computing the aggregated `w'` polynomial vector and
>          decomposing into `(w_low, w_high)`;
>
>     (b3) evaluating the FIPS 204 §6.2 R1-R4 rejection conditions
>          on the aggregated `(z, w_low, c · t_0_agg)` and on the
>          hint weight;
>
>     (b4) if all R1-R4 conditions hold, packing the signature and
>          terminating;
>
>     (b5) if any R1-R4 condition fails, broadcasting an abort
>          signal carrying the failing rejection condition's index,
>          and either:
>
>          (i) re-running Round-1 + Round-2 with kappa+1 if the
>              quorum is still committed to signing,
>
>          (ii) identifying and excluding the deviating party(s)
>               via the abort-evidence protocol of Claim 15,
>
> wherein the rejection-loop's kappa selection is deterministic in
> the per-call randomness and per-party expansion seeds, and the
> resulting signature is bit-identical to a single-party FIPS 204
> ML-DSA-65 signature on the centralized secret as per Claim 1.

### §4.2 Reference to spec and proof

- Spec section: `spec/pulsar.tex` §4.4 (Combine) + §5.3 (Abort
  attribution)
- EC mechanization: `proofs/easycrypt/Pulsar_N1_Combine_Refinement.ec`
- Roadmap: `proofs/easycrypt/extraction/combine-byte-walk-roadmap.md`

### §4.3 Dependent claims

**Claim 19.** The method of claim 18, wherein step (b1) further
comprises caching per-quorum Lagrange coefficients to amortize
across kappa attempts within the same signing session.

**Claim 20.** The method of claim 18, wherein step (b5)(ii) is
preferred over step (b5)(i) when the failure pattern indicates a
specific deviating party, providing punitive attribution rather
than retry.

## §5 Claim group E — Specification + reference implementation as system

### §5.1 System claim (Claim 21, draft)

> **Claim 21.** A computing system for distributed threshold signing
> under FIPS 204 ML-DSA-65, the system comprising:
>
> (a) a plurality of computing devices, each storing a secret-key
>     share derived per the method of Claim 11;
>
> (b) a coordinator computing device storing public-key material
>     and signing requests;
>
> (c) a network channel connecting the computing devices in (a)
>     and (b);
>
> (d) instructions on each computing device that, when executed,
>     perform the methods of Claims 1-9 and 15-20,
>
> wherein the system produces signatures bit-identical to
> single-party FIPS 204 ML-DSA-65 signatures on the reconstructed
> secret under Lagrange interpolation.

### §5.2 Dependent system claims

**Claim 22.** The system of claim 21, wherein the network channel
is a public blockchain providing message ordering and replay
prevention, and wherein the threshold session identifier is bound
to the blockchain's per-block transcript hash.

**Claim 23.** The system of claim 21, wherein at least one computing
device in (a) is a FIPS 140-3 validated cryptographic module
containing a ML-DSA implementation.

## §6 Drafting checklist for attorney

- [ ] Claim 1: confirm "bit-identical" / "byte-identical" language
  matches USPTO precedent for cryptographic equivalence claims.
- [ ] Claim 1: verify the FIPS 204 §-references match the most
  recent published FIPS 204 text (NIST sometimes renumbers §s in
  errata).
- [ ] Claim 8: precise DKG language — Lux's DKG is a Pedersen-VSS
  variant; check for blocking patents on Pedersen-VSS specifically
  (likely public-domain at this point but verify).
- [ ] Claim 11: reshare claim — coordinate with any existing patents
  on proactive secret sharing.
- [ ] Claim 15: abort-evidence per-kind validation — verify novelty
  search on threshold-protocol blame protocols (CGGMP21 has some
  related work).
- [ ] Claim 18: FROST + ML-DSA composition — verify novelty against
  the IACR ePrint archive's threshold-Dilithium work.
- [ ] PCT designation list: confirm with Lux business team which
  jurisdictions are priority.
- [ ] Inventorship: assign inventors per claim group based on
  contribution records.

## §7 What this document is NOT

- Not legal advice. This document is a technical-substance brief
  for attorney consumption; legal opinions are the attorney's.
- Not a filed application. The claim drafts here will be revised
  by the attorney before filing.
- Not an exhaustive list of patentable subject matter. Additional
  patentable contributions may emerge during implementation
  hardening (e.g., specific constant-time techniques in
  `jasmin/threshold/`).
- Not a commitment by Lux to file every claim group. Lux's business
  team will decide which groups warrant the patent prosecution cost.

---

**Document metadata**

- Document name: `docs/patent-claims.md`
- Document version: v0.1 (working draft for attorney review)
- Document date: 2026-05-18
- Status: **INTERNAL — pre-filing draft**. Do not redistribute
  outside the attorney-client privilege without Lux legal approval.
- Companion public-facing document: `../PATENTS.md` (grant text).
