# SPEC — Pulsar Public-DKG Threshold ML-DSA (v0.1)

> **Standalone protocol specification** for PULSAR-THRESHOLD-ML-DSA.
> Companion to `spec/pulsar.tex` (the formal LaTeX spec that builds
> to `spec/pulsar.pdf`) and `docs/ietf-draft-skeleton.md` (the
> Internet-Draft version for CFRG submission).
>
> Required sections per NIST IR 8214C / IETF Internet-Draft
> conventions.

## §1 Scope

This document specifies **Pulsar**, the Tier 1 construction of the
**Hanzo PQ Threshold Suite**. Pulsar is a public-DKG threshold
profile for FIPS 204 ML-DSA that produces signatures byte-identical
to single-party FIPS 204 ML-DSA, accepted by any unmodified FIPS
204 conformant verifier.

This spec does NOT cover:
- The single-party FIPS 204 algorithm (see [FIPS204]).
- Verifier implementations (see `ref/go/pkg/pulsar/verify.go` for the
  Pulsar reference call into `cloudflare/circl`'s FIPS 204 verifier).
- Magnetar (Tier 3 threshold SLH-DSA research profile) — see
  `docs/magnetar.md`.
- Corona (R-LWE sibling) — see `~/work/lux/corona/`.

## §2 Terminology

See `docs/ietf-draft-skeleton.md` §2.2 for the full glossary.
Key terms:
- **Party**: a computing entity participating in DKG / signing.
- **Quorum** `Q`: subset of parties of size ≥ `t`.
- **Sharing polynomial** `f`: degree `t − 1` polynomial in R_q^l[X].
- **Group public key** `pk`: FIPS 204 ML-DSA public key produced by DKG.
- **Session identifier** `sid`: 32-byte fresh randomness binding a session.
- **Lagrange coefficient at zero** `λ_i^Q`: standard interpolation weight.

## §3 Parameter sets

| Identifier | NIST Category | pk bytes | sig bytes | typical (t, n) |
|---|---|---|---|---|
| `PULSAR-THRESHOLD-ML-DSA-44` | 2 | 1312 | 2420 | (2, 3) |
| `PULSAR-THRESHOLD-ML-DSA-65` | 3 (RECOMMENDED) | 1952 | 3309 | (3, 5) |
| `PULSAR-THRESHOLD-ML-DSA-87` | 5 | 2592 | 4627 | (5, 7) |

Parameter-set semantics inherit FIPS 204 §4 Table 1 verbatim. The
threshold `(t, n)` is application-level subject to `1 ≤ t ≤ n < q`.

## §4 Threat model

Per `docs/ietf-draft-skeleton.md` §4. Summary:
- Static corruption of at most `t − 1` parties.
- Rushing Byzantine adversary.
- Synchronous network with known upper bound `Δ` on message delivery.
- Public DKG with publicly-verifiable randomness beacon.
- M-LWE / M-SIS hardness (inherited from FIPS 204).
- SHAKE128/SHAKE256 collision/preimage resistance (FIPS 202).

## §5 Security goals

1. **EUF-CMA-Threshold**: no forgery under honest-quorum.
2. **Output interchangeability** (Class N1 / MPTC): signatures
   bit-identical to single-party FIPS 204.
3. **Public-key preservation** across resharing (Class N4 / MPTC).
4. **Identifiable abort** with third-party-verifiable evidence
   (synchronous network).
5. **Robustness**: ≥ t honest parties → valid signature with
   overwhelming probability.

Detailed proofs / reductions: `proofs/easycrypt/Pulsar_N1.ec`
(machine-checked), `pulsar-m/unforgeability.tex` (paper sketch).

## §6 Public DKG

Per `docs/ietf-draft-skeleton.md` §6. Highlights:
- Pedersen-VSS commitment + Lagrange-share encryption + complaint round.
- Qualified set `QSET` determined by complaint resolution.
- Group public key `pk = (ρ, t_1)` per FIPS 204 §3.5.4 KeyGen.
- Publicly-verifiable transcript `T_dkg`.

## §6.1 Pedersen / Feldman VSS details

The DKG uses **Pedersen verifiable secret sharing** over R_q^l:
- Coefficient commitments `C_i^(j) = G^(f_i^(j)) · H^(r_i^(j))`
  where `G, H` are public R_q^l generators (derived from `sid_dkg`
  via SHAKE256).
- Per-pair encrypted shares via HPKE [RFC9180] with ML-KEM-768 KEM
  [FIPS203] (post-quantum-safe).
- Complaint round produces public proofs of malformed shares.

Feldman VSS (without blinding) is acceptable as a fallback for
deployments where Pedersen's blinding factor is impractical to
sample, at the cost of share-content confidentiality.

## §6.2 Qualified-set selection

- After complaint round, `QSET = {i : commitments valid AND no successful complaint}`.
- If `|QSET| < t`, DKG ABORTS.
- All qualified parties broadcast their final share commitments.
- All parties verify agreement; deterministic ordering of `QSET`
  (ascending party index) MUST be used.

## §7 Threshold signing (2 rounds)

Per `docs/ietf-draft-skeleton.md` §7. Summary:
- Round 1: each party samples `y_i`, broadcasts `w1_i = HighBits(A · y_i)`.
- Aggregator: `c_tilde = SHAKE256(mu_ext || w1Encode(Σ λ_i^Q w1_i))`.
- Round 2: each party broadcasts `z_i = y_i + c · s_{1,i}`.
- Aggregator: compute aggregated z, h; check FIPS 204 §6.2 R1-R4
  rejection conditions; if reject, restart with κ+1; if accept,
  pack `σ = sigEncode(c_tilde, z, h)`.

Cost per signing session: 2 broadcast rounds + 1 aggregator-to-all
round; total `O(n × |w1| + n × |z|)` bandwidth.

## §8 Verification

**Unmodified FIPS 204 §6.3 Verify**. No Pulsar-specific verifier.

```
ML_DSA.Verify(pk, M, ctx, sigma) ∈ {accept, reject}
```

## §9 Proactive resharing

Per `docs/ietf-draft-skeleton.md` §9. Preserves `pk` across
committee rotation.

## §10 Identifiable abort and slashing

Per `docs/ietf-draft-skeleton.md` §10. TLV-encoded abort-evidence
records sufficient for third-party verification + on-chain
slashing.

## §11 Transcript and domain separation

`DOMAIN_PREFIX = "HANZO-PULSAR-MLDSA-v0.1"`. All hashes use this
prefix. Replay binding: `sid + chain_id + epoch + (n, t) + QSET-hash +
M-hash + ctx-hash`.

## §12 Wire formats

ASN.1 (SEQUENCE-of-…) for wire messages per
`docs/ietf-draft-skeleton.md` §12. Compact byte layouts for FIPS
204-format objects (`pk`, `sk_i`, `σ`) per FIPS 204 §3.5.

## §13 Public-chain profile

Per `docs/ietf-draft-skeleton.md` §13. On-chain transcript
posting; validator-set rotation via reshare; reorg behaviour;
gas/calldata bounds.

## §14 Test vectors

Cross-validated against `cloudflare/circl`, pq-crystals reference,
BoringSSL FIPS. See `vectors/README.md`.

## §15 Security considerations

Per `docs/ietf-draft-skeleton.md` §15.

## §16 Implementation considerations

Per `docs/ietf-draft-skeleton.md` §16.

## §17 Known limitations

Per `docs/ietf-draft-skeleton.md` §17 + `BLOCKERS.md`.

## §18 Proof and audit status

- **Machine-checked refinement proof**: `proofs/easycrypt/` (EC) +
  Lean bridges. 13/13 EC compile, 5/5 bridges, 0/0 admits.
  See `PROOF-CLAIMS.md`, `AXIOM-INVENTORY.md`,
  `TRUSTED-COMPUTING-BASE.md`, `FIPS-TRACEABILITY.md`.
- **Side-channel**: jasmin-ct 3/3 blocking on threshold layer;
  libjade sign advisory under #2.
- **External audit**: TBD — engagement post-submission.

## §19 Patent / IP declaration

Royalty-free patent grant per `PATENTS.md`. 21 numbered claims in
`docs/patent-claims.md`. Defensive termination extends to all
NIST-standardized PQ signature schemes.

---

**Document metadata**

- Name: `SPEC.md`
- Version: v0.1
- Date: 2026-05-18
- Companion docs: `spec/pulsar.tex` (PDF), `docs/ietf-draft-skeleton.md` (IETF), `SUITE.md` (suite index).
