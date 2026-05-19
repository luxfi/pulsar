# Magnetar — Public-DKG MPC Threshold SLH-DSA (research profile)

> **Tier 3 of the Hanzo PQ Threshold Suite.** Research-track
> construction for threshold FIPS 205 SLH-DSA via MPC. **NOT
> production-ready. NOT part of the v0.1 NIST MPTC submission.**

## What this document is

A placeholder + design-direction sketch for a future research-grade
public-DKG threshold construction over FIPS 205 SLH-DSA. The Hanzo
PQ Threshold Suite includes Magnetar to signal architectural intent
without overclaiming maturity.

## What this document is NOT

- Not a specification. The protocol is unfixed.
- Not a security claim. The protocol has not been analyzed.
- Not an implementation. No `ref/go/`-equivalent exists for Magnetar.
- Not a NIST submission. Submitting threshold SLH-DSA as if it
  were standardized would be inaccurate.

## Why Magnetar exists conceptually

SLH-DSA is hash-based and stateless (FIPS 205). Its security rests
on different assumptions from ML-DSA: collision/preimage resistance
of the underlying hash (SHA-2 or SHAKE), with no lattice
assumption.

A threshold profile of SLH-DSA gives a defense-in-depth signature:
even if ML-DSA's lattice assumption is broken in the future,
Magnetar's hash-based threshold provides a fallback.

## Why this is hard

Unlike threshold schemes for discrete-log-style or lattice-based
signatures, SLH-DSA does NOT decompose into a linear-aggregation
identity. The signing process is a tree of hash computations
(Merkle tree of hash-based one-time signatures), where the
"secret" is a SHAKE seed and "signing" involves traversing the
tree based on the message hash.

Threshold SLH-DSA constructions in the literature typically require:
- MPC over hash computations (slow; SHAKE computed inside MPC).
- Distributed seed generation with VSS.
- Per-signature MPC ceremony.

None of these match the elegance of FROST-style aggregation that
Pulsar uses for ML-DSA. Magnetar is a research-grade direction,
not an obvious specification target.

## Suggested research direction

1. **Distributed seed generation**: Lux-style Pedersen-VSS over
   the SHAKE seed space (32 or 64 bytes for FIPS 205 SHAKE
   profiles).

2. **Per-signature MPC**: a multi-party Generic-Group-Model
   ceremony to compute the SLH-DSA signature components without
   any single party reconstructing the seed.

3. **Hash precomputation amortization**: precompute layers of the
   FORS / W-OTS+ Merkle tree in batched MPC sessions to amortize
   the per-signature ceremony cost.

4. **Identifiable abort**: same TLV-encoded evidence format as
   Pulsar §10, with per-MPC-round per-party state.

5. **Public-key preservation across resharing**: standard
   zero-secret-refresh applied to the SHAKE seed shares.

## Parameter-set candidates

If the research direction matures into a specification, the
following parameter sets are candidates (matching FIPS 205 §4):

| Identifier | NIST Category | sig bytes | Notes |
|---|---|---|---|
| `MAGNETAR-THRESHOLD-SLH-DSA-SHAKE-128s` | 1 | 7856 | small/slow |
| `MAGNETAR-THRESHOLD-SLH-DSA-SHAKE-192s` | 3 | 16224 | RECOMMENDED if Magnetar matures |
| `MAGNETAR-THRESHOLD-SLH-DSA-SHAKE-256s` | 5 | 29792 | high security |

Note that SLH-DSA signatures are LARGE compared to ML-DSA
(7-30 KB vs 2-5 KB). The per-signature MPC cost will dominate
deployment economics.

## Why we do not ship Magnetar in v0.1

1. **No mature construction**: published threshold-SLH-DSA work is
   limited and not well-reviewed.
2. **MPC complexity**: per-signature MPC dwarfs the per-signature
   cost of Pulsar.
3. **Signature size**: 7-30 KB per signature is operationally
   expensive on-chain.
4. **Standardization status**: NIST has not signalled threshold
   SLH-DSA as a near-term MPTC target.

Magnetar will be re-evaluated for v0.2-v0.4 submission consideration
based on community / NIST direction.

## Honest framing for users

> Magnetar is the **research-track** member of the Hanzo PQ
> Threshold Suite. It is intended for paranoid scenarios where
> ML-DSA's lattice security assumption is broken in the future and
> a hash-based fallback is needed. It is NOT recommended for
> production use today. Use **Pulsar (Tier 1)** for production
> threshold post-quantum signing.

## Contact

For research collaboration on Magnetar:
- Email: `magnetar@lux.network`
- Public discussion:
  <https://github.com/luxfi/pulsar/discussions> (label: `magnetar`)

---

**Document metadata**

- Name: `docs/magnetar.md`
- Version: v0.1 (placeholder)
- Date: 2026-05-18
- Status: **Research direction, not specification.** No production
  use. No NIST submission claim.
