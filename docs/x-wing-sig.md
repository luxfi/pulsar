# X-Wing-Sig — Hybrid PQ Signature Wrapper

> **Proposed construction.** Not yet specified as an LP. Not yet
> implemented. This document captures the design direction per user
> request: "ala X-Wing but for older crypto wallets".

## Context

X-Wing (LP-115) is the **hybrid PQ KEM** (X25519 + ML-KEM-768)
adopted by Lux for key encapsulation. There is no equivalent
hybrid PQ signature scheme in the Lux suite today.

X-Wing-Sig fills that gap: a hybrid PQ signature wrapper that
combines a classical signature (Ed25519 / ECDSA) with a PQ
signature (ML-DSA / SLH-DSA) into a single signature byte string.

## Construction

```
HybridSig(sk_classical, sk_pq, M)
  := Sign_classical(sk_classical, DOMAIN ++ M)
     || Sign_pq(sk_pq,            DOMAIN ++ M)
  where DOMAIN = "X-WING-SIG-v0||<ciphersuite_id>||"

HybridVerify(pk_classical, pk_pq, M, sig)
  := let (s_c, s_p) = split sig at classical_len
     Verify_classical(pk_classical, DOMAIN ++ M, s_c)
       ∧ Verify_pq(pk_pq, DOMAIN ++ M, s_p)
```

Both signatures MUST verify for `HybridVerify` to accept.

## Parameter sets

| Identifier | Classical | PQ | Total sig bytes |
|---|---|---|---|
| `X-WING-SIG-Ed25519-MLDSA-65` | Ed25519 (64 B) | ML-DSA-65 (3309 B) | 3373 |
| `X-WING-SIG-ECDSA-P256-MLDSA-65` | ECDSA P-256 (~71 B) | ML-DSA-65 (3309 B) | ~3380 |
| `X-WING-SIG-Ed25519-MLDSA-87` | Ed25519 | ML-DSA-87 | ~4691 |
| `X-WING-SIG-Ed25519-SLHDSA-SHAKE-192s` | Ed25519 | SLH-DSA-SHAKE-192s | ~16288 |

Most deployments will use `X-WING-SIG-Ed25519-MLDSA-65` for the
balance of signature size and security category.

## Security goals

- **Forgery requires breaking both schemes**: an adversary
  producing a valid hybrid signature must produce a valid
  classical AND PQ signature for the same domain-separated
  message.
- **Composition robust**: classical scheme's failure (e.g.,
  Shor's-algorithm-broken ECDSA on a quantum computer) does NOT
  weaken the PQ scheme's protection.
- **PQ scheme's failure** (e.g., future ML-DSA cryptanalytic
  break) does NOT weaken classical scheme's protection during the
  transition window.

## Use cases

1. **Legacy wallet migration**: hardware wallets pinned to ECDSA
   (e.g., older Ledger / Trezor firmware) can continue to sign
   with ECDSA while the user gradually upgrades to PQ-native.
2. **Federal compliance during PQ transition**: FIPS-validated
   classical modules continue to operate while the PQ component is
   added.
3. **Defense-in-depth**: paranoid scenarios (e.g., long-lived
   secrets like root certificate authorities, multi-decade
   archival signatures) sign with both schemes to hedge against
   either being broken.

## Migration path for Lux native chains

For C-Chain (EVM-compatible) and X-Chain (UTXO):

1. **Soft fork — wallets**: introduce a new wallet account type
   that signs with X-Wing-Sig. Existing ECDSA-only accounts
   continue to work.
2. **Soft fork — validators**: validators accept either the legacy
   ECDSA signature OR the X-Wing-Sig hybrid signature for the same
   account. Old wallets continue working; new wallets are
   PQ-protected.
3. **Account upgrade**: when a user upgrades their wallet, the
   account's authorized signature scheme rotates to X-Wing-Sig.
   Old ECDSA-only signatures become invalid for that account
   going forward.
4. **PQ-native fork** (much later): drop ECDSA support after
   sufficient migration window. C-Chain becomes PQ-only.

This soft-fork-first migration matches the X-Wing-KEM rollout
pattern (LP-115).

## Threshold variant

Trivially threshold-izable: run a threshold instance of each
underlying scheme and concatenate the outputs.

```
ThresholdHybridSig(Q, [sk_classical_i], [sk_pq_i], M)
  := FROST(Q, [sk_classical_i], DOMAIN ++ M)
     || PULSAR(Q, [sk_pq_i],    DOMAIN ++ M)
```

This becomes "FROST × Pulsar" — the natural threshold-X-Wing-Sig.
Should be specified as a future revision of LP-019.

## Open design questions

1. **Domain separation**: should `DOMAIN` include the wallet account
   identifier to prevent cross-account replay?
2. **Verification order**: classical-first or PQ-first? (Doesn't
   affect security; affects gas cost on EVM verification.)
3. **Signature ordering**: classical-first || PQ-first or vice
   versa? Pick one for the standard.
4. **PQ scheme choice**: ML-DSA-65 is the obvious default for
   signature-size + speed; SLH-DSA available for the paranoid.
5. **Hashed-message-binding**: should both schemes sign the same
   hash of `DOMAIN ++ M` or `DOMAIN ++ M` directly? Both work; the
   hashed-binding form is slightly smaller and gas-cheaper to
   verify.

## Estimated effort

- LP draft: 1-2 weeks (collect community feedback on the open
  design questions above).
- Reference implementation (Go in `~/work/lux/crypto/x-wing-sig/`):
  1 week.
- Lean composition proof (`hybrid_secure ⇐ classical_secure ∨ pq_secure`):
  2-3 weeks.
- Test vectors (cross-validated against pq-crystals + cloudflare/circl):
  1 week.
- C-Chain / X-Chain wallet integration: 4-8 weeks (coordinated
  with consensus rollout).

Total to v0.1 IETF draft: ~2 months.

## Cross-references

- LP-115: X-Wing (KEM) — the parent design pattern.
- LP-019: Threshold MPC — FROST + CGGMP21 (classical-side primitives).
- `./`: Pulsar (PQ threshold ML-DSA) — the PQ-side primitive.
- LP-078: EVM precompiles — gas-cost model for on-chain hybrid
  verification.
- LP-134: C-Chain + X-Chain topology — deployment target.
- This document: `./docs/x-wing-sig.md`.
- Suite-level inventory: `./HANZO-CRYPTO-SUITE.md` §3.

## Honest framing

X-Wing-Sig is a **proposed design direction**, not a specification.
It is documented here because the user identified it as a
necessary suite member ("ala X-Wing but for older crypto
wallets"). Implementation, formal specification, and security
analysis are open work.

For production hybrid-PQ signing TODAY, use Pulsar (Tier 1) with
the application providing the optional classical signature
out-of-band. X-Wing-Sig will codify this pattern when the LP
lands.

---

**Document metadata**

- Name: `docs/x-wing-sig.md`
- Version: v0.1 (design direction; not specification)
- Date: 2026-05-18
- Status: **proposed**; LP not yet drafted; no implementation
