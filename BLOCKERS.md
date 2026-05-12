# Pulsar production go-live blockers

This file replaces the prior `spec/known-limitations.tex` framing.
The 4-red-agent + 1-scientist adversarial audit (2026-05) found that
the v0.1 reference implementation in `ref/go/pkg/pulsarm/` has
critical security gaps that block production deployment as a
strict-PQ threshold signer on an open public permissionless
blockchain under nation-state threat model.

The canonical, fully-detailed list with file:line refs, attack
models, and fix sketches lives at the **submission** mirror:

> <https://github.com/luxfi/pulsar-mptc/blob/main/BLOCKERS.md>

This `BLOCKERS.md` file is the production-library mirror. The
13 CRITICAL findings are summarised below; consult the submission
mirror for the canonical specification of each.

## 13 critical findings (summary)

### A. Strict-PQ profile is unenforced

1. **CR-1** `pq.active` is a process-global singleton. Multi-chain
   nodes hosting strict-PQ + permissive chains have last-writer-wins
   semantics.
2. **CR-2** `RefuseUnderStrictPQ` is dead code — no production
   ChainConfig implements `StrictPQReporter`. Every classical
   precompile (BLS12-381, KZG, alt_bn128, BabyJubJub, BLAKE3, etc.)
   runs on chains pinning strict-PQ profile.
3. **CR-3** `SchemeGate.Classify` is never called from
   `network.upgrade()`. Classical secp256k1 TLS certs are accepted
   at peer-handshake time on strict-PQ chains.
4. **CR-4** `WitnessSet.MinPolicy` is never wired in production.
   Chains silently downgrade from PolicyQuantum → PolicyQuorum
   (BLS-only) under partial fault.

### B. PQ handshake is dead code

5. **CR-5** `InitiateHandshake` / `RespondHandshake` /
   `FinishInitiatorHandshake` in `network/peer/handshake.go` are
   never invoked in production. Every peer connection uses Go
   `crypto/tls` (X25519 + secp256k1) — full quantum HNDL exposure.

### C. Pulsar-M threshold layer is hollow

6. **CR-6** DKG commit (`cSHAKE(c_i || blind_i)`) is never opened
   in any later round. Malicious dealer biases joint pubkey.
7. **CR-7** `deriveMACKey` derives MAC keys from PUBLIC inputs
   (pk + node IDs). Any network observer forges Round-1 messages
   → identifiable-abort fails with NO partition.
8. **CR-8** DKG envelopes are plaintext on the broadcast wire.
   Passive surveillance recovers master key in one DKG ceremony.

### D. Validator identity is quantum-forgeable

9. **CR-9** `SignedIP` signs validator-IP gossip with classical TLS
   + BLS12-381. Both quantum-broken. Nation-state forges any
   validator's IP claim.
10. **CR-10** Triple-mode QuasarCert is unenforced. `IsTripleMode()`
    exists but never gates vote acceptance or cert verification.
11. **CR-11** BFT engine adapter inherits classical `luxfi/bft`
    semantics under strict-PQ profile. No PQ-envelope enforcement.
12. **CR-12** `ComputeRoundDigest` does NOT bind effective
    `policy_id`. Cross-policy replay possible.

### E. Other

13. **CR-13** Modulo-bias in three independent random samplers
    (`photon/emitter.go`, `prism/cut.go`, `prism/stake_weighted_cut.go`).
    Nation-state grinding biases committee sampling.

## What ships now

- The Pulsar Go library at v1.0.x as a **research / reference**
  implementation. NIST submission paper-ready.
- Lean mechanization of OutputInterchange + Unforgeability + Shamir
  (zero `sorry`).
- 89.7% test coverage on the reference impl.
- KAT vectors with deterministic regen and Class N1 E2E interop
  via cloudflare/circl FIPS 204 verifier.

## What does NOT ship as production strict-PQ until blockers close

- Lux mainnet as an end-to-end strict-PQ enforceable claim.
- "Drop BLS safely" — current Pulsar threshold layer without BLS
  would leave the chain with an unopened-DKG, forgeable-MAC, plaintext-
  envelope finality primitive. BLS is presently the floor; dropping
  it without closing CR-6/7/8 removes the floor.

Estimated remediation: 3-4 months of senior crypto-engineering plus
outside cryptographer review and KAT regen.

See the submission mirror at <https://github.com/luxfi/pulsar-mptc/blob/main/BLOCKERS.md>
for full per-finding details.
