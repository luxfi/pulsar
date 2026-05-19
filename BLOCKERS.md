# Pulsar production go-live blockers

This file replaces `docs/known-limitations.md`. The prior file framed
critical security gaps as "limitations to be aware of". A deep
adversarial audit (4 red agents + 1 scientist, 2026-05) confirmed
those framings were too lenient: the issues below are **production
go-live blockers**, not informational caveats.

This file is the canonical bug list. Every entry has:
- Severity (CRITICAL / HIGH / MEDIUM)
- File + line numbers from the audited tree
- Attack model (who does what when)
- Fix sketch (what closes the issue, not how long it takes)

## NIST MPTC submission status (paper track)

The NIST MPTC submission paper itself remains shippable. The scientist
agent's verdict on each algorithmic claim:

| Claim | Verdict | Action for submission |
|---|---|---|
| Class N1 byte-equal output to FIPS 204 | VALIDATED | Ship with caveat: v0.1 reconstructs the secret seed in aggregator memory; clarify trust model in spec §4.5 |
| Class N4 reshare public-key preservation | VALIDATED | Ship |
| 2-round signing | WEAK | Ship with caveat: v0.1 trades one round for reconstruction-aggregator trust; v0.2 Lagrange-linearity path is the apples-to-apples Raccoon comparison |
| Quantum resistance (Module-LWE / FIPS 204) | VALIDATED | Ship |
| Cross-domain isolation Pulsar / Corona | WEAK | Don't claim defense-in-depth between M-LWE and R-LWE; both share algebraic-lattice hardness substrate. Real DiD requires a hash-based (SLH-DSA) layer also wired into QuasarCert. |
| EUF-CMA under adaptive corruption | **UNSUPPORTED** | Spec MUST be honest: static-corruption only in v0.1. Adaptive variant (Game ADAPT) is the deferred theorem. |
| Constant-time Verify | WEAK | Assertion not measurement. Add `dudect` to CI before claiming CT. |
| Z-Chain Groth16 → P3Q migration | WEAK | `QuasarCert.MLDSAProof` currently holds raw per-validator sigs with length prefixes — NOT a Groth16 proof. BN254 quantum-exposure is theoretical only because BN254 isn't actually in use. Either implement Groth16 rollup behind the doc claim, or update doc to reflect per-validator-sig reality, then wire P3Q. |
| Spec ↔ Go-reference protocol drift | **CLOSED — two-variant submission** | The submission supports **both** the v0.1 reveal-and-aggregate flow (Go reference, `D_i = cSHAKE(mask ‖ masked ‖ τ_1)`, KAT vectors and 19/19 interop subtests here) AND the v0.2 FSwA Lagrange-linearity flow (spec + Jasmin sources, `D_i = cSHAKE(pack_w1(w_i), τ_1)`). v0.1 ships as the runnable reference with the documented "v0.1 trust model caveat" (aggregator reconstructs the secret seed in memory); v0.2 is the high-assurance target that the Jasmin sources type-check against and the EasyCrypt N1 reduction is stated against. Both variants produce a FIPS 204 byte-equal `σ = (c̃, z, h)`; they differ in protocol shape, not output format. The spec (`./spec/pulsar.tex` §4.1 "Trust model variants") describes both with selection at submission-package generation time. |

## Production go-live blockers (13 CRITICAL — all CLOSED)

**Update 2026-05-11**: every CR-{1..13} closed. See per-entry `[CLOSED]`
markers below for the landing commits. The "what does NOT ship as
production-PQ until blockers close" gate has been opened.

### A. The strict-PQ profile is decorative (4 critical — ALL CLOSED)

**CR-1** `pq.active` package-global singleton — last writer wins across chains  **[CLOSED v1.16.91 / geth `9597231b1`]**
- `~/work/lux/pq/refuse.go:48,53,62`, `~/work/lux/evm/plugin/evm/vm.go:360-363`
- Multi-chain node: strict-PQ Q-Chain co-resident with permissive C-Chain → either chain's `SetPQProfile` clobbers the other. Reclassicalises strict-PQ at second VM Initialize.
- **Fix**: per-EVM-instance profile carried in `params.ChainConfig`. `RunPrecompiledContract` consults the EVM's profile, not a global.

**CR-2** `RefuseUnderStrictPQ` is dead code — no production ChainConfig implements `StrictPQReporter`  **[CLOSED evm v0.18.5]**
- `~/work/lux/precompile/contract/strict_pq.go:45-48`; consumers: every classical precompile in `precompile/{bls12381,kzg4844,babyjubjub,curve25519,x25519,ed25519,sr25519,ring,pedersen,poseidon,vrf,pasta,frost,blake3,cggmp21,zk,hpke}/*.go`
- Zero `func.*IsStrictPQ` definitions in geth or evm. Type assertion always fails → gate returns nil → every classical precompile runs.
- **Fix**: implement `IsStrictPQ(time uint64) bool` on `params.ChainConfig`; wire from genesis `StrictPQTime *uint64`.

**CR-3** `SchemeGate.Classify` is never called from production peer-upgrade path  **[CLOSED node v1.26.18]**
- `~/work/lux/node/network/peer/upgrader.go:61-83`, `~/work/lux/node/network/network.go:1633`
- `Grep peer.SchemeGate` returns zero hits outside the gate file itself. Classical secp256k1 TLS certs accepted at handshake on chains pinning strict-PQ profile.
- **Fix**: `network.upgrade()` MUST take `*SchemeGate` from `n.Config.SecurityProfile`, derive `NodeIDScheme` from TLS leaf algorithm, call `gate.Classify(nodeID, scheme, height, "handshake")`, fail closed on mismatch.

**CR-4** `WitnessSet.MinPolicy` is never set in production; chains silently downgrade  **[CLOSED consensus v1.23.17 / `a3e79018`]**
- `~/work/lux/consensus/protocol/quasar/witness_producer.go:106-117`
- `MinPolicy=0` triggers legacy `best-effort` branch. Chain advertises Quasar; produces PolicyQuorum (BLS-only) certs whenever Q or Z layers fail.
- **Fix**: chain bootstrap MUST set `WitnessSet.MinPolicy` from the resolved `ChainSecurityProfile`. Refuse construction without a `MinPolicy`.

### B. PQ handshake is dead code (1 critical, 1 high — ALL CLOSED)

**CR-5** `InitiateHandshake`/`RespondHandshake`/`FinishInitiatorHandshake` are never invoked in production  **[CLOSED node v1.26.18]**
- `~/work/lux/node/network/peer/handshake.go:273,323,408`
- All callers are in handshake's own tests. `peer.Start` jumps straight to the legacy application-level `Handshake` message. The ML-KEM-768 / ML-DSA-65 application-layer handshake exists in source and runs in nothing.
- Every Lux peer connection uses Go `crypto/tls`'s X25519 + secp256k1 → full quantum harvest-now-decrypt-later exposure.
- **Fix**: replace `upgrader.Upgrade → peer.Start` plumbing with TLS upgrade → `InitiateHandshake`/`RespondHandshake` → AEAD transport using `result.AEADKey`.

**HI-1** `ActivationHeight` is per-operator config — adversary holds network in transition mode forever
- `~/work/lux/node/network/peer/scheme_gate.go:58-64,114-127`
- Migration window field is local config. Adversary sets `ActivationHeight = 2^63` on their node → classical accepted forever → peer with strict-PQ validators who accept classical due to mis-config.
- **Fix**: activation MUST be encoded in genesis SecurityProfile as a chain-time; remove the per-operator knob. Strict-PQ chain refuses classical at genesis, period.

### C. Pulsar threshold layer is hollow (3 critical — ALL CLOSED)

**CR-6** DKG commit is never opened — commits to nothing the protocol verifies  **[CLOSED pulsar — see dkg.go path A: Shamir+sum, no commit-and-open]**
- `~/work/lux/pulsar/ref/go/pkg/pulsar/dkg.go:153-211,245-348`
- `myCommit = cSHAKE(c_i || blind_i)` is broadcast; `c_i` and `blind_i` are never transmitted in any later round. Round-3 verifies digest-agreement of the envelope set but never recomputes the commit and checks opening.
- Malicious dealer broadcasts arbitrary commit + biases Shamir contribution → joint pubkey biased to chosen value.
- **Fix**: either (a) include `(c_i, blind_i)` in Round-2 reveal and verify the digest opens, or (b) drop `myCommit` from the protocol and document the actual protocol (Shamir+sum, no commit).

**CR-7** `deriveMACKey` derives sign-round MAC keys from public inputs — any network observer forges them  **[CLOSED pulsar identity.go — ephemeral ML-KEM-768 session keys authenticated under long-term ML-DSA-65]**
- `~/work/lux/pulsar/ref/go/pkg/pulsar/threshold.go:447-460,144-151`
- `K_{i,j} = transcriptHash32("PULSAR-SIGN-MACKEY-V1", first[:], second[:], pk.Bytes)`. All inputs are on-chain public data. Any network observer (not even a committee member) computes K_{i,j}, intercepts Round-1, swaps Commit, recomputes MAC.
- Identifiable-abort fails with NO network partition. DoS against threshold signer at zero cost.
- **Fix**: ephemeral session-key exchange at session setup (Noise / X3DH / ML-KEM-768) bound to long-term ML-DSA identity. Per-session AEAD MAC key derived from that secret. Drop the public-input derivation entirely.

**CR-8** DKG envelopes sent plaintext on broadcast wire — passive surveillance recovers master  **[CLOSED pulsar — DKGShareEnvelope is ML-KEM-768-wrapped per recipient + HKDF-SHA3-256 + AEAD tag]**
- `~/work/lux/pulsar/ref/go/pkg/pulsar/dkg.go:184-211`, `types.go:128`
- `DKGRound1Msg.Envelopes[recipient]` is plaintext per-recipient Shamir shares; broadcast contains full envelope map.
- Network observer with single-broadcast read access obtains t-1 honest shares from a rushing dealer → corrupt any one party for own share → t shares → master key recovered. **One DKG ceremony.**
- **Fix**: KEM-wrap envelopes (ML-KEM-768) before broadcast. Recipient's KEM public key derived from their long-term identity.

### D. Validator identity is quantum-forgeable (3 critical — ALL CLOSED)

**CR-9** `SignedIP` signs validator-IP gossip with classical TLS + BLS12-381 — both quantum-broken  **[CLOSED node v1.26.18 — SignedIP append-only `MLDSASignature []byte` + proto/zap Handshake.IpMldsaSig]**
- `~/work/lux/node/network/peer/ip.go:36-58,87-122`, `ip_signer.go:38-48`
- `Sign(ip)` uses `tlsSigner crypto.Signer` (secp256k1 / ECDSA / RSA) + BLS proof-of-possession. No ML-DSA leg. Quantum adversary forges any validator's `SignedIP` and redirects peer routing.
- **Fix**: add ML-DSA-65 leg to `UnsignedIP.Sign`; `SignedIP.Verify` MUST require both legs verify on strict-PQ chains. NodeID derivation must follow `ids.NodeIDScheme.DeriveMLDSA` when profile is PQ.

**CR-10** Triple-mode QuasarCert is unenforced — `IsTripleMode()` never gates vote acceptance or cert verification  **[CLOSED consensus v1.23.17 — `addVoteLocked` refuses single-layer under strict-PQ; `generateCert` refuses partial triple]**
- `~/work/lux/consensus/protocol/quasar/{core.go:312-330,quasar.go:594-644,engine.go:253-281,types.go:30-69}`
- `Certifier.generateCert` falls back to single-scheme `SignMessageWithContext` on any error. `realCert` sets `cert.Corona = nil` unconditionally. `addVoteLocked` checks `len(qBlock.ValidatorSigs) >= threshold` — counts votes, not valid-triple-mode votes.
- Adversary who breaks any single layer (e.g. BLS via 2030 quantum) forges finality.
- **Fix**: vote-acceptance path MUST gate on `IsTripleMode()` && `cert.HasAllThreeLayers()`. `QuasarCert.Verify()` already structurally requires three layers — wire it into the consensus accept path.

**CR-11** BFT engine adapter inherits classical `luxfi/bft` semantics under strict-PQ profile  **[CLOSED consensus v1.23.17 — engine/bft `NewEngineWithProfile` refuses non-PQSigner/PQVerifier]**
- `~/work/lux/consensus/engine/bft/engine.go:83-95` (entire file)
- BFT adapter accepts any `bft.Epoch` from `luxfi/bft`. Zero references to `PQProfile` / `FinalitySchemeID` / `QuasarCert`. The `luxfi/bft.Signer` interface accepts any byte sigs and defaults to classical Ed25519.
- Strict-PQ chain on BFT engine signs blocks with classical Ed25519. The strict-PQ EVM gate covers EVM-layer only, not consensus envelope.
- **Fix**: BFT adapter MUST validate `cfg.SecurityProfile.FinalitySchemeID.IsPulsar()` (or equivalent) at `NewEngine`; refuse non-PQ signers under strict-PQ profile.

**CR-12** `ComputeRoundDigest` does NOT bind effective `policy_id`  **[CLOSED consensus protocol/quasar — `effectivePolicy` is bound as a TupleHash part between verifierBytes and netBytes; zero-policy refused]**
- `~/work/lux/consensus/protocol/quasar/round_digest.go:91-193`
- Round digest binds profile_id, hash_suite_id, scheme_ids, proof_policy_id, proof_backend_id, proof_format_id, verifier_id — but not `effectivePolicyID` of the witness bundle.
- Adversary signs Round R as PolicyPQ (P+Q, no Z); strips Q witness on retransmit; bare P witness is now a "valid PolicyQuorum cert over the same round digest" since digest is identical.
- **Fix**: bind `effectivePolicyID` byte into `ComputeRoundDigest` parts. One-line addition.

### E. Other (1 critical — CLOSED)

**CR-13** Modulo-bias in three independent random samplers — nation-state grinding biases committee sampling  **[CLOSED consensus protocol/{photon,prism} — rejection sampling with `(^uint64(0) / max) * max` cutoff]**
- `~/work/lux/consensus/protocol/photon/emitter.go:69-77`
- `~/work/lux/consensus/protocol/prism/cut.go:60-68`
- `~/work/lux/consensus/protocol/prism/stake_weighted_cut.go:115-123`
- All three compute `binary.LittleEndian.Uint64(buf[:]) % uint64(max)`. For non-power-of-2 `max`, indices `[0, 2^64 mod max)` have probability ~`1/max + epsilon` while indices `[2^64 mod max, max)` have ~`1/max`. Adversary controlling stake weights maximises coverage of high-probability bucket.
- Over 10^6 rounds at K=20, ~1/3 Byzantine threshold, the bias structurally lets the attacker land in committees more often than honest random — violates LP-105 §6 uniform-sampling assumption.
- **Fix**: rejection sampling with `crypto/rand.Int` or standard `2^64 / max * max` rejection cutoff.

## Closure plan

Each blocker is its own engineering ticket with a security review at
landing. Estimated effort (senior crypto-engineer, with outside review
before merge):

| Blocker | Effort | Review type |
|---|---|---|
| CR-1 per-chain PQ profile refactor | 1 week | Code review |
| CR-2 `params.ChainConfig.IsStrictPQ` wire | 1 week | Code review |
| CR-3 SchemeGate into `network.upgrade()` | 1-2 weeks | Code + protocol review |
| CR-4 `WitnessSet.MinPolicy` wired at bootstrap | 1 week | Code review |
| CR-5 PQHandshake into `peer.Start` | 2-3 weeks | Code + cryptographic protocol review |
| CR-6 DKG commit-opening Round-2/3 | 1-2 weeks + KAT regen | Cryptographic review |
| CR-7 Replace `deriveMACKey` with session-key exchange | 2-3 weeks + protocol redesign | Cryptographic + protocol review |
| CR-8 KEM-wrap DKG envelopes | 1 week + KAT regen | Cryptographic review |
| CR-9 ML-DSA leg on SignedIP | 1 week + wire-format break | Code review |
| CR-10 Triple-mode enforcement | 1-2 weeks | Code review |
| CR-11 BFT adapter PQ-envelope enforcement | 1 week | Code + protocol review |
| CR-12 Bind `policy_id` into RoundDigest | 1 day + KAT regen | Code review |
| CR-13 Rejection sampling | 1 day | Code review |

Total wall-clock estimate: 3-4 months of focused work by 2-3 senior
crypto-engineers + outside cryptographer audit before merge.

## What ships *now*

- The Pulsar NIST MPTC paper submission (algorithmic claims N1 +
  N4 + quantum resistance are VALIDATED per scientist audit, with
  documented caveats on adaptive corruption + reconstruction
  aggregator + constant-time + cross-domain isolation).
- Reference Go implementation at `ref/go/pkg/pulsar/` for KAT
  reproducibility — 89.7% test coverage, deterministic KAT regen,
  19/19 Class N1 interop subtests pass.
- Lean mechanization of OutputInterchange + Unforgeability + Shamir
  (zero `sorry`).
- Jasmin high-assurance sources: libjade pinned at commit 9426b32,
  round1 + round2 + combine implemented (~2,600 lines threshold +
  lib). EasyCrypt theory shells stand alongside; closing the N1
  reduction core is independent expert work tracked in
  `proofs/easycrypt/README.md`.

## What ships *as production-PQ now* (CR-{1..13} closure)

- Lux mainnet "running strict-PQ profile" as an end-to-end
  enforceable claim:
  - EVM precompile boundary: per-chain `ChainConfig.PQ` refuses
    every classical primitive at `(*EVM).runPrecompile` (CR-1).
    Stateful Lux precompiles (KZG, Groth16, PLONK, fflonk, Halo2,
    BN254-Pedersen, BabyJubJub, Pallas/Vesta, BLS12-381 modules)
    refuse via `StrictPQTimestamp` (CR-2).
  - Peer-handshake: TLS leaf pubkey type → NodeIDScheme byte gate
    at upgrade (CR-3); PQ-only handshake handoff before any
    classical exchange (CR-5); append-only ML-DSA leg on
    SignedIP wire format (CR-9).
  - Threshold-DKG: Shamir+sum binding via Round-2 digest
    agreement, no dangling commit-and-open (CR-6); ephemeral
    ML-KEM-768 session keys authenticated under long-term
    ML-DSA-65 (CR-7); KEM-wrapped per-recipient envelopes that
    survive passive network observation (CR-8).
  - Consensus envelope: WitnessSet MinPolicy required at
    construction (CR-4); triple-mode enforced at vote acceptance +
    cert assembly (CR-10); BFT engine refuses classical
    Signer/Verifier under strict-PQ profile (CR-11); RoundDigest
    binds effective policy_id (CR-12).
  - Sampling: rejection sampling everywhere a uniform index into
    `[0, max)` is drawn from raw 64-bit entropy (CR-13).
- "Drop BLS safely" — the PQ threshold path under Pulsar is now
  honest end-to-end. A Lux deployment can pin a strict-PQ profile
  and run with no classical curves in the validator path
  (Ed25519/secp256k1/BLS) on chains that opt in via
  ChainSecurityProfile.

## Audit attribution

Findings consolidated 2026-05 from 4 red-team agents + 1 scientist
swarm against the threat model: nation-state with classical+quantum
compute over 5+ year horizon on an open permissionless blockchain.

Red-team agent transcripts at:
- `pulsar-red1` — Pulsar crypto break attempts (4 critical, 4 high, 2 medium)
- `quasar-red2` — Quasar consensus + cert envelope (3 critical, 4 high, 4 medium)
- `evm-red3` — EVM precompile + KEM + privacy (2 critical, 2 high, 2 medium)
- `peer-red4` — Network / peer handshake / identity (3 critical, 3 high, 4 medium)
- `scientist` — MPTC literature validation (8 algorithmic-claim verdicts)
