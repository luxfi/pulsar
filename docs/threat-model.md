# Pulsar-M threat model

## Adversary classes

We give an adversary the union of the following capabilities, parameterized
by `t` (the corruption threshold) and the corruption model:

### Static corruption (default)

- Adversary `A` selects up to `t-1` parties to corrupt **before** protocol
  start. From start to end of the protocol, those `t-1` parties are
  controlled; the remaining honest parties run the protocol faithfully.
- `A` sees all messages on the broadcast channel + all messages on the
  authenticated point-to-point channels into corrupted parties.
- `A` learns each corrupted party's full state (secret share, randomness,
  per-round values) including session-state values.
- `A` can selectively delay messages within the round window but cannot
  forge messages from honest parties on authenticated channels.

### Adaptive corruption (stronger model)

- Adversary `A` can corrupt up to `t-1` parties at any time during the
  protocol, including mid-round, conditioned on the transcript so far.
- Once corrupted, a party remains corrupted for the rest of the protocol.
- All other capabilities as in static.

The Pulsar-M security analysis (`spec/security-games.tex`) provides the
precise game definitions. Static security is the baseline; adaptive
security is a stretch goal for the first MPTC submission and a hard
requirement for the second-round response.

### Mobile corruption (proactive resharing)

For long-lived deployments where the validator set rotates between epochs
(Pulsar's `reshare/` direction), the relevant model is HJKY97 mobile
adversary: `A` can corrupt up to `t-1` parties **per epoch**, with the
corruption set varying across epochs. The adversary may *uncorrupt* a
party (forget what it learned) at epoch boundaries.

Pulsar-M proactive resharing inherits the soundness argument from Pulsar's
`reshare/` (with the constant-time fix from F9 of the Hanzo HIP-0077
red review). The MPTC submission documents the mobile-adversary game
explicitly.

## Out-of-scope adversary capabilities

- Compromise of the cryptographic hash function (SHAKE-256 / cSHAKE-256 /
  KMAC-256). NIST FIPS 202 + SP 800-185 are taken as building blocks.
- Side-channel attacks on the *physical* hardware running a party
  (power analysis, EM, fault injection). Mitigation discussed in
  `docs/known-limitations.md` as future work.
- Compromise of the BIP-32/BIP-39 mnemonic from which device-specific
  keys are derived. The HD-derivation security argument lives in
  HIP-0077 §"Identity"; the Pulsar-M layer assumes parties' input keys
  are uniformly distributed.

## In-scope security goals

### Threshold unforgeability (TS-UF)

For any PPT adversary `A` controlling up to `t-1` parties, `A` cannot
produce a valid Pulsar-M signature `σ*` on any message `μ*` that an
honest signing ceremony has not produced.

### Robustness / identifiable abort

If a corrupted party deviates from the protocol, the honest parties:
1. Detect the deviation.
2. Identify the deviating party.
3. Produce signed evidence of the deviation suitable for slashing /
   reputation reduction.

### Output indistinguishability from FIPS 204

A Pulsar-M signature `σ` on message `μ` against group public key `pk`
is computationally indistinguishable from a FIPS 204 ML-DSA signature on
the same `(pk, μ)`. Specifically: an adversary that can distinguish the
two with non-negligible advantage breaks the underlying M-LWE assumption.

### Bias resistance

The randomness used in each party's contribution (Gaussian samples,
challenge polynomials) is statistically indistinguishable from uniform
even given the adversary's view of corrupted parties' randomness.

### DKG soundness

Pedersen DKG over `R_q^k` produces a public key `pk` distributed
uniformly over the valid M-LWE public-key space, with no party holding
more than `1/n` partial information about the corresponding secret key.

## Assumed channels

| channel | property | purpose |
|---|---|---|
| Broadcast | authenticated, eventual-delivery | round transcripts, public coins |
| Point-to-point | authenticated, encrypted | private share / blind delivery |
| Public bulletin | authenticated, append-only | DKG commitments, reshare records |

The reference implementation provides these channels via TCP + TLS.
Production deployments (e.g. Lux consensus + Quasar) bind these to
their existing P2P transport.

## Trusted parameters

- The cyclotomic ring `R_q = Z_q[X] / (X^256 + 1)` and parameters
  `(q, k, ℓ, η, β, ω, …)` exactly as in FIPS 204 ML-DSA-65.
- The hash family: SHAKE-256 (FIPS 202), cSHAKE-256 / KMAC-256 /
  TupleHash-256 (NIST SP 800-185). Customization tags are pinned in
  `spec/pulsar-m.tex`.
- The Gaussian sampler parameters from FIPS 204 §3.3 / §4.2.

No trusted setup beyond NIST primitives.

## Failure modes addressed

The MPTC submission documents how Pulsar-M handles each failure mode that
broke earlier threshold-lattice schemes:

- **Rejection-sampling restart leaking secret information across rounds**:
  Pulsar's PRNG-key per-round domain separation (CRIT-1 fix from
  upstream's 2026-05-03 amendment) ports forward.
- **Constant-time share comparison**: `dkg2.constTimePolyEqual` pattern
  ported from upstream Pulsar (`reshare/commit.go` F9 fix).
- **Information leaks via logging**: zero stdlib `log` use in any
  secret-touching path; all logging via `luxfi/log` at fields that are
  explicitly public.
- **Deterministic quorum selection in resharing leaking adversary
  positioning**: Pulsar-M uses a beacon-derived per-reshare quorum
  selection (HIP-0077 §"reshare quorum" F10 fix).
- **Cross-mode hash-suite confusion**: NIST profile is exclusively
  SHA-3 family; no BLAKE3 in Pulsar-M ever.
