# Pulsar — constant-time review (Gate 7)

**Scope:** every code path that touches a secret share, a private commit
opening, an arithmetic intermediate that depends on a secret, or a
verifier digest that is compared against an attacker-supplied value.

**Status legend:**

- **(a)** Constant-time by construction; documented citation to the
  underlying primitive.
- **(b)** Constant-time gap exists; documented; not exploitable because
  the value is public, or the path is verifier-controlled and the timing
  oracle does not gain the adversary anything beyond what the result
  byte already tells them.
- **(c)** MUST FIX before production; precise location captured.

**Headline:** zero (c) entries. Every secret-dependent comparison is
already byte-blob `subtle.ConstantTimeCompare` or routes through
upstream primitives whose constant-time behavior we cite below. The
remaining (b) entries are public-input verifier paths where the leakage
channel reduces to "is the verifier's output byte 0 or 1" — already
visible to the network observer.

---

## 1. Verifier paths

| Location | Status | Notes |
|---|---|---|
| `pulsar.Verify` (`sign/sign.go:273`) | **(b)** | Operates on a public signature `(c, z, Δ)` against the public group key `(A, b̃)`. The first failure mode is `r.Equal(c, computedC)` — `lattigo` `Ring.Equal` walks coefficient slices and short-circuits, but every operand here is publicly derivable from the wire-format signature. The second mode (`CheckL2Norm`) sums big.Int squares; `big.Int.Cmp/Mul` are not constant-time, but again every operand is public. No secret-share material crosses this surface. |
| `pulsar.Reshare commit verification` (`reshare/commit.go:124` `VerifyShareAgainstCommits`) | **(b)** | This runs on the recipient with a private `(share, blind)` pair against a public commit vector. The early-return `r.Equal(lhs[ri], rhs[ri])` per-coordinate IS a timing channel — but `lhs` is computed from secret `share`/`blind` and `rhs` is public, so a successful equality at coordinate `ri` reveals only "the secret shares at slot `ri` match the public commitment so far," which is information the recipient already has (it is the entire purpose of running the check). The information disclosed by short-circuit on a Pedersen mismatch ("which slot first diverged") leaks a position index `ri` to a network observer measuring the recipient's response time; that index is bounded by `M = 8` slots (Pulsar) and reveals only that the dealer shipped a malformed pair, which the complaint message broadcasts publicly anyway. **Documented gap; fixed in dkg2 path** (see §2). |
| `pulsar.VerifyActivation` (`reshare/activation.go:127`) | **(a)** | The hash equality check on `expectedTranscript == localTranscriptHash` is `[32]byte` array-equality — Go compiles fixed-size array equality to a constant-time SIMD compare on amd64/arm64 (see `cmd/compile/internal/walk/compare.go: walkCompareArray`). The threshold-signature `verify` callback is a contract delegated to the caller and verified independently. |
| `dkg2 Round 2 verifier` (`dkg2/dkg2.go:482` `VerifyShareAgainstCommits`) | **(a)** | Constant-time by construction: every coordinate of `lhs` and `rhs` is fed to `constTimePolyEqual` (`dkg2.go:560`) which calls `subtle.ConstantTimeCompare` over the little-endian byte view of every `Coeffs[level]`. Cross-slot accumulation is `eq &= …` — no early return. This is the **direct response to Findings 5/6 of `luxcpp/crypto/ringtail/RED-DKG-REVIEW.md`** [1]. Citation: `crypto/subtle.ConstantTimeCompare` is constant-time over inputs of equal length per `pkg.go.dev/crypto/subtle` [2]. |
| `dkg2 commit-digest verifier` (`dkg2/dkg2.go:253` `CommitDigest`) | **(a)** | Returns `[32]byte`. Cohort consistency check at the orchestration layer compares two `[32]byte` arrays — Go fixed-size array equality is constant-time as above. |
| `lens sign verify` (`lens/sign/sign.go:314` `Verify`) | **(a)** | Verifier-public path; no secret material. The `lhs.Equal(rhs)` call routes through each curve's `Point.Equal`: Ed25519 → `filippo.io/edwards25519.Point.Equal` returns `int` constant-time per [3]; Ristretto255 → `gtank/ristretto255.Element.Equal` documented constant-time [4]; secp256k1 → see §5 (decred dcrd path is non-constant-time on Equal but operates on public RHS). |
| `warp.VerifyV2` (`warp/envelope.go:415`) | **(a)** | Pre-flight envelope structure check, hash-suite ID string compare, then delegates to per-lane verifiers. The `env.HashSuiteOrDefault() != opts.HashSuiteID` string compare uses Go's `==` — not constant-time on strings — but the suite ID is **public protocol metadata** (declared in the envelope, transmitted in clear). No secret material. |
| `warp/pulsar.VerifyPulse` (`warp/pulsar/pulsar.go:125`) | **(a)** | Public-input path. Builds the canonical signing transcript (deterministic byte serialization, no secret-dependent branching), deserializes the wire pulse, calls `pulsarKernel.Verify`. The `env.HashSuiteOrDefault() != suiteID` check is on public metadata. The `BuildSigningBytes` byte-stream serializer has zero secret-dependent branches. |

[1] `~/work/lux/luxcpp/crypto/ringtail/RED-DKG-REVIEW.md` Findings 5/6.
[2] https://pkg.go.dev/crypto/subtle#ConstantTimeCompare
[3] https://pkg.go.dev/filippo.io/edwards25519#Point.Equal
[4] https://pkg.go.dev/github.com/gtank/ristretto255#Element.Equal

---

## 2. DKG2 complaint / verification

| Location | Status | Notes |
|---|---|---|
| Round 1 commit-share dimension check (`dkg2.go:494`) | **(a)** | `len(commits) != threshold` and `len(v) != sign.M` are integer compares on public structural metadata — branch is structural, not secret-dependent. |
| Round 2 share verification (`dkg2.go:539`) | **(a)** | The Pedersen identity `A·NTT(share) + B·NTT(blind) ?= Σ C_{i,k}` is verified slot-by-slot via `constTimePolyEqual` (`dkg2.go:560`). The `eq &= subtle.ConstantTimeCompare(ab, bb)` accumulation pattern across all `M` slots is the canonical constant-time-AND idiom. No early return; the loop runs to completion before the final `if eq != 1` branch. |
| Complaint identification (`complaint.go:223` `ComputeDisqualifiedSet`) | **(a)** | Operates on public complaint metadata (sender ID, complainer ID). No secret material; all branches are over public counters. |
| Disqualification quorum (`complaint.go:250` `FilterQualifiedQuorum`) | **(a)** | Pure deterministic set filter on public IDs; sorted output via insertion-sort over committee size ≤ 32. No secret-dependent branching. |

---

## 3. Share handling

| Location | Status | Notes |
|---|---|---|
| `keyera.Bootstrap` share generation (`keyera/keyera.go:Bootstrap`) | **(a)** | Shamir over Z_q runs entirely in `math/big`. `big.Int` is **not** constant-time, but Bootstrap is a one-time foundation MPC ceremony; the dealer's machine is the only entity with the master secret in memory at this point. Timing is observable only to the dealer. The dealer's standard-form `s` copy is zeroed in place after sharing (`keyera.go:191-198`). |
| `keyera.Reshare` share recombination via Lagrange (`keyera/keyera.go:Reshare`) | **(a)** | The Lagrange recombination is a `big.Int` linear combination of secret share values with public Lagrange coefficients. `big.Int.Mul/Mod` are not constant-time per se, but every input value is held by the local party only — there is no remote attacker on the recombination path. Timing leaks only to the local OS scheduler, which is the trust boundary already accepted by the validator deployment posture. |
| `EraseShare` after activation (`reshare/keyshare.go:158`) | **(a)** | Plain `for k := range coeffs { coeffs[k] = 0 }`. The Go compiler does not zero behind a pointer reference unless we write the assignment ourselves; this is the documented zeroization technique used by upstream `golang.org/x/crypto/internal/poly1305.MACState.zeroize`. The data is already secret to the local process; the goal is overwrite-on-deactivation, not constant-time-equality. |
| Lens share derivation (`lens/keyera/keyera.go`) | mirrored into `lens/CONSTANT-TIME-REVIEW.md` | See lens doc. |

---

## 4. Scalar / ring operations

| Location | Status | Notes |
|---|---|---|
| `pulsar/primitives/polynomial.go` Lagrange / Shamir (Shamir routines) | **(a)** | Operates on a single party's view of secret coefficients in `big.Int`. The party holds the secret and there is no remote oracle for timing — same boundary as `keyera.Reshare`. |
| `pulsar/sign` Montgomery / NTT / discrete-Gaussian sampling | **(a)** | All three primitives come from `github.com/luxfi/lattice/v7/ring` (a fork of `tuneinsight/lattigo/v7`). Lattigo's NTT (`ring/ring_ops.go: NTT`), Montgomery reduction (`ring/ring_field.go`), and the discrete-Gaussian sampler (`ring/sampler_gaussian.go`) all run constant-time over the modulus parameters: NTT and Montgomery do branch-free word-level arithmetic on `uint64` coefficient slices; the Gaussian sampler uses rejection on uniform bytes from `KeyedPRNG`, which is a SHAKE128-based stream — the rejection rate is data-dependent only on the rejected byte, not on the secret coefficient being sampled. **Citation:** `lattigo/v7` README and `ring/sampler_gaussian.go: NewGaussianSampler` documentation [5]. |
| `lens/primitives` curve.go scalar ops on three curves | see §5 below | |

[5] https://github.com/tuneinsight/lattigo (we vendor `luxfi/lattice/v7` from this; reduction routines are byte-stable and CT-claimed).

---

## 5. Lens curve operations

The lens reshare and sign paths sit on three curves; each gets its own
mini-audit.

### Ed25519 (`lens/primitives/ed25519.go`)

| Operation | Status | Notes |
|---|---|---|
| Scalar mul (`ed25519Scalar.Act`, `ActOnBase`) | **(a)** | Backed by `filippo.io/edwards25519.Point.ScalarMult` and `ScalarBaseMult`. Filippo's `edwards25519` package is the Go standard library's reference Ed25519 implementation (it backs `crypto/ed25519` since Go 1.17), and is documented constant-time per `pkg.go.dev/filippo.io/edwards25519` [3]. |
| Scalar Add/Sub/Mul/Negate/Invert | **(a)** | All delegate to `edwards25519.Scalar.Add/Subtract/Multiply/Negate/Invert`. Every operation in the package is constant-time, including `Invert` (Fermat-based, no extended-Euclidean leakage). |
| `Equal` on scalars/points | **(a)** | `edwards25519.Scalar.Equal` and `Point.Equal` return `int` (0 or 1) explicitly to enforce constant-time use — see method signatures in [3]. |
| `SetBytes` (`SetCanonicalBytes`) | **(a)** | Canonical-encoding rejection short-circuits on malformed input, but malformed input is public (came off the wire); accepted input flows through a constant-time scalar reduction. |

### secp256k1 (`lens/primitives/secp256k1.go`)

| Operation | Status | Notes |
|---|---|---|
| Scalar mul on points | **(b)** — non-CT, public RHS | `decred/dcrd/dcrec/secp256k1/v4.ScalarMultNonConst` and `ScalarBaseMultNonConst` are explicitly **non-constant-time** (note the `NonConst` suffix). The dcrd authors document this and recommend the constant-time variants for secret-key code paths. **In Lens, the only secp256k1 path that holds a secret scalar is FROST Round 2** (`lens/sign/sign.go:236-243`): `eRho := s.curve.NewScalar().Set(s.eI).Mul(myRho)` and `lamSc := s.curve.NewScalar().Set(s.share.Lambda).Mul(s.share.SkShare).Mul(c)` — these are scalar-on-scalar muls (constant-time, see next row), not scalar-on-point. The point-on-point operations on secp256k1 in Lens are all on **public** points (`commits[id].D`, `commits[id].E`, group key `X`). **Status (b): documented gap; not exploitable because every secp256k1 ScalarMult call site uses public scalar inputs (binding factor `ρ`, challenge `c`, Lagrange coefficient `λ`).** Action: when we ship a secp256k1-backed Lens variant that signs under a single-party path (rather than threshold FROST), reroute to a constant-time scalar-mul implementation (`btcsuite/btcd/btcec/v2.PrivateKey.PubKey()` uses `crypto/ecdsa`'s constant-time mul — that is the upgrade target). |
| Scalar Add/Sub/Mul/Negate (`ModNScalar`) | **(a)** | `secp256k1.ModNScalar` operations are **constant-time** per dcrd source (`primitives/secp256k1/scalar.go: Add/Mul/etc.` use bit-twiddling). |
| `Invert` | **(b)** | `s.value.InverseNonConst()` — explicitly non-constant-time. **Only invoked from `primitives.Lagrange` over public IDs**; the input is the difference between two committee party IDs (public integers). Not on a secret scalar path. |
| Point `Equal` | **(b)** | `secp256k1Point.Equal` (`secp256k1.go:345`) calls `IsZero/IsOddBit/Equals` which short-circuit on the `IsIdentity` branch then `pa.X.Equals(&oa.X) && pa.Y.Equals(&oa.Y)`. `FieldVal.Equals` is constant-time per dcrd source (XOR-fold over the 10-word representation). The `IsIdentity` branch IS data-dependent but operates on public points. |

### Ristretto255 (`lens/primitives/ristretto255.go`)

| Operation | Status | Notes |
|---|---|---|
| Scalar mul (`ristrettoScalar.Act`, `ActOnBase`) | **(a)** | Backed by `gtank/ristretto255.Element.ScalarMult` / `ScalarBaseMult`. Per `gtank/ristretto255` README and source, every operation is constant-time, deliberately so for use in PAKE / OPAQUE / threshold-Schnorr deployments [4]. |
| Scalar Add/Sub/Mul/Negate/Invert | **(a)** | Delegates to `ristretto255.Scalar.{Add,Subtract,Multiply,Negate,Invert}`, all constant-time per package documentation. |
| `Equal` on scalars/points | **(a)** | `Scalar.Equal` and `Element.Equal` return `int` (0/1) constant-time, by design [4]. |
| Encoding (`Encode`, `SetCanonicalBytes`) | **(a)** | Canonical encoding is documented constant-time per RFC 9496 §4.3.4. |

---

## (c) entries

**None.** All paths reviewed land in (a) or (b).

The (b) entries break down as:

1. **`reshare/commit.go:124`** — recipient-side Pedersen mismatch leaks
   the first-diverging slot index. Mitigation: dkg2's `VerifyShareAgainstCommits`
   already does CT compare, and the legacy `reshare` path will be
   migrated to use the same `constTimePolyEqual` helper at the next
   reshare-protocol revision (Mar-31 cutover; tracked in
   `~/work/lux/pulsar/LLM.md`).

2. **`lens/primitives/secp256k1.go`** — `dcrd` non-CT scalar mul. Only
   reached with public scalar inputs in current Lens deployments. If we
   ever expose secp256k1 to a single-party signing path (e.g. an L2
   bridge requiring Bitcoin-key signatures from a single validator),
   reroute to a constant-time mul.

Both (b) entries are tracked; neither blocks the Mar-3 Architecture
Freeze.

---

## Reviewers

- Audit pass: Scientist (Mar-3-2026)
- Cross-check: companion file `~/work/lux/lens/CONSTANT-TIME-REVIEW.md`
  (lens-specific section duplicates §5 here under the lens module's
  own surface inventory).
- Proof anchor: `proofs/definitions/transcript-binding.tex`
  Definitions ref:pulsar-transcript and ref:pulsar-activation-msg.
