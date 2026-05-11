# Pulsar -- Agent Knowledge Base (formerly Pulsar-M)

**Repository (current)**: github.com/luxfi/pulsar-m
**Repository (target)**: github.com/luxfi/pulsar
**Latest Tag**: v0.1.0
**Status**: Research / Reference (not production hardened, not FIPS validated)

## Rename in progress: Pulsar-M → Pulsar

Per the Lux family rebrand, the three threshold libraries are:

| Name | Lattice | Class | Source path going forward |
|---|---|---|---|
| **Pulsar** (this repo, was Pulsar-M) | Module-LWE | NIST MPTC N1+N4 | `~/work/lux/pulsar` |
| **Corona** (was the prior R-LWE Pulsar) | Ring-LWE | NIST MPTC S1+S4 | `~/work/lux/corona` |
| **Ringtail** (unchanged) | Ring-LWE | academic upstream + Lux lifecycle DKG expansions | `~/work/lux/ringtail` |

Until the cross-repo moves land, this repo continues at `luxfi/pulsar-m`
and the existing `luxfi/pulsar v0.1.5` (R-LWE) keeps shipping. The
rename is a naming change, not a behaviour change — wire formats,
KAT vectors, and FIPS 204 byte-equality guarantees are unchanged.

## Family migration plan

| Going-forward name | Lattice | Class | Where it lives now | Where it lives after |
|---|---|---|---|---|
| **Pulsar** | Module-LWE / FIPS 204 | NIST MPTC N1 + N4 | `github.com/luxfi/pulsar-m` | `github.com/luxfi/pulsar` |
| **Corona** | Ring-LWE | NIST MPTC S1 + S4 | `github.com/luxfi/pulsar` (current R-LWE production fork) | `github.com/luxfi/corona` |
| **Ringtail** | Ring-LWE | academic upstream + Lux lifecycle DKG expansions | `github.com/luxfi/ringtail` | `github.com/luxfi/ringtail` (unchanged) |
| **Quasar** | composition layer | -- | `consensus/protocol/quasar/` (sub-protocol) | optional standalone `github.com/luxfi/quasar` as the **PQ event horizon** |

### Quasar — PQ event horizon

Quasar is proposed as the top-level meta-package that consumes every
PQ primitive (Pulsar threshold ML-DSA, Corona threshold R-LWE, P3Q
STARK rollup, BLS aggregate, ML-DSA single-party) and exposes a
unified `Verify(cert)` interface. Consensus's existing
`consensus/protocol/quasar/` already implements this as a sub-protocol;
promoting it to a standalone repo would let EVM precompiles
(`precompile/quasar/` at 0x0604 per the LP-4200 table) and external
relying parties consume the same verification surface without
depending on the full consensus stack.

### Migration order (when push authorised)

1. Push pre-existing work first to avoid entangling pre-migration commits
   with the rename:
   - `luxfi/ringtail` push commits ahead
   - `luxfi/pulsar` commit + push LLM.md edit
   - `luxfi/p3q` commit + push LLM.md edit
   - `luxfi/pulsar-m` commit `Large*`, `luxround`, `largeshamir`, spec,
     proofs and push as `v0.2.0`
   - `luxfi/precompile` commit + push the new `pulsar/` precompile
2. Stand up `luxfi/corona` by mirroring current `luxfi/pulsar` contents.
   Preserve all tags. Cut rename commit as `v0.2.0` on `luxfi/corona`.
   Leave `luxfi/pulsar` as redirect/archive marker for downstream
   go.mod consumers.
3. Move pulsar-m contents to `luxfi/pulsar`: delete R-LWE content
   (preserved in corona), copy M-LWE content from pulsar-m, bump module
   path. Cut as `v0.2.0`. Archive `luxfi/pulsar-m` with README redirect.
4. Update consumers' go.mod (`luxfi/consensus`, `luxfi/precompile`):
   replace `github.com/luxfi/pulsar-m v0.1.0` with
   `github.com/luxfi/pulsar v0.2.0`. Update imports + `go mod tidy`.
5. Optional: stand up `luxfi/quasar` as the PQ event horizon meta-repo.
   Imports `luxfi/pulsar`, `luxfi/corona`, `luxfi/p3q`,
   `luxfi/crypto/bls`, `luxfi/crypto/mldsa`. Wire `precompile/quasar/`
   (0x0604) to consume it.

### Destructive-action checklist (push phase)

Operations modify shared / production systems and need explicit user
confirmation per auto-mode safety policy:

- [ ] `git push` to any of the four repos
- [ ] `gh repo rename luxfi/pulsar luxfi/corona`
- [ ] `gh repo create luxfi/corona`
- [ ] `gh repo archive luxfi/pulsar-m`
- [ ] Updating `luxfi/consensus/go.mod` and `go.sum` to switch from
      `pulsar-m` to `pulsar` (busts go.sum hashes)
- [ ] Cutting new tags (`v0.2.0` on renamed repos)

### Cleanliness audit (local snapshot)

| Repo | Status | Action |
|---|---|---|
| `luxfi/pulsar-m` | modified + untracked (GF(q) `Large*`, luxround helpers, spec, proofs) | Commit cleanly; archive when contents move |
| `luxfi/pulsar` | LLM.md rename note modified | Commit; hosts M-LWE post-migration |
| `luxfi/ringtail` | commits ahead + modified + untracked | Push commits first; merge/discard locally |
| `luxfi/p3q` | LLM.md modified | Commit; v0.0.1 pushed |
| `luxfi/consensus` | Clean | go.mod bump after migration |
| `luxfi/precompile` | New `precompile/pulsar/` (LP-4200 0x012204) | Commit + run CI |
| `luxfi/corona` | Does not exist | Create from current `luxfi/pulsar` R-LWE contents |
| `luxfi/quasar` | Does not exist | Optional standalone repo |

## Purpose (one-liner)

Threshold ML-DSA: 2-round threshold signing and DKG whose generated
signatures are verifiable by **unmodified FIPS 204 ML-DSA verification**.
Targeting NIST MPTC Class N1 (signing) + N4 (ML keygen / DKG).

Pulsar-M is the Module-LWE sibling of `luxfi/pulsar` (Ring-LWE). Pulsar's
2-round protocol is transplanted onto ML-DSA-65's polynomial-vector-over-`R_q`
algebra so the aggregated signature is bit-identical to a single-party
FIPS 204 signature on the same message + public key.

## Canonical profile + scheme constants

- Hash family: SHAKE / cSHAKE / KMAC256 / TupleHash256 (FIPS 202 + SP 800-185).
- Sharing: byte-wise Shamir, two regimes:
  - **GF(257)** for small committees (n ≤ 256), 64-byte wire share.
  - **GF(q)** for large committees (n ≤ q-1 = 8,380,416), 128-byte wire
    share. Canonical extreme committee target: `TargetCommitteeSize =
    1_111_111` (seven 1s).
- Curve / lattice: same Module-LWE parameters as ML-DSA-65.
- Round count: 2 (commit + reveal).
- Abort model: identifiable.
- Arithmetic width: uint32 lanes with uint64 accumulators. uint128 /
  uint256 not required (reserved for the Z-Chain SNARK side).

## Recent significant changes

| commit-like SHA | Impact |
|-----|--------|
| `170a705` | NIST MPTC submission readiness — benchmarks + CI gates |
| `ced8779` | KAT vectors for keygen / sign / verify / threshold / dkg |
| `cff8813` | Proactive resharing with beacon-randomized quorum |
| `ddef135` | Threshold sign (2-round commit + reveal) |
| `d0ae91e` | Epoch DKG with identifiable abort |
| `14481d6` | Byte-wise Shamir secret sharing over GF(257) |
| `4d0ff1f` | Keygen + sign + verify (single-party) |
| `6cf9e5b` | Bootstrap NIST MPTC submission package |
| (pending) | GF(q) Shamir + N=1,111,111 target + spec system-model + parameters complete |

## Active versions

- Repo: `v0.1.0` (initial submission-readiness tag; next: `v0.1.1`).
- Pinned by: `luxfi/consensus v1.23.5+` (finality verify path replaces
  the placeholder Pulsar-M verifier).

## Cross-repo dependencies

- Depends on:
  - `golang.org/x/crypto/sha3` (cSHAKE / KMAC primitives)
  - `luxfi/crypto/pq/mldsa/mldsa65` (FIPS 204 verifier — Pulsar-M outputs
    must round-trip through it byte-equal)
- Consumed by:
  - `luxfi/consensus/protocol/quasar` (finality path) — F107/F109 closure.
  - NIST MPTC submission package (`spec/` LaTeX).

## Where to look for X

- Keygen / sign / verify (single-party): `ref/go/pkg/pulsarm/keygen.go`,
  `sign.go`, `verify.go`.
- 2-round threshold sign: `ref/go/pkg/pulsarm/threshold.go`
- Epoch DKG (identifiable abort): `ref/go/pkg/pulsarm/dkg.go`
- Proactive reshare (beacon randomization): `ref/go/pkg/pulsarm/reshare.go`
- Small-committee Shamir (GF(257)): `ref/go/pkg/pulsarm/shamir.go`
- Large-committee Shamir (GF(q)): `ref/go/pkg/pulsarm/shamir_gfq.go`,
  `largeshamir.go`
- Field auto-selection logic: `ref/go/pkg/pulsarm/types.go:resolveField`
- KAT vectors: `vectors/`
- LaTeX submission spec: `spec/pulsar-m.tex` (full; not a stub),
  `spec/parameters.tex`, `spec/system-model.tex`, `spec/security-games.tex`
- Benchmarks (MPTC requirement): `bench/`
- CT (constant-time) guards: `ct/`

## Where to find proofs

- LaTeX theorem statements + proofs: `~/work/lux/proofs/pulsar-m/`
  - `unforgeability.tex` -- TS-UF reduction to MLWE+MSIS+ML-DSA EUF-CMA
  - `scaling.tex` -- Concrete claims at N* = 1,111,111
  - `output-interchangeability.tex` -- Class N1 manifesto
  - `dkg-soundness.tex` -- DKG soundness + share privacy
  - `reshare-preservation.tex` -- Reshare preserves pk + soundness + privacy
- Lean 4 mechanization skeletons: `~/work/lux/proofs/lean/Crypto/Pulsar_M/`
  - `Unforgeability.lean`, `Shamir.lean`, `OutputInterchange.lean`

## Open follow-ups

- Submission package deadline (NIST MPTC first call): 2026-Nov-16.
- BLAKE3 hash variants flagged experimental; out of scope for MPTC.
- Output-interchangeability tests vs. BoringSSL FIPS / AWS-LC / OpenSSL
  3.0 PQ provider are TODO once those packages ship FIPS-validated
  ML-DSA verifiers.
- Adaptive corruption proof is round-2 work (round-1 ships static
  unforgeability only).
- Cross-message restart hybrid is round-2 work.

## Rules

1. Patch-bump only (`v0.1.0` → `v0.1.1`); never minor/major without
   explicit approval.
2. Any deviation from the SHAKE / cSHAKE / KMAC profile is a forking
   decision — it breaks output-interchangeability with FIPS 204.
3. KAT vectors are CI-pinned; never edit without rerunning the generator
   and committing the new vectors in the same commit.
4. `TargetCommitteeSize = 1_111_111` is the canonical extreme committee
   target. Change requires updating the constant in `params.go`, the
   proofs in `~/work/lux/proofs/pulsar-m/scaling.tex`, and the spec in
   `spec/pulsar-m.tex` section "Large committees".
5. Default to `FieldDefault` when constructing a session; only pin
   `FieldGF257` or `FieldGFq` for KAT replay where wire-format
   determinism is required.
