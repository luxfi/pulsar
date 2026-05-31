# TRUSTED-COMPUTING-BASE — Pulsar EC/Jasmin/OCaml TCB

> **What you must trust below the residual EasyCrypt axioms.**
> Companion to `proof-axiom-inventory.md` (the axioms above the TCB) and
> `proof-claims.md` (the proof scope).

The Pulsar Class N1 byte-equality theorem rests on three layered
trust bases:

1. **EasyCrypt residual axioms** — enumerated in `proof-axiom-inventory.md`.
2. **Lean theorems used as bridges** — enumerated in
   `proofs/lean-easycrypt-bridge.md`.
3. **The trusted-computing base (TCB) below the proof tools** —
   THIS document.

If any element of the TCB is unsound, the proof's conclusion is
unsound regardless of the axiom inventory.

## §1 Verifier TCBs

| Layer | What you trust | Why |
|---|---|---|
| **EasyCrypt prover** | Soundness of the EC type-checker, tactic engine, and `byphoare`/`equiv` Hoare-logic implementation. Specifically: `easycrypt-dev` at git-hash 909464e (pinned via `opam` in `jasmin` switch). | EC's soundness is the foundation of the refinement proof. Bugs in EC could allow proofs that don't actually establish what they claim. |
| **Lean 4 + Mathlib** | Soundness of the Lean 4 kernel and Mathlib's polynomial-Lagrange theory. Specifically: `lean4` at version listed in `~/work/lux/proofs/lean/lean-toolchain`. | The 5 Lean-bridged axioms (lagrange_inverse_eval, threshold_partial_response_identity, etc.) trust Lean's kernel to have verified the corresponding theorems. |
| **Jasmin verified compiler** | Soundness of the Jasmin → assembly compilation chain. Specifically: `jasminc` from `~/.opam/jasmin/bin`. | The threshold layer's constant-time guarantees and byte-walk correctness depend on Jasmin compiling the `.jazz` sources to assembly that preserves semantics. |
| **OCaml runtime** | OCaml's runtime correctness (the language EasyCrypt is implemented in). | EC is an OCaml program; OCaml bugs could affect EC's soundness. |
| **Operating-system kernel and CPU** | The host kernel scheduler, memory protections, and CPU instruction semantics. | Standard for any cryptographic implementation; not Pulsar-specific. |

## §2 Build TCBs

| Layer | What you trust | Reproducibility |
|---|---|---|
| **opam switch `jasmin`** | The specific opam package versions captured at submission time. | Pinned via `opam switch export` (committed to repo) |
| **Go toolchain** | The Go compiler used to build `ref/go/`. | Version pinned in `go.mod` |
| **`scripts/build.sh`** | The build orchestrator's correctness — that it produces deterministic outputs from a fresh checkout. | CI runs the script on every commit; reproducible-build property is load-bearing for the NIST submission. |
| **`scripts/check-high-assurance.sh`** | The gate orchestrator — that all 7 per-push checks actually fail when they should. | Each per-check script is independently runnable (`scripts/checks/*.sh`); the orchestrator just sequences them. |
| **`scripts/test.sh`** | The test harness's correctness — that KAT vectors compare bit-by-bit, not just lex-equal. | Reviewed; reference impl uses `bytes.Equal` for KAT comparison. |
| **`scripts/gen_vectors.sh`** | Deterministic generation of KAT vectors from seed. | The 48-byte seed is committed; KATs regenerate deterministically. |

## §3 Implementation TCBs

### §3.1 Reference implementation (`ref/go/`)

| Component | Trust | Mitigations |
|---|---|---|
| Go reference impl (`ref/go/pkg/pulsar/`) | Standard library correctness, `crypto/rand` randomness quality | Reviewed; cross-validated against pq-crystals reference + BoringSSL FIPS |
| `cloudflare/circl` (ML-DSA-65 single-party reference for cross-validation) | Upstream Cloudflare CIRCL library | Version pinned in `go.mod` |
| Encoding/decoding of FIPS 204 byte formats | Direct from FIPS 204 §3.5 spec text | Reviewed against test vectors |

### §3.2 Deployed-binary targets (outside the algorithm-level reference)

| Target | Status |
|---|---|
| Optimised Rust crate | downstream packaging; tracked by `docs/roadmap.md` Tier 1 |
| C library + FFI | downstream packaging; Tier 1 |
| WASM build | downstream packaging; Tier 2 |
| `no_std` embedded | downstream packaging; Tier 2 |

Each deployed-binary target requires its own constant-time audit +
KAT cross-validation + binding-level fuzz before claiming production
posture; the Class N1 byte-equality theorem applies to the
algorithm-level reference at `ref/go/pkg/pulsar/` and is the
correctness anchor every binary inherits from.

## §4 Jasmin / libjade TCB

| Layer | What you trust |
|---|---|
| `jasmin/ml-dsa-65/` (libjade ML-DSA-65 single-party baseline) | Upstream Formosa-Crypto libjade Dilithium-3 Jasmin sources at the pinned commit. Fetched on-demand by `jasmin/ml-dsa-65/fetch.sh`. |
| `jasmin/threshold/{round1,round2,combine}.jazz` | Pulsar threshold-layer Jasmin sources (~1400 lines total). Hand-written, reviewed. |
| Jasmin → EasyCrypt extraction | The `jasmin extract -lang EC` tool. Currently version-pinned to a specific Formosa-Crypto build. |
| jasmin-ct (constant-time analyzer) | Soundness of jasmin-ct's type system for detecting secret-dependent control flow. Threshold layer green (3/3); libjade sign advisory (#2). |

## §5 What the TCB does NOT include

These are explicitly NOT part of the trust base for the N1
byte-equality theorem:

- **Specific operating system** (Linux, macOS, BSD, Windows) — the
  proof is OS-independent.
- **Specific CPU architecture** — the Jasmin sources target x86_64
  with documented ARM port path; the EC proof is architecture-
  independent.
- **Network protocol stack** — Pulsar's transport sits above the
  byte-equality theorem; consensus and P2P concerns route through the
  consumer.
- **Storage layer** — `sk`-at-rest is a deployed-binary concern.
- **Key management policies** — key lifecycle is application-level.
- **Application code calling Pulsar** — Pulsar's API contract is the
  trust boundary.

## §6 TCB risks and mitigations

### §6.1 EasyCrypt soundness bugs

| Risk | Mitigation |
|---|---|
| A latent bug in EC's `equiv` tactic could allow proofs that don't actually establish refinement | Pin EC to a specific commit; track upstream bug reports; cross-validate critical theorems via multiple proof paths (e.g., `byphoare` vs `equiv`) |
| Inconsistent axiom additions could derive ⊥ | Hard-pinned `admit budget = 0/0`; `ec-regressions.sh` flags retired axiom shapes; `ec-refinement-scaffold.sh` flags untracked `declare axiom` additions |

### §6.2 Lean soundness bugs

| Risk | Mitigation |
|---|---|
| Lean kernel bug could invalidate a bridged theorem | Lean 4 + Mathlib are widely used; bugs are rare and quickly patched. Pin to specific Mathlib version. |
| Bridge mistranslation between Lean theorem statement and EC axiom statement | `scripts/check-lean-bridge.sh` verifies axiom-name + Lean-theorem-name + file existence at every per-push CI run; manual review of bridge correspondence at axiom-introduction commits |

### §6.3 Jasmin compiler bugs

| Risk | Mitigation |
|---|---|
| Jasmin compiler emits assembly that doesn't preserve semantics | Jasmin is a verified compiler — the verified path goes Jasmin → safety-checked IR → register-allocated assembly. Bugs in the verifier itself are the residual risk. |
| Side-channel timing bug despite jasmin-ct green | jasmin-ct is a STATIC analyzer; it doesn't catch micro-architectural leakage. Pair with dynamic dudect tests (`ct/dudect/` — nightly, 10⁹ samples). |

### §6.4 Build reproducibility breaks

| Risk | Mitigation |
|---|---|
| `scripts/build.sh` produces non-deterministic output | The build is currently deterministic from a 48-byte seed; reproducible-build property is checked on CI. Drift triggers a CI failure. |
| Toolchain version drift between commits | opam switch pin + `go.mod` toolchain directive |

## §7 Independent verification protocol

To independently verify Pulsar's claims, a reviewer should:

1. Clone the repo at the submission tag.
2. Set up the opam switch as documented in `README.md`.
3. Run `scripts/build.sh` — expect deterministic output.
4. Run `scripts/check-high-assurance.sh` — expect 0/0 admits +
   5/5 Lean bridges + 13/13 EC compile.
5. Run `scripts/test.sh` — expect KAT cross-validation against
   3 independent ML-DSA implementations.
6. Run `scripts/bench.sh` — expect performance within published
   bounds.
7. Read `proof-axiom-inventory.md` and verify each axiom's statement
   matches the cited file:line.
8. For Lean-bridged axioms, clone the Lean repo and verify the
   Lean theorems compile + prove what the bridge document claims.

If all 8 steps pass, the trust base reduces to the TCB enumerated
in this document.

## §8 What this means for downstream consumers

For a downstream consumer (e.g., a blockchain protocol incorporating
Pulsar):

- **The proof transfer is conditional on the TCB.** If you change
  the build toolchain, recompile EC theorems, or port to a
  different platform, the proof's transferable guarantees attenuate.
- **For FIPS 140-3 module validation**, you need an end-to-end
  audit of the production module (Pulsar reference impl is not a
  FIPS module by itself). Pulsar's role is the algorithm-level
  reference + proof artifact; module packaging is downstream.
- **For ACVP/CAVP algorithm validation**, you can use Pulsar's
  reference implementation as the input to a lab-run validation;
  the proof artifact strengthens the implementation-correctness
  argument but does NOT substitute for algorithm-conformance
  testing.

---

**Document metadata**

- Name: `tcb.md`
- Version: v1.0 (post v10)
- Date: 2026-05-18
- EC version pin: `git-hash 909464e` (opam switch `jasmin`)
- Lean version pin: see `lean-toolchain` file in `~/work/lux/proofs/lean/`
