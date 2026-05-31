# Pulsar — Jasmin high-assurance track

This directory holds the **Jasmin** sources for the Pulsar high-
assurance implementation track. Jasmin (https://github.com/jasmin-lang/jasmin)
is a low-level cryptographic implementation language with a verified
compiler whose generated assembly is bit-identical to the source-level
semantics and admits machine-checked side-channel (constant-time)
guarantees through the **EasyCrypt** companion proof system
(https://github.com/EasyCrypt/easycrypt).

The `libjade` project (https://github.com/formosa-crypto/libjade) ships
Jasmin sources for ML-DSA (Dilithium) and ML-KEM (Kyber) with
EasyCrypt-machine-checked functional correctness against FIPS 204 /
FIPS 203 and constant-time proofs against the leakage model of Barbosa
et al. (Eurocrypt 2021). NIST PQC submissions that integrate
libjade-verified primitives sit in the high-assurance evaluation track
alongside the formosa-crypto reference work.

For Pulsar, the high-assurance plan splits along the Class N1 / Class
N4 boundary of the construction itself:

| Layer | What Jasmin verifies | Source of truth |
|---|---|---|
| **Single-party ML-DSA-65 core** | Functional equivalence to FIPS 204 + constant-time over secret key and nonce paths | libjade (`jasmin/ml-dsa-65/`, vendored via fetch script) |
| **Threshold layer** (Round-1 commit, Round-2 response, Combine) | Functional correctness of the round protocol's polynomial-vector arithmetic + constant-time over each party's secret share | new (`jasmin/threshold/`, this submission) |

The Class N1 byte-equality claim composes the two: a Pulsar
threshold signature is a single-party FIPS 204 signature whose
underlying `(z, h, c̃)` components have been computed by an honest
quorum running the threshold protocol. So the Pulsar Jasmin proof
chain is

    libjade ML-DSA-65 (functional ≡ FIPS 204)
      ∘ Pulsar threshold (functional ≡ single-party computation under
                            honest quorum + share-additivity)
      ⇒ Pulsar output ≡ FIPS 204 output (Class N1)

with constant-time taken as a side condition on every secret-dependent
control- and memory-access path.

## Status — initial track

The high-assurance scaffolding shipped at submission carries:

1. The libjade ML-DSA-65 single-party baseline as the verified core
   (fetched on demand via `ml-dsa-65/fetch.sh`; not vendored into
   this repository).
2. Threshold-layer Jasmin sources at `threshold/round1.jazz` (~400
   lines), `threshold/round2.jazz` (~600 lines), and
   `threshold/combine.jazz` (~400 lines) plus shared `lib/` (~1200
   lines). The jasmin-ct gate runs blocking on all three (3 / 3
   green per `scripts/checks/jasmin.sh`).
3. EasyCrypt theories at `../proofs/easycrypt/` — 13 files compile
   with the admit budget hard-pinned at 0 / 0 by
   `scripts/checks/ec-admits.sh`. The Class N1 byte-equality theorem
   is a proved lemma at
   `Pulsar_N1_Extracted.pulsar_n1_byte_equality_extracted`. The
   residual axioms (22 total: 17 narrow implementation-refinement +
   5 Lean-bridged algebraic) are enumerated in
   `../docs/proof-axiom-inventory.md` with a per-axiom closure plan.

## How to fetch libjade

```bash
cd jasmin/ml-dsa-65
./fetch.sh                  # clones libjade at the pinned commit
```

The fetch script pins libjade to a specific commit so the submission
artifact reproduces deterministically. The libjade tree itself is **not**
committed to this repository — it is fetched on demand. This keeps the
submission tarball small and avoids re-licensing complexity (libjade is
MIT-licensed; we cite + link rather than redistribute).

## How to check

```bash
../scripts/check-high-assurance.sh
```

The script is **skip-friendly**: if `jasminc` or `easycrypt` is not on
the system PATH it prints a clear skip message and exits 0. When the
tools are present it compiles each `.jazz` file and runs `easycrypt
check` on each `.ec` file.

## Tool installation

- **Jasmin compiler** — https://github.com/jasmin-lang/jasmin#installation
  (OPAM: `opam install jasmin`). The reference platform is OCaml 4.14
  with Coq 8.18.
- **EasyCrypt** — https://github.com/EasyCrypt/easycrypt#installation
  (OPAM: `opam install easycrypt`). Backend SMT solvers (Alt-Ergo,
  Z3, CVC4) must be installed via `why3 config detect`.

## Citations

- Almeida, Barbosa, Barthe, Blot, Grégoire, Laporte, Oliveira, Pacheco,
  Schwabe, Strub. *The last mile: High-assurance and high-speed
  cryptographic implementations.* IEEE S&P 2020.
- Bond, Hawblitzel, Maillard, Protzenko et al. *EverCrypt: A Fast,
  Verified, Cross-Platform Cryptographic Provider.* IEEE S&P 2020.
- Barbosa, Barthe, Doczkal, Don, Fehr, Grégoire, Huang, Hülsing,
  Lee, Wu. *Fixing and Mechanizing the Security Proof of Fiat–Shamir
  with Aborts and Dilithium.* CRYPTO 2023.
- libjade ML-DSA implementation — https://github.com/formosa-crypto/libjade
