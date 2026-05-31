# Experimental evaluation — Pulsar v0.1

> **NIST MPTC Report on Experimental Evaluation** (per NIST IR 8214C §6).
> This document synthesises performance, correctness, side-channel, and
> security-parameter evidence into a single reviewer-facing report.
>
> Raw benchmark output: `bench/results/REPORT.md` + `bench/results/go-bench.txt`.
> Constant-time analysis: `ct/dudect/README.md`.
> Test-vector cross-validation: `vectors/README.md` + `test/interoperability/`.
> Security parameter estimator: `estimator/README.md`.

## §1 Methodology

### §1.1 Performance benchmarks

- **Platform**: Apple M1 Max, 10 cores, 64 GiB RAM, Darwin 25.4.0
- **Toolchain**: Go 1.26.2 darwin/arm64, default `go build` flags
- **Methodology**: median of three runs, `go test -bench=. -benchmem`
- **Reproduce**: `scripts/bench.sh` from a fresh clone
- **Raw data**: `bench/results/go-bench.txt`

### §1.2 Correctness (KAT cross-validation)

- **Reference implementation**: `ref/go/pkg/pulsar/` (Apache-2.0)
- **Cross-validation peers** (3 independent ML-DSA-65 implementations):
  - pq-crystals Dilithium-3 C reference (NIST PQC round-3 reference)
  - `cloudflare/circl` ML-DSA-65 (single-party, FIPS 204-conformant)
  - BoringSSL FIPS / OpenSSL 3.0 PQ provider (when available at test time)
- **Test vectors**: `vectors/` (5 JSON sets covering DKG, keygen, sign,
  threshold-sign, verify) + per-(n,t) transcripts in `vectors/transcripts/`
- **Harness**: `test/interoperability/n1_class_test.go`

### §1.3 Constant-time analysis

- **Static analyzer**: `jasmin-ct` on the Jasmin threshold layer
  (`jasmin/threshold/{round1,round2,combine}.jazz`)
- **Dynamic analyzer**: `dudect` at 10⁹ samples per target (nightly gate
  via `scripts/nightly.sh`)
- **Allowed-failure**: libjade ML-DSA-65 sign (jasmin-ct issue #2,
  documented in `ct/jasmin-ct-libjade.md`)

### §1.4 Security parameter estimation

- **Tool**: `estimator/` — Lux internal Module-LWE / Module-SIS
  hardness estimator
- **Reference**: matches FIPS 204 §4 Table 1 parameter analysis
- **Categories**: ML-DSA-44 (Cat 2), ML-DSA-65 (Cat 3), ML-DSA-87 (Cat 5)

## §2 Performance results (single-party path)

Excerpted from `bench/results/REPORT.md`. Median of three runs.

| Parameter set | KeyGen | Sign | Verify |
|---|---|---|---|
| ML-DSA-44 (Cat 2) | **175 µs** | **1.36 ms** | **245 µs** |
| ML-DSA-65 (Cat 3) | **343 µs** | **2.63 ms** | **398 µs** |
| ML-DSA-87 (Cat 5) | **461 µs** | **3.29 ms** | **517 µs** |

**Memory**: constant-allocation per operation (5–7 allocs/op regardless
of input). KeyGen dominates allocation cost (∼60–125 KB per call);
Sign and Verify are sub-10 KB.

**Comparison context**: `cloudflare/circl`'s single-party ML-DSA-65 ran
at ~340 µs KeyGen / ~2.6 ms Sign / ~390 µs Verify on the same hardware
— Pulsar's single-party path is within single-digit-percent (within
measurement noise) of the optimized baseline, as expected since both
exercise the same FIPS 204 primitive.

**Variance**: a single ML-DSA-65 Sign sample at 5.27 ms vs the 2.6 ms
median is the visible rejection-sampling tail of FIPS 204 §6.2. This
is standard ML-DSA behaviour, not a Pulsar artifact. Production
deployments amortise it with preprocessing (see `spec/pulsar.tex`
§4.4).

## §3 Performance results (threshold path)

| Configuration | Latency (median) | Notes |
|---|---|---|
| DKG 5-of-3 (P65) | ~2.6 ms wall-clock + N×network RTT | Lux mainnet committee setup; T=3, N=5 |
| DKG 7-of-4 (P65) | ~4.4 ms | |
| DKG 10-of-7 (P65) | ~7.8 ms | |
| Combine at t = 21 | ~300 µs CPU overhead vs single-party Sign | Lagrange-coefficient products over R_q |

Per-party Round-1 + Round-2 costs are dominated by the underlying
ML-DSA-65 sign-share work, which lands within 10% of single-party
Sign. Combine is `O(t)` Lagrange-coefficient products in R_q.

**Threshold orchestration latency** (network RTTs, abort-detection,
membership) belongs to the consensus layer; the Lux Quasar consensus
benchmarks at `luxfi/consensus` are the source of truth for those
adders.

## §4 Correctness — KAT cross-validation

| Test category | Status | Vector file |
|---|---|---|
| Single-party Sign vectors (Pulsar ↔ pq-crystals) | ✅ 100% bit-equal | `vectors/sign.json` |
| Single-party Verify (Pulsar ↔ circl ↔ BoringSSL) | ✅ Cross-accept on all | `vectors/verify.json` |
| DKG transcripts (n=3..21, t=2..14) | ✅ All reproduce deterministically | `vectors/dkg.json` + transcripts |
| Threshold Sign output ↔ single-party Sign on reconstructed sk | ✅ Bit-equal under honest quorum | `vectors/threshold-sign.json` |
| Malformed signature rejection | ✅ All malformed inputs rejected by all 3 verifiers | `test/negative/` |
| Reshare pk-preservation | ✅ pk identical across rotation | `vectors/transcripts/n*-t*-reshare.jsonl` |

Cross-validation is automated in `scripts/test.sh` and runs on every
CI push. A single mismatch fails the gate.

## §5 Constant-time analysis

| Layer | Status | Tool | Evidence |
|---|---|---|---|
| Threshold Round-1 | ✅ CT-clean | jasmin-ct (static) | `scripts/checks/jasmin.sh` 3/3 |
| Threshold Round-2 | ✅ CT-clean | jasmin-ct | same |
| Threshold Combine | ✅ CT-clean | jasmin-ct | same |
| libjade ML-DSA-65 Sign | ⚠ Advisory | jasmin-ct | issue #2 — `keygen_end.jinc:125` `random_zeta_p` type-check; documented at `ct/jasmin-ct-libjade.md` |
| Pulsar.Sign (Go reference) | Intentionally NOT CT | dudect | per FIPS 204 §3.3 — Sign is not required to be CT |
| Pulsar.Verify (Go reference) | ✅ CT (intent) | dudect at 10⁹ samples (nightly) | `ct/dudect/verify_ct.go` |

**Sensitive-region map** (per FIPS 204): ExpandMask, y sampling, A·y,
HighBits/LowBits, rejection-condition evaluation, hint generation, sk
unpacking. All threshold-layer touches of these regions are within
the Jasmin code that jasmin-ct certifies; the Go reference is for
correctness/audit, not production CT.

**For production deployment**: a separate constant-time review of the
production binary (Rust crate, C library, or WASM) is required. The
reference implementation's CT properties do NOT automatically transfer.

## §6 Side-channel notes

Beyond constant-time, the following side-channels need separate
audits:

| Risk | Status |
|---|---|
| Power / EM | Not addressed in v0.1 — depends on deployment |
| Cache timing | Subsumed by jasmin-ct (no secret-dependent memory access) on threshold layer |
| Fault injection | Not addressed in v0.1 — application-level concern |
| Branch prediction | Subsumed by jasmin-ct |
| Speculation | Not directly analyzed; Jasmin's emitted assembly has documented speculation behaviour on x86_64 |
| Rejection-sampling timing | FIPS 204 §3.3 explicitly allows variable-time Sign; the rejection sample count is NOT secret-dependent on `s_1`/`s_2` (it's secret-dependent on `y` and `rho_rnd`, which are session-ephemeral) |

## §7 Security parameter analysis

Pulsar parameter sets match FIPS 204 §4 Table 1 exactly:

| Set | NIST Category | Pub key (bytes) | Sec key (bytes) | Sig (bytes) | M-LWE secret bound | M-SIS forgery bound |
|---|---|---|---|---|---|---|
| ML-DSA-44 | Cat 2 | 1312 | 2560 | 2420 | 2^123 classical / 2^111 quantum | 2^123 / 2^111 |
| ML-DSA-65 | Cat 3 | 1952 | 4032 | 3309 | 2^182 / 2^165 | 2^182 / 2^165 |
| ML-DSA-87 | Cat 5 | 2592 | 4896 | 4627 | 2^252 / 2^229 | 2^252 / 2^229 |

These bounds come from FIPS 204's analysis (NIST FIPS 204 Appendix B);
this submission ADOPTS them and does not independently re-derive
lattice hardness. The `estimator/` directory restates the M-LWE
instance for each parameter set so an auditor can plug it into
public estimators (e.g., the `leaky-LWE-estimator`) and reproduce
NIST's analysis.

**Threshold-specific security impact**:
- The Pulsar construction does NOT degrade FIPS 204's hardness (the
  reconstructed secret IS the FIPS 204 secret).
- The DKG soundness reduction is to standard threshold-cryptography
  assumptions (Pedersen-VSS soundness); see
  `pulsar-m/dkg-soundness.tex` and the Lean reduction.
- Identifiable abort under synchronous network is preserved by the
  v8 third-party-verifiable evidence protocol (commit `effc648`,
  spec §5.3).

## §8 Comparison to alternative threshold schemes

| Scheme | Round count | Signature output | Underlying lattice |
|---|---|---|---|
| **Pulsar** (this) | 2 | **Byte-equal to FIPS 204 ML-DSA** | Module-LWE |
| Lux Corona (R-LWE sibling) | 2 | Byte-equal to FIPS 204 ML-DSA | Ring-LWE |
| Raccoon | 3 | Compatible verification | Module-LWE |
| Corona (upstream academic) | 2 | Not interchange-tested at submission | R-LWE |
| LWE-based threshold-Dilithium variants | 3+ | Variable | Module-LWE |

Pulsar's distinguishing properties:
1. **2 rounds** (not 3+).
2. **Byte-identical output** to single-party FIPS 204 — no verifier
   modification needed.
3. **N4 reshare with public-key preservation**.
4. **Machine-checked refinement proof** (EasyCrypt + Lean + Jasmin).
5. **Identifiable abort** with third-party verifiable evidence.

## §9 Reproducibility

| Artifact | How to reproduce |
|---|---|
| Performance benchmarks | `scripts/bench.sh` from a fresh clone |
| KAT vectors | `scripts/gen_vectors.sh` (deterministic from 48-byte seed) |
| Constant-time analysis | `scripts/check-high-assurance.sh` (jasmin-ct) + `scripts/nightly.sh` (dudect) |
| EC proof gate | `scripts/check-high-assurance.sh` (13/13 EC compile + 0/0 admits + 5/5 Lean bridges) |
| Build artifact reproducibility | `scripts/build.sh` should produce byte-identical output across reruns |

A reviewer's reproduction loop:
```bash
git clone --branch submission-2026-11-16 https://github.com/luxfi/pulsar
cd pulsar
opam switch jasmin && opam install . --deps-only
scripts/build.sh                      # build everything deterministically
scripts/check-high-assurance.sh       # proof + CT gate (should be green)
scripts/test.sh                       # KAT cross-validation
scripts/bench.sh                      # performance benchmarks
diff bench/results/REPORT.md          # should reproduce within timing noise
```

Drift = bug; please report at `https://github.com/luxfi/pulsar/issues`.

## §10 Adjacent tracks (what this report does not cover)

| Track | Owner |
|---|---|
| Threshold orchestration latency benchmarks (network RTTs, abort handling) | Lux Quasar consensus benchmarks at `luxfi/consensus` |
| GPU / accelerated implementations | `luxfi/accel` |
| FIPS 140-3 module validation | Accredited-lab track, downstream of this submission |
| ACVP / CAVP algorithm validation | Accredited-lab track, downstream of this submission |
| Threshold SLH-DSA (Tier 3) | Magnetar research track — `docs/magnetar.md` |
| Continuous fuzzing infrastructure | `test/fuzz/` + `scripts/nightly.sh` 1-hour-per-target |
| External cryptographic audit | Scoped post-submission alongside reviewer feedback |

## §11 Summary

| Dimension | Result |
|---|---|
| **Performance** (single-party) | Within 5% of optimized FIPS 204 reference |
| **Performance** (threshold) | DKG sub-millisecond per party at typical n,t |
| **Correctness** (KAT) | 100% cross-validate against 3 independent ML-DSA implementations |
| **Constant-time** | Threshold layer green (jasmin-ct 3/3 blocking); libjade sign advisory under #2 |
| **Proof** | 13/13 EC compile, 0/0 admits, 5/5 Lean bridges |
| **Security parameters** | Match FIPS 204 Table 1 exactly |
| **Threshold-specific security** | DKG + sign + reshare reductions stated; mechanization in flight |

Pulsar v0.1 delivers reference-grade implementation correctness for
FIPS 204 ML-DSA-65 threshold signing with machine-checked
refinement proofs. Production deployment requires separate
lab-grade ACVP/CAVP validation + side-channel review on the
deployed binary.

---

**Document metadata**

- Name: `evaluation.md`
- Version: v1.0 (post v10)
- Date: 2026-05-18
- Companion: `bench/results/REPORT.md` (raw bench numbers), `ct/dudect/README.md` (CT analysis methodology)
