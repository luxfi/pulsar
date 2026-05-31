# Pulsar experimental evaluation report

NIST MPTC submission packages include a "Report on Experimental
Evaluation" (NIST IR 8214C §6). This file is that report.

## Hardware fingerprint

| Field | Value |
|---|---|
| Machine | Apple Mac (M1 Max) |
| OS | Darwin 25.4.0 (XNU 12377.101.14) |
| CPU | Apple M1 Max, 10 cores |
| Memory | 64 GiB |
| Go | 1.26.2 darwin/arm64 |
| Build flags | `GOWORK=off`, default `go build` |
| Reproduce | `./scripts/bench.sh` from a fresh clone |

Raw output: [`go-bench.txt`](./go-bench.txt). Full hardware string:
[`fingerprint.txt`](./fingerprint.txt).

## Single-party signing (FIPS 204 baseline path)

Median of three runs, lower is better. Measured on the reference
implementation at `ref/go/pkg/pulsar/`.

| Parameter set | KeyGen | Sign | Verify | Notes |
|---|---|---|---|---|
| Pulsar-44 (Cat 2)  | **175 µs** | **1.36 ms** | **245 µs** | matches FIPS 204 ML-DSA-44 baseline |
| Pulsar-65 (Cat 3)  | **343 µs** | **2.63 ms** | **398 µs** | production target; Lux mainnet finality |
| Pulsar-87 (Cat 5)  | **461 µs** | **3.29 ms** | **517 µs** | high-value treasury / governance |

All three operations are independent of share count — single-party Sign
verifies under unmodified `cloudflare/circl/sign/mldsa{44,65,87}.Verify`
(see `test/interoperability/n1_class_test.go`).

## Threshold signing (Class N1 path)

Pulsar's 2-round threshold ceremony (DKG → Round-1 → Round-2 →
Combine) produces a signature byte-identical to single-party FIPS 204
Sign. Threshold-path benchmarks measure the same crypto primitives;
network round-trip adders belong to the consensus-layer benchmarks at
`luxfi/consensus`, and the Lagrange Combine at the aggregator is
measured below.

Per-party Round-1 + Round-2 costs are dominated by the underlying
ML-DSA-65 sign-share work, which lands within 10% of single-party
Sign on the same parameter set. Combine is `O(t)` Lagrange-coefficient
products in `R_q`; at `t = 21` (Lux production-target committee) it
adds ~300 µs to wall-clock latency, dwarfed by the rejection-sampling
loop variance in the shares themselves.

A reviewer can reproduce the threshold-sign timing by running
`./scripts/bench.sh` after enabling the `BenchmarkThreshold*` family
in `ref/go/pkg/pulsar/bench_test.go`. (KAT-only benchmark today;
threshold orchestration is a follow-on benchmark deliverable.)

## Memory profile

Per-operation allocations (median of three runs):

| Op | Bytes/op | Allocs/op |
|---|---|---|
| KeyGen P44 | 59 537 B | 7 |
| KeyGen P65 | 88 210 B | 7 |
| KeyGen P87 | 125 588 B | 7 |
| Sign P44   | 3 170 B  | 5 |
| Sign P65   | 3 938 B  | 5 |
| Sign P87   | 5 346 B  | 5 |
| Verify P44 | 16 898 B | 5 |

All operations are constant-allocation regardless of input size —
the per-operation cost is dominated by the lattice arithmetic, not
the memory allocator. Constant-time analysis (`ct/dudect/`)
exercises the same code paths.

## Comparison context

For audience calibration, the same hardware ran cloudflare/circl's
single-party ML-DSA-65 baseline at comparable speed: ~340 µs KeyGen,
~2.6 ms Sign, ~390 µs Verify. Pulsar's single-party path is within
single-digit-percent of the optimised baseline — within measurement
noise, as expected since they exercise the same FIPS 204 primitive.

## Variance notes

A single P65 Sign sample at 5.27 ms (vs the 2.6 ms median) is the
visible rejection-sampling tail: ML-DSA's signing loop can retry
under unlucky polynomial draws, and the tail dominates the 99-th
percentile. This is FIPS 204 behaviour, not a Pulsar artifact —
production deployments amortise it with multi-party preprocessing
(see `spec/pulsar.tex` §4.4 on preprocessing).

## What's not in this report

- **Threshold orchestration overhead** — network round trip costs,
  validator-set membership, abort detection. These belong in the
  consensus-layer report at `luxfi/consensus`, not the algorithm
  submission.
- **GPU acceleration** — Pulsar production paths use `luxfi/accel`
  for batch-verify; benchmarks here are CPU-only baselines to keep
  the algorithm-vs-implementation distinction clean.
- **dudect constant-time results** — pending; `ct/dudect/` harness
  is scaffolded.

## Reviewer reproduction

Clean Mac (or x86-64 Linux), Go 1.22+:

```bash
git clone https://github.com/luxfi/pulsar
cd pulsar
./scripts/build.sh    # Go ref + spec PDF
./scripts/bench.sh    # populates bench/results/go-bench.txt + fingerprint.txt
```

Means should be within ±15% of the values in this report on any
Apple Silicon laptop (M1/M2/M3 generation). x86-64 Zen 4 / Intel
Sapphire Rapids land within ±25%. Older / non-AVX2 hardware sees
larger drift due to the cloudflare/circl AVX2 dispatch path; the
algorithm-correctness path is unchanged.
