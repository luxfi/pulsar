# Constant-time analysis (dudect)

dudect (https://github.com/oreparaz/dudect) is a black-box constant-time
checker. It runs a target operation on two classes of inputs (fixed +
random) and applies a Welch's t-test to the timing distributions. If
the test detects a statistically significant timing difference, the
target leaks information through wall-clock time.

This directory holds the Pulsar dudect harness. We measure two
operations:

1. **`pulsar.Verify`** — the load-bearing entry point. Tested for
   constant-time over the class of VALID signatures from honest
   signers — i.e., the population an attacker can observe in a
   real protocol exchange. Verify holds no long-term secret
   state, so timing differences over INVALID inputs (random byte
   patterns rejected at parse / range check) are not a
   confidentiality property: the attacker SUPPLIED the garbage.
   The valid-sig class is the OPERATIONALLY meaningful CT
   population for Verify; this is not a FIPS 204 carve-out
   (FIPS 204 §6.3 is the Verify algorithm spec, not a CT
   requirement section), it's a property of where attacker-
   observable timing actually matters.
2. **`pulsar.Combine`** — the threshold aggregator. Must be
   constant-time in the per-party signature shares (which DO carry
   secret-derived randomness). A leak here is a real CT regression
   on the threshold path; the high-assurance gate promotes a
   combine-side dudect leak to a HARD FAIL.

`pulsar.Sign` is intentionally NOT constant-time per FIPS 204 §3.3 —
the rejection-sampling loop has secret-dependent retry count. This is
a property of ML-DSA itself, not Pulsar. Production deployments that
need constant-time Sign use the FIPS 204 "ext-ml-dsa-65-cs" context-
supplied variant (open question for MPTC); Pulsar inherits whatever
Sign property the underlying FIPS 204 implementation gives.

### Verify CT population

`dudect_verify` tests Verify CT over the **valid-signature class**:
both class A and class B are valid signatures on the same
`(pk, message)`, varying only in the per-signing randomness
(ML-DSA signing is randomised per FIPS 204 §3.5.2, so two valid
sigs over the same message have different byte strings but
verify through the same code path). The valid-sig class is the
operationally meaningful CT population for Verify (the spec
itself — FIPS 204 §6.3 — is the Verify algorithm, not a CT
requirement; see comments in `verify_ct.go` for the framing).

- Class A: `pool[0]` every time (Welch's t-test requires
  byte-identical class-A samples).
- Class B: `pool[rand % 64]` (uniform draw from the 64-sig pool).

Pool generation runs once at startup (`pulsar_verify_ct_setup`
calls `pulsar.Sign` 64 times under `crypto/rand`). The class
selection in `prepare_inputs` uses dudect's own RNG, so the
class assignment is uncorrelated with anything Verify could see.

**Why not zeros vs random?** Earlier versions of this harness
used `class A = all-zero bytes` vs `class B = random bytes`.
Both are INVALID signatures but on different rejection paths:
zeros pass the `||z||_∞ < γ1-β` range check (z=0 is trivially in
range) and run the full pipeline; random bytes usually fail
range fast and early-reject. dudect detected that timing
difference — but it is **NOT a security property Verify is
claimed to satisfy**. Verify holds no long-term secret; timing
differences over arbitrary attacker-supplied byte patterns do
not leak any confidential value. The current design tests the
operationally meaningful population (valid sigs the attacker
might observe in a real exchange).

### Smoke vs submission budget

At the smoke budget (10k samples per batch × 4 batches = 40k max),
even the valid-vs-valid test can land borderline around dudect's
`t = 10` threshold. The verdict depends on platform noise; ARM
generic-timer noise floor on Apple Silicon is higher than RDTSC
on x86. The high-assurance gate reports a smoke-budget leak as
`[warn]`, not `[FAIL]`.

The authoritative gate is the submission-grade run: ~10^9 samples
on a pinned, quiet CPU. Pin the result to
`ct/dudect/results/verify-submission.log` on the `submission-`
tag. Pass criterion: no max-t above 4.5σ.

For Combine the smoke-budget `[LEAK]` outcome is gated as HARD
FAIL because Combine processes secret shares — there a leak is a
real CT regression on the threshold path.

## Status

Harness layout: **wired**.

| File | Status |
|---|---|
| `verify_ct.go` | cgo bridge exposing `pulsar.Verify` |
| `combine_ct.go` | cgo bridge exposing `pulsar.Combine` |
| `dudect_verify.c` | dudect main loop driving Verify |
| `dudect_combine.c` | dudect main loop driving Combine |
| `dudect_compat.h` | AArch64 shim for `_mm_mfence` / `__rdtsc` |
| `Makefile` | host-platform build (Linux/macOS, x86_64/arm64) |
| `fetch.sh` | clones upstream dudect at pinned commit |
| `results/` | pinned harness output (smoke + submission runs) |

## Architecture

dudect is a single-header library with this contract:

```c
// User supplies:
void prepare_inputs(dudect_config_t *cfg, uint8_t *input, uint8_t *classes);
uint8_t do_one_computation(uint8_t *data);

// User drives:
dudect_init(&ctx, &cfg);
while (dudect_main(&ctx) == DUDECT_NO_LEAKAGE_EVIDENCE_YET) { /* loop */ }
dudect_free(&ctx);
```

`do_one_computation` MUST execute the target in constant time IF the
target is constant time. We achieve this with a thin cgo bridge:

```
+-------------------+        +-----------------------+        +----------+
|  dudect_verify.c  |  --->  |  libpulsar_verify.*  |  --->  |  pulsar |
|  (C main loop)    |  cgo   |  (verify_ct.go bridge)|  Go    |  .Verify |
+-------------------+        +-----------------------+        +----------+
```

The bridge holds a fixture (pk + valid signature on a fixed message)
built once at startup. `pulsar_verify_ct(data)` copies `data` into a
fresh `*Signature` and calls `pulsar.Verify(params, pk, msg, sig)`
— the result is discarded; dudect measures cycles around the call.

For Combine the bridge runs a real (n=3, t=2, ModeP65) DKG +
threshold-sign once at startup, then on each sample overwrites one
party's Round-2 PartialSig bytes with the caller's bytes before
invoking `pulsar.Combine`.

### AArch64 compatibility

Upstream `dudect.h` uses x86 intrinsics (`_mm_mfence`, `__rdtsc`).
`dudect_compat.h` is force-included by the Makefile on `arm64` /
`aarch64` hosts and supplies equivalents using `dsb sy` + reads of
`CNTVCT_EL0`. The ARM generic timer ticks slower than RDTSC (typically
24 MHz on Apple Silicon vs ~3 GHz on x86) but the Welch t-test is
dimensionless in counter units — the constant-time verdict is the
same, just with a slightly different noise floor.

## Install dudect

dudect is NOT packaged by Homebrew or apt. Fetch from upstream:

```bash
./fetch.sh
```

This clones `https://github.com/oreparaz/dudect.git` into
`./dudect/`. The Makefile reads `./dudect/src/dudect.h`.

To pin a specific commit, edit `DUDECT_COMMIT` at the top of
`fetch.sh`.

## Build

```bash
make            # both harnesses
make verify     # just dudect_verify
make combine    # just dudect_combine
make clean
```

The Makefile detects host platform via `uname -s` (Darwin → `.dylib`,
elsewhere → `.so`) and `uname -m` (`arm64` / `aarch64` → include the
compat shim).

## Run

```bash
# Smoke test (default — 10000/2000 samples/batch × 4 batches):
./dudect_verify   2>results/verify.log
./dudect_combine  2>results/combine.log

# Larger budget (override via env):
DUDECT_SAMPLES=1000000 DUDECT_MAX_BATCHES=100 ./dudect_verify

# Full NIST submission budget (~10^9 samples). Pin to a single CPU,
# kill background daemons, disable frequency scaling:
taskset -c 1 sh -c '
    DUDECT_SAMPLES=1000000 DUDECT_MAX_BATCHES=1000 ./dudect_verify
' 2>results/verify-submission.log
```

Exit codes:
- `0` — no leakage evidence at the configured budget
- `2` — leakage detected (t-statistic above dudect threshold)
- other — harness setup failure (look at stderr)

## CI integration

`scripts/check-high-assurance.sh` builds + runs the smoke test
automatically when `dudect/src/dudect.h` is present:

- dudect not fetched → `[skip]` with install instructions
- harness builds, no leakage → `[ok]`
- `dudect_verify` reports leakage → `[warn]` (expected at smoke
  budget per "Verify smoke CT framing" above; not a CT regression,
  not gate-blocking)
- `dudect_combine` reports leakage → `[FAIL]` (Combine handles
  secret shares; gate-blocking)
- other harness rc → `[warn]`
- harness build fails → `[info]` (mid-refactor; non-blocking
  during ongoing development)

## Submission run

NIST evaluates constant-time at the release point. The
submission-grade run requires:
- ~10^9 samples (configure via `DUDECT_SAMPLES` × `DUDECT_MAX_BATCHES`)
- Quiet machine: no background processes, perf governor pinned
- CPU pinning (`taskset -c <cpu>` on Linux; on macOS the harness
  does not pin — Apple Silicon doesn't expose a fixed-frequency
  mode and the timer noise floor is higher; document this honestly
  rather than overclaim a CPU pin)

Use the wrapper:

```bash
# Both targets, default budget (10^6 × 1000 = 10^9 samples each):
bash ct/dudect/run-submission.sh

# Only one target:
TARGET=combine bash ct/dudect/run-submission.sh

# Custom budget (smoke test):
DUDECT_SAMPLES=10000 DUDECT_MAX_BATCHES=10 \
    bash ct/dudect/run-submission.sh

# Pin to CPU 5 on Linux:
CPU=5 bash ct/dudect/run-submission.sh
```

The wrapper produces a self-describing log set under
`ct/dudect/results/submission-<commit>-<utc-stamp>.{meta.txt,
build.log, verify.{stdout,stderr}, combine.{stdout,stderr}}`. The
`.meta.txt` captures:

- timestamp + UTC
- repo commit + dirty-bit
- host OS / arch / kernel / CPU model
- CPU pin (or `none` with reason)
- dudect upstream commit
- Go / cc / jasminc versions
- samples-per-batch + max-batches
- max observed t-statistic (parsed out of dudect stdout)
- iteration count
- exit code per target

This is exactly the metadata NIST submission needs to reproduce the
run.

Pass criterion: no max-t-statistic above 4.5σ (dudect calls this
`t_threshold_moderate=10` by default — we apply the stricter NIST
4.5σ post-hoc when reading the logs).

Pin the canonical submission run to the `submission-` git tag and
preserve the result set under `ct/dudect/results/`.
