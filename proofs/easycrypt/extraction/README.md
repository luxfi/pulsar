# Jasmin → EasyCrypt extraction artifacts

This directory holds the output of `jasmin2ec` run over the threshold
layer in `jasmin/threshold/`. The artifact is **not vendored** — it is
regenerated on demand by `scripts/extract-jasmin-ec.sh`. CI runs that
extraction script as part of the high-assurance gate and discards the
output between runs.

## Why on-demand rather than vendored

The extraction produces ~4000 lines of EC per .jazz function plus
~60 array-support theories shared across the threshold layer and
libjade. Vendoring this would (a) be 5+ MB of generated EC drowning
human-written proofs in the repo, (b) drift silently if a Jasmin
source change isn't followed by a re-extraction, and (c) couple repo
bumps to specific `jasmin2ec` versions.

On-demand reproduction is simpler and more honest:

```
$ bash scripts/extract-jasmin-ec.sh
```

…produces `proofs/easycrypt/extraction/build/{combine,round1,round2}.ec`
plus the array-support theories.

## What the extraction guarantees

The fact that `jasmin2ec` produces an EC theory that compiles standalone
guarantees:

1. The Jasmin source is well-typed at every compilation pass `jasmin2ec`
   runs (default `--after=typing`).
2. The libjade dependencies resolve to EC theories that exist in the
   libjade-fetched tree at the pinned commit.
3. The generated EC theory parses + type-checks under the same EasyCrypt
   version we use for the hand-written proofs.

It does **NOT** guarantee:

- That `M.pulsar_combine` (the extracted procedure) refines
  `CombineAbs.combine` (the abstract spec in `Pulsar_N1.ec`). That
  refinement is a separate proof obligation — the byte-level
  `equiv [ M.pulsar_combine ~ CombineAbs.combine : ... ==> ={res} ]` —
  which requires a memory model + the ABI bridge from pointer-based
  W64 args to the abstract `(group_pk, m, ctx, …)` tuple.

The refinement obligations are tracked as separate issues (different
proof efforts, different reviewers, different failure modes):

- [#4 — `combine_body_axiom` refinement](https://github.com/luxfi/pulsar/issues/4):
  `equiv [ M.pulsar_combine ~ CombineAbs.combine : ... ]`
- [#3 — `S_functional_spec` refinement](https://github.com/luxfi/pulsar/issues/3):
  `equiv [ M.sign ~ FIPS204Sign.sign : ... ]` (libjade ML-DSA-65)
- [#2 — jasmin-ct annotations](https://github.com/luxfi/pulsar/issues/2):
  add `#public` / `#declassify` to 4 .jazz files so the
  `jasmin-ct-leakage` CI job flips from advisory to blocking.

## Pinning

- Jasmin version: from `~/.opam/jasmin/bin/jasminc -version` at extract time.
- libjade commit: `9426b32` (pinned by `jasmin/ml-dsa-65/fetch.sh`).
- EasyCrypt commit: `909464e` (pinned by `.github/workflows/ci.yml`
  `Install EasyCrypt (source build)` step).
