# Contributing to Pulsar-M

## What we accept

This is a NIST-MPTC-track repository. Until the 2026-Nov-16 package
submission, contributions that align with the MPTC submission are highest
priority:

1. **Specification clarity** — text edits that disambiguate `spec/*.tex`.
2. **Reference implementation** — `ref/go/`. Boring, clear, no assembly,
   no clever abstractions. Match the spec section-by-section.
3. **Test vectors** — `vectors/*.json`. Cross-validate against the FIPS 204
   reference (output interchangeability is the headline claim).
4. **Constant-time analysis** — `ct/dudect/`. Show, don't claim.
5. **Lattice-estimator runs** — `estimator/`. Concrete classical + quantum
   security-strength tables.
6. **Cryptanalysis** — open an issue. We track external review explicitly.

## What we don't accept

Until after the MPTC submission lands:

- New protocol features. Spec freeze is hard.
- Optimized implementations (AVX2, SIMD, hand-rolled assembly).
- HSM integration patches.
- Production-deployment patches.
- BLAKE3 hash-suite changes — the NIST profile uses SHAKE/cSHAKE/KMAC
  exclusively. BLAKE3 deltas land in upstream `luxfi/pulsar`, not here.

These reopen post-submission.

## Process

1. **Open an issue first.** Discuss the change before implementing.
2. **One concern per PR.** Don't bundle spec edits with implementation
   changes. The MPTC review process treats them as separate artifacts.
3. **CI must pass.** Build, test, KAT regeneration, dudect, lattice-estimator
   all green before merge.
4. **Sign your commits.** GPG-signed, real name in `Signed-off-by`.
   Patent-claim disclosures attach to commits.

## Development setup

```bash
git clone https://github.com/luxfi/pulsar-m
cd pulsar-m
./scripts/build.sh
./scripts/test.sh
```

Spec build requires LaTeX (TeX Live 2024+):
```bash
cd spec/
latexmk -pdf pulsar-m.tex
```

## Coding standards (Go reference)

- Go 1.22+.
- All logging via `github.com/luxfi/log`. **No `log.Println`, `log.Fatalf`,
  `fmt.Printf`** in code that touches a secret.
- All secret comparison via `crypto/subtle` or local constant-time helpers.
- All sampling via the central `pkg/sampling` interface. Direct
  `math/rand` is forbidden.
- Errors carry context via `fmt.Errorf("%w", err)` not bare panics.

## License

By contributing, you agree your contribution is licensed under Apache-2.0
and grant the patent license described in the Apache 2.0 §3.

For NIST MPTC submission: contributions are subject to the patent-claim
disclosures collected in `docs/patent-notes-draft.md`.
