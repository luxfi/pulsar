# libjade ML-DSA-65 — single-party verified baseline

This directory holds the **fetched** libjade ML-DSA Jasmin sources used
as the single-party verified core under Pulsar's threshold layer. The
libjade tree is **not** committed to this repository — it is pulled in
on demand via `fetch.sh` at a pinned commit.

## Why fetched, not vendored

Vendoring the libjade tree (~tens of thousands of lines of Jasmin +
EasyCrypt) into the Pulsar submission tarball would:

1. Explode the submission tarball size.
2. Mix licenses (libjade is MIT, this repository is Apache-2.0) in a
   way that confuses provenance — the Pulsar submission should cite +
   link libjade, not redistribute it.
3. Couple the Pulsar submission's reproducibility to libjade's
   internal restructurings (libjade is an active research codebase).

The fetch-on-demand model gives reviewers a deterministic single command
that reproduces the exact libjade tree we built against, without
shipping it.

## How to fetch

```bash
./fetch.sh
```

`fetch.sh` clones libjade at the pinned commit hash `LIBJADE_COMMIT`
(see the script) into `./libjade/`. The Pulsar Jasmin build then
references `./libjade/src/crypto_sign/dilithium/dilithium3/amd64/` as
the ML-DSA-65 (parameter set 3) single-party implementation.

The pinned commit is updated only at submission-tag time so the
release tarball reproduces deterministically.

## What we use from libjade

| libjade artifact | Pulsar role |
|---|---|
| `src/crypto_sign/dilithium/dilithium3/amd64/{ref,avx2}/` | Single-party ML-DSA-65 keygen / sign / verify (the FIPS 204 baseline) |
| `proof/crypto_sign/dilithium/dilithium3/` | EasyCrypt functional + CT theories — imported by `proofs/easycrypt/Pulsar_N1.ec` |

Pulsar's threshold layer (`../threshold/`) wraps these as the
single-party kernel; the Class N1 reduction in
`../../proofs/easycrypt/Pulsar_N1.ec` discharges the byte-equality
claim by routing through libjade's functional theorem for ML-DSA-65.

## What we do NOT use

- libjade's ML-KEM (Kyber) tree — Pulsar is a signature scheme; ML-KEM consumption routes through `~/work/lux/crypto/mlkem/` per FIPS 203.
- libjade's lower-parameter Dilithium variants (Dilithium2, Dilithium5).
  Pulsar's submitted parameter set is ML-DSA-65 only; ML-DSA-44 and
  ML-DSA-87 variants are discussed in `spec/parameters.tex` but the
  reference implementation and submitted KAT vectors target -65.

## Layout after fetch

```
ml-dsa-65/
├── README.md           (this file)
├── fetch.sh            (clones libjade at pinned commit)
├── libjade/            (created by fetch.sh; NOT committed)
└── .gitignore          (ignores libjade/)
```
