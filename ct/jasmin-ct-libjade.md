# Libjade jasmin-ct status (Pulsar issue #2)

## Status

The Pulsar high-assurance gate runs `jasmin-ct` (Jasmin's
constant-time analyzer) in **two modes**:

* **Blocking** on the threshold layer (round1.jazz, round2.jazz,
  combine.jazz). These ARE clean and the per-push CI exits
  non-zero if any finding appears.
* **Advisory** on the libjade ML-DSA-65 sign source
  (`jasmin/ml-dsa-65/libjade/oldsrc-should-delete/crypto_sign/
  dilithium/dilithium3/amd64/ref/sign.jazz`). This is currently
  **allowed-failure** under tracked issue #2 because libjade
  upstream has one specific public/secret annotation gap that
  jasmin-ct flags. Promoting this to blocking requires either:
  fixing it upstream and bumping the libjade pin; or carrying a
  Pulsar-side patch.

## The exact finding

```
$ jasmin-ct --infer -I "Jade=<libjade-root>" \
    jasmin/ml-dsa-65/libjade/oldsrc-should-delete/crypto_sign/dilithium/dilithium3/amd64/ref/sign.jazz

"jasmin/ml-dsa-65/libjade/oldsrc-should-delete/crypto_sign/dilithium/common/amd64/keygen_end.jinc",
line 125 (23-36):
constant type checker: random_zeta_p has type secret it needs to be public
```

The flagged site is the call:

```jasmin
// keygen_end.jinc, line 124-125 (inline fn keygen):
pk, sk = keygen_inner(random_zeta_p);
```

where `random_zeta_p` is the 32-byte uniformly random seed that
ML-DSA-65 keygen consumes to expand into (rho, K, tr, s1, s2, t0).

## Why jasmin-ct flags this

The Jasmin constant-time analyzer's `--infer` mode propagates
secret-vs-public types through procedure calls. `random_zeta_p`
is annotated as `secret` (correctly — it's the seed of all
secret-key material). But `keygen_inner` returns `pk` (a PUBLIC
value — the ML-DSA public key) along with `sk` (the secret key
material). The signature of `keygen_inner` does not separate
the public vs. secret outputs cleanly: jasmin-ct sees
`random_zeta_p → pk` as a secret-tainted flow into a public
output, which is the canonical CT violation pattern.

In reality this is NOT a CT violation:
* The flow `random_zeta_p → pk` IS legitimate — pk is derived
  from rho (a public byte string itself derived from
  `random_zeta_p` via SHAKE expansion). pk is intended to be
  public.
* The flow `random_zeta_p → sk` is the secret flow we DO want
  jasmin-ct to track.

The fix is an annotation: tell jasmin-ct that the pk output of
`keygen_inner` is a **declassification point** for the rho
component of `random_zeta_p`. This is what
`#[declassify = "pk"]` or an explicit `public` output annotation
in the libjade source would do.

## What needs to happen

### Option A (upstream): patch libjade

Submit a PR to libjade adding the right CT annotations to
`keygen_inner`'s output binding. The annotation needs to make
explicit:
* `sk` stays `secret`.
* `pk` is `public` (post-declassification of the rho fragment
  derived from random_zeta_p via SHAKE).

This is the right long-term move — it benefits every libjade
consumer, not just Pulsar.

### Option B (carry patch): Pulsar-side override

Apply a thin patch to the vendored libjade copy that adds the
annotation; revendor the patched libjade under
`jasmin/ml-dsa-65/libjade/`. Document the diff in this file.
This is a workaround if upstream is slow.

### Option C (blind declassify): NOT acceptable

Adding a `#declassify` on `random_zeta_p` itself would silence
jasmin-ct but would ALSO let real secret-material leakage flow
into public outputs without being flagged. **Do not do this.**

## What we DO NOT promise

Until #2 is closed (upstream PR or carry-patch), the libjade
sign side does NOT carry a blocking constant-time guarantee
from jasmin-ct. The high-assurance gate reports it as advisory.
Constant-time properties of libjade sign are, in practice,
covered by:

* libjade's own upstream review (the code IS CT — the issue
  is just the annotation).
* Manual review of the Pulsar-side calling conventions
  (the threshold wrapper passes secret-bearing inputs only at
  documented secret-ports).
* Dudect smoke runs (`ct/dudect/`).

None of these are equivalent to a clean jasmin-ct gate. They
are upper-bound on the empirical risk; lower-bounding via
mechanical analysis requires #2's closure.

## How to verify the finding

```bash
cd ~/work/lux/pulsar
eval $(opam env --switch=jasmin)
jasmin-ct --infer \
    -I "Jade=$PWD/jasmin/ml-dsa-65/libjade/oldsrc-should-delete" \
    jasmin/ml-dsa-65/libjade/oldsrc-should-delete/crypto_sign/dilithium/dilithium3/amd64/ref/sign.jazz
```

Should print the `random_zeta_p has type secret it needs to be
public` message; no other findings.

## Cross-references

* Pulsar issue tracker: #2.
* Upstream libjade source:
  https://github.com/formosa-crypto/libjade
  (this repo vendors the snapshot under `jasmin/ml-dsa-65/libjade/`).
* The `--infer` mode docs: https://github.com/jasmin-lang/jasmin
  (search for "constant-time inference").
* Related Pulsar threshold-side jasmin-ct (which is CLEAN and
  BLOCKING): `scripts/check-high-assurance.sh` § "jasmin-ct
  (BLOCKING — threshold layer)".
