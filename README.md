# @synoi/verify-core

The ONE offline evidence-bundle verifier for SynOI (ADR_019 STEP 8).

Before this package there were two `verifyEvidenceBundle` implementations: the
gateway self-verify and the third-party `@synoi/verify` copy. They had drifted -
the gateway copy was strictly weaker (no signed-tenant binding, no vacuous
fail-closed, no key-fingerprint surfacing), so "a green here means a green there"
was false in code. This package collapses both onto ONE function. `@synoi/verify`
re-exports it; the gateway self-verify imports it. Two copies cannot mechanically
disagree when there is only one.

## Contract

- Depends on `@synoi/sraid` for RFC 8785 JCS `canonicalize`, the `cdroContentCore`
  content-core projection, and hybrid DSSE `verifyAttestation` (Ed25519 AND
  ML-DSA-65, both required). No divergent canonicalizer is defined here. This
  keeps `@synoi/sraid` a pure L0 package - the verifier lives one layer up.
- Accepts ONLY `synoi-evidence-bundle-v2`. A v1 bundle is HARD-REJECTED with
  reason `unsupported-bundle-version` (fail-closed, no back-compat window).

## Bundle v2: signed completeness

The v1 `content_digest` committed only `{ receipts, absence_statements }`. It did
NOT commit the completeness flags, so a truncated bundle could be relabeled
`truncated: false` and still verify green - it could lie about completeness under
a green check. v2 folds the completeness flags plus the declared scope INTO the
signed digest preimage:

```
content_digest = 'sha256:' + sha256(canonicalize({
  bundle_version, tenant_id, receipt_count, absence_count,
  truncated, body_filtered_omission, filter, receipts, absence_statements
}))
```

Flipping `truncated` true->false, relabeling `body_filtered_omission`, dropping a
receipt, or changing the declared tenant now BREAKS the digest.

## Checks

1. structural shape (arrays + manifest + honesty present),
2. `bundle_version === v2`, else hard-reject,
3. v2 `content_digest` recomputes and matches (JCS integrity anchor over the
   completeness-committing preimage),
4. manifest counts match the enclosed arrays,
5. every receipt: signed `tenant_id == bundle.tenant_id`, then payload-bound +
   hybrid both-required signature under one enclosed key,
6. every absence statement: same,
7. vacuous fail-closed: a bundle that attests to nothing is not valid.

## Trust anchor

A verified bundle proves the enclosed contents were signed by the key(s) named in
`verifying_key_fingerprints` and not altered since, that every item is bound to
the declared tenant, and that the completeness flags are the ones that were
signed. It does NOT prove those keys are legitimate SynOI gateway keys - the
recipient must anchor the fingerprints OUT OF BAND. It is NOT court-admissible and
NOT regulator-accepted.
