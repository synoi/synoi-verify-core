/**
 * @synoi/verify-core src/bundle.ts - the ONE offline EVIDENCE BUNDLE verifier.
 *
 * ADR_019 STEP 8. Before this package there were TWO verifyEvidenceBundle copies:
 * the gateway self-verify (synoi-gateway gap/ledger/evidence-bundle.ts) was
 * strictly WEAKER than the third-party one (synoi-verify src/bundle.ts) - it
 * lacked the signed-tenant binding, the vacuous-bundle fail-closed, and the
 * key-fingerprint surfacing. "A green here means a green there" was FALSE in code.
 * This module collapses both onto ONE function that carries EVERY stronger check.
 * The @synoi/verify CLI re-exports it; the gateway self-verify imports it. Neither
 * keeps its own copy, so they cannot mechanically disagree.
 *
 * BUNDLE v2 (ADR_019 STEP 8, decision 4). The v1 content_digest committed only
 * { receipts, absence_statements }. It did NOT commit the completeness/honesty
 * assertions (truncated, body_filtered_omission), so a truncated bundle could be
 * flipped to truncated:false and still verify green - it could lie about
 * completeness under a green check. v2 folds those flags (and the scope: tenant,
 * counts, filter, version) INTO the signed digest preimage:
 *
 *   content_digest = 'sha256:' + sha256(canonicalize({
 *     bundle_version, tenant_id, receipt_count, absence_count,
 *     truncated, body_filtered_omission, filter, receipts, absence_statements
 *   }))
 *
 * Flipping truncated true->false, relabeling body_filtered_omission, dropping a
 * receipt, or changing the declared tenant now BREAKS the digest. A truncated or
 * body-filtered bundle can no longer present as complete and verify green.
 *
 * FAIL-CLOSED. This verifier HARD-REJECTS v1 bundles with reason
 * 'unsupported-bundle-version'. There is NO allowLegacyV1Bundle window: a v1
 * bundle carried no signed completeness guarantee to lose, so it is not
 * v2-verifiable and must not be accepted as if it were.
 *
 * HONEST CLAIM. A verified bundle proves the enclosed contents were signed by a
 * SPECIFIC key (named by fingerprint in the result) and have not been altered
 * since, that every signed item is bound to the bundle's declared tenant_id, and
 * that the completeness flags are the ones that were signed. It does NOT prove
 * that key is a legitimate SynOI gateway key: trust in the key is a SEPARATE
 * anchor the recipient must establish OUT OF BAND. It is NOT court-admissible and
 * NOT regulator-accepted; those are legal determinations this code cannot make.
 *
 * ONE CANONICAL TRUTH. Canonicalization (RFC 8785 JCS), the content-core
 * projection (cdroContentCore), and hybrid DSSE verification (verifyAttestation,
 * Ed25519 AND ML-DSA-65 both-required) come from @synoi/sraid. This module does
 * NOT re-implement a canonicalizer; a divergent canonicalizer is a
 * signature-confusion hazard and is not reintroduced here.
 *
 * NO em dashes. NO AI attribution.
 */

import { createHash, createPublicKey } from 'node:crypto'
import { canonicalize, cdroContentCore, verifyAttestation } from '@synoi/sraid'
import type { AttestationEnvelope } from '@synoi/sraid'

/**
 * The ONLY bundle version this verifier accepts. v1 bundles are hard-rejected
 * (unsupported-bundle-version); they carried no signed completeness guarantee.
 */
export const EVIDENCE_BUNDLE_VERSION = 'synoi-evidence-bundle-v2'

/**
 * DSSE payload type a GAP decision-receipt attestation carries. Pinned so a
 * receipt attestation cannot be transplanted onto a different object class.
 */
export const GAP_RECEIPT_PAYLOAD_TYPE = 'application/vnd.synoi.gap+json'

/**
 * DSSE payload type a provable-absence statement carries. Distinct from the
 * receipt type so the two attestation classes are not interchangeable (the DSSE
 * PAE binds payloadType into the signed bytes).
 */
export const STATE_ABSENCE_PAYLOAD_TYPE = 'application/vnd.synoi.state-absence+json'

/**
 * A PUBLIC key-history entry: verification material for one signing key-id. NO
 * private/secret material.
 */
export interface PublicKeyBundle {
  key_id: string
  /** Ed25519 public key, SPKI PEM. */
  ed25519_public_key_pem: string
  /** Ed25519 public key, raw 32 bytes, base64. Optional; PEM is authoritative. */
  ed25519_public_key_b64?: string
  /** ML-DSA-65 public key, raw bytes, base64. FIPS 204. */
  ml_dsa_public_key_b64: string
}

/**
 * The completeness/honesty assertions. In v2 the machine-checkable subset
 * (truncated, body_filtered_omission) is folded INTO the signed content_digest.
 * The remaining fields are fixed advisory constants.
 */
export interface BundleHonesty {
  tamper_evident?: boolean
  independently_verifiable_offline?: boolean
  court_admissible?: boolean
  regulator_accepted?: boolean
  /** True when the export could not include every selected receipt. SIGNED in v2. */
  truncated: boolean
  /** True when a body-level filter dropped column-backed receipts. SIGNED in v2. */
  body_filtered_omission: boolean
  note?: string
}

export interface EvidenceBundleManifest {
  receipt_count: number
  absence_count: number
  /** v2: 'sha256:' + sha256(canonicalize(<v2 preimage incl. completeness flags>)). */
  content_digest: string
}

export interface EvidenceBundle {
  bundle_version: string
  generated_at_ms: number
  tenant_id: string
  filter: Record<string, unknown>
  receipts: Record<string, unknown>[]
  absence_statements: Record<string, unknown>[]
  key_history: PublicKeyBundle[]
  manifest: EvidenceBundleManifest
  honesty: BundleHonesty
}

export type BundleVerifyReason =
  | 'malformed-bundle'
  | 'unsupported-bundle-version'
  | 'missing-honesty'
  | 'manifest-count-mismatch'
  | 'content-digest-mismatch'
  | 'receipt-missing-attestation'
  | 'receipt-signature-invalid'
  | 'receipt-tenant-mismatch'
  | 'absence-invalid'
  | 'absence-tenant-mismatch'
  | 'no-verifiable-content'

export interface ReceiptVerifyDetail {
  oid: string
  valid: boolean
  ed25519_valid: boolean
  ml_dsa_valid: boolean
  /** key_id whose material verified this item (only set when valid). */
  verifying_key_id?: string
  /** Fingerprint of the key that verified this item (only set when valid). */
  verifying_key_fingerprint?: string
  reason?: string
}

export interface AbsenceVerifyDetail {
  oid: string
  valid: boolean
  verifying_key_id?: string
  verifying_key_fingerprint?: string
  reason?: string
}

export interface BundleVerifyResult {
  valid: boolean
  reasons: BundleVerifyReason[]
  content_digest_ok: boolean
  recomputed_content_digest?: string
  receipt_results: ReceiptVerifyDetail[]
  absence_results: AbsenceVerifyDetail[]
  /** tenant_id the bundle DECLARES; every signed item is bound to it. */
  bundle_tenant_id?: string
  /**
   * De-duplicated fingerprints of the keys that ACTUALLY verified one or more
   * enclosed items, each as 'key_id sha256:<hex>'. This is the trust anchor the
   * recipient must confirm OUT OF BAND: a valid bundle proves these keys signed
   * the contents, NOT that these keys are legitimate SynOI gateway keys.
   */
  verifying_key_fingerprints: string[]
}

/**
 * Reconstruct ed25519 raw + ml-dsa public key bytes from a PublicKeyBundle in the
 * bundle's OWN key_history, so verification uses ONLY material carried IN the
 * bundle (true offline verification, no external key state).
 */
function keysFromPublicBundle(pk: PublicKeyBundle): {
  ed25519_pub: Uint8Array
  ml_dsa_pub: Uint8Array
} {
  const edPub = createPublicKey({ key: pk.ed25519_public_key_pem, format: 'pem' })
  const edDer = edPub.export({ format: 'der', type: 'spki' }) as Buffer
  const ed25519_pub = new Uint8Array(edDer.subarray(edDer.length - 32))
  const ml_dsa_pub = new Uint8Array(Buffer.from(pk.ml_dsa_public_key_b64, 'base64'))
  return { ed25519_pub, ml_dsa_pub }
}

/**
 * Stable fingerprint of a hybrid public key = 'sha256:' + sha256 over the
 * concatenation of the Ed25519 SPKI DER bytes and the ML-DSA-65 raw public
 * bytes. Both halves are included so a bundle that swaps EITHER key produces a
 * DIFFERENT fingerprint the recipient can reject.
 */
function keyFingerprint(pk: PublicKeyBundle): string {
  const edPub = createPublicKey({ key: pk.ed25519_public_key_pem, format: 'pem' })
  const edDer = edPub.export({ format: 'der', type: 'spki' }) as Buffer
  const mlPub = Buffer.from(pk.ml_dsa_public_key_b64, 'base64')
  const hex = createHash('sha256').update(edDer).update(mlPub).digest('hex')
  return `sha256:${hex}`
}

/**
 * BUNDLE v2 SIGNED-COMPLETENESS PREIMAGE (ADR_019 STEP 8). The single source of
 * truth for the content_digest, shared by producer and verifier. Committing the
 * completeness flags (truncated, body_filtered_omission) plus the declared scope
 * (bundle_version, tenant_id, counts, filter) alongside the content means a
 * completeness lie (flip truncated true->false, relabel body_filtered_omission,
 * drop a receipt, relabel the tenant) BREAKS the digest.
 *
 * Field order in the object is irrelevant: canonicalize (RFC 8785 JCS) sorts
 * keys. It is written in a fixed order here purely for readability.
 */
export function bundleContentDigestPreimage(input: {
  bundle_version: string
  tenant_id: string
  receipt_count: number
  absence_count: number
  truncated: boolean
  body_filtered_omission: boolean
  filter: Record<string, unknown>
  receipts: unknown[]
  absence_statements: unknown[]
}): Record<string, unknown> {
  return {
    bundle_version: input.bundle_version,
    tenant_id: input.tenant_id,
    receipt_count: input.receipt_count,
    absence_count: input.absence_count,
    truncated: input.truncated,
    body_filtered_omission: input.body_filtered_omission,
    filter: input.filter,
    receipts: input.receipts,
    absence_statements: input.absence_statements,
  }
}

/**
 * Compute the v2 integrity anchor: 'sha256:' + sha256 over the JCS-canonical form
 * of the v2 preimage. RFC 8785 JCS via @synoi/sraid, NOT bare JSON.stringify, so
 * key order + number formatting are deterministic across producer and verifier.
 */
export function computeBundleContentDigest(bundle: EvidenceBundle): string {
  const preimage = bundleContentDigestPreimage({
    bundle_version: bundle.bundle_version,
    tenant_id: bundle.tenant_id,
    receipt_count: bundle.manifest.receipt_count,
    absence_count: bundle.manifest.absence_count,
    truncated: bundle.honesty.truncated,
    body_filtered_omission: bundle.honesty.body_filtered_omission,
    filter: bundle.filter,
    receipts: bundle.receipts,
    absence_statements: bundle.absence_statements,
  })
  const canonical = canonicalize(preimage)
  const hex = createHash('sha256').update(canonical, 'utf8').digest('hex')
  return `sha256:${hex}`
}

/**
 * Verify one enclosed GAP decision-receipt against the bundle key_history,
 * offline. Authentic IFF its DSSE attestation verifies (BOTH Ed25519 AND
 * ML-DSA-65 under one bundled key) over the canonical signing payload AND the
 * attestation payload equals the recomputed canonical form of the presented
 * receipt AND the SIGNED tenant_id equals the bundle's declared tenant_id.
 */
function verifyReceiptInBundle(
  receipt: Record<string, unknown>,
  keyHistory: PublicKeyBundle[],
  bundleTenantId: string,
): ReceiptVerifyDetail {
  const oid = typeof receipt.oid === 'string' ? receipt.oid : '(no-oid)'
  const att = receipt.attestation as
    | { payloadType?: unknown; payload?: unknown; signatures?: unknown }
    | undefined

  if (!att || typeof att !== 'object' || !Array.isArray(att.signatures) || att.signatures.length === 0) {
    return { oid, valid: false, ed25519_valid: false, ml_dsa_valid: false, reason: 'missing-attestation' }
  }
  if (att.payloadType !== GAP_RECEIPT_PAYLOAD_TYPE) {
    return { oid, valid: false, ed25519_valid: false, ml_dsa_valid: false, reason: 'wrong-payload-type' }
  }

  // TENANT BINDING: the receipt's tenant_id is INSIDE the signed core
  // (cdroContentCore keeps it), so a signature over a receipt for tenant A cannot
  // be relabeled tenant B without breaking below. Reject a receipt whose SIGNED
  // tenant_id does not equal the bundle's declared tenant_id.
  if (receipt.tenant_id !== bundleTenantId) {
    return { oid, valid: false, ed25519_valid: false, ml_dsa_valid: false, reason: 'tenant-mismatch' }
  }

  // PAYLOAD BINDING: signed bytes are canonicalize(cdroContentCore(receipt)).
  // Recompute over the PRESENTED receipt and require an exact match, so a body
  // whose field was flipped is rejected even if carried alongside a stale-valid
  // payload. cdroContentCore strips the six envelope fields incl. oid/attestation.
  let expectedPayload: string
  try {
    expectedPayload = canonicalize(cdroContentCore(receipt))
  } catch {
    return { oid, valid: false, ed25519_valid: false, ml_dsa_valid: false, reason: 'payload-binding-mismatch' }
  }
  if (att.payload !== expectedPayload) {
    return { oid, valid: false, ed25519_valid: false, ml_dsa_valid: false, reason: 'payload-binding-mismatch' }
  }

  for (const pk of keyHistory) {
    try {
      const { ed25519_pub, ml_dsa_pub } = keysFromPublicBundle(pk)
      const v = verifyAttestation({
        envelope: att as unknown as AttestationEnvelope,
        ed25519_pub,
        ml_dsa_pub,
        expectedPayloadType: GAP_RECEIPT_PAYLOAD_TYPE,
      })
      if (v.valid) {
        return {
          oid,
          valid: true,
          ed25519_valid: true,
          ml_dsa_valid: true,
          verifying_key_id: pk.key_id,
          verifying_key_fingerprint: keyFingerprint(pk),
        }
      }
    } catch {
      /* fail-closed, try next key */
    }
  }
  return { oid, valid: false, ed25519_valid: false, ml_dsa_valid: false, reason: 'signature-invalid' }
}

/**
 * Verify one enclosed absence statement against the bundle key_history, offline,
 * using the SAME DSSE contract absence.ts writes: recompute the signed content
 * core (strip signature_key_id, set AFTER signing; cdroContentCore excludes
 * oid/attestation), pin the absence payloadType, require BOTH signatures under one
 * bundled key, and bind the SIGNED tenant_id to the bundle's declared tenant.
 */
function verifyAbsenceInBundle(
  stmt: Record<string, unknown>,
  keyHistory: PublicKeyBundle[],
  bundleTenantId: string,
): AbsenceVerifyDetail {
  const oid = typeof stmt.oid === 'string' ? stmt.oid : '(no-oid)'
  const att = stmt.attestation as
    | { payloadType?: unknown; payload?: unknown; signatures?: unknown }
    | undefined

  if (!att || typeof att !== 'object' || !Array.isArray(att.signatures) || att.signatures.length === 0) {
    return { oid, valid: false, reason: 'missing-attestation' }
  }
  if (att.payloadType !== STATE_ABSENCE_PAYLOAD_TYPE) {
    return { oid, valid: false, reason: 'wrong-payload-type' }
  }

  // TENANT BINDING: the absence statement's tenant_id is INSIDE the signed core.
  if (stmt.tenant_id !== bundleTenantId) {
    return { oid, valid: false, reason: 'tenant-mismatch' }
  }

  // Recompute the signed core exactly as absence.ts did: strip signature_key_id
  // (set AFTER signing); cdroContentCore strips oid/attestation.
  let expectedPayload: string
  try {
    const { signature_key_id: _skid, ...unsigned } = stmt
    void _skid
    expectedPayload = canonicalize(cdroContentCore(unsigned))
  } catch {
    return { oid, valid: false, reason: 'payload-binding-mismatch' }
  }
  if (att.payload !== expectedPayload) {
    return { oid, valid: false, reason: 'payload-binding-mismatch' }
  }

  // Defensive: a signed absence body must carry a string examined_receipt_digest.
  const body = stmt.body as { examined_receipt_digest?: unknown } | undefined
  if (!body || typeof body.examined_receipt_digest !== 'string') {
    return { oid, valid: false, reason: 'malformed-absence' }
  }

  for (const pk of keyHistory) {
    try {
      const { ed25519_pub, ml_dsa_pub } = keysFromPublicBundle(pk)
      const v = verifyAttestation({
        envelope: att as unknown as AttestationEnvelope,
        ed25519_pub,
        ml_dsa_pub,
        expectedPayloadType: STATE_ABSENCE_PAYLOAD_TYPE,
      })
      if (v.valid) {
        return { oid, valid: true, verifying_key_id: pk.key_id, verifying_key_fingerprint: keyFingerprint(pk) }
      }
    } catch {
      /* fail-closed, try next key */
    }
  }
  return { oid, valid: false, reason: 'signature-invalid' }
}

/**
 * Verify an evidence bundle OFFLINE. Fail-closed, never throws. Any mismatch =>
 * valid=false with a specific machine-readable reason per failure. Uses ONLY
 * material carried in the bundle (its own key_history), so a third party can run
 * it with just the JSON + this library.
 *
 * Synchronous: every dependency (canonicalize, cdroContentCore, verifyAttestation)
 * is synchronous. The @synoi/verify CJS package wraps this in an async re-export;
 * the gateway (which already statically imports @synoi/sraid) calls it directly.
 *
 * Checks, in order:
 *   1. structural shape (arrays + manifest + honesty present),
 *   2. bundle_version === v2, else HARD-REJECT (unsupported-bundle-version),
 *   3. v2 content_digest recomputes and matches manifest (JCS integrity anchor
 *      over the completeness-committing preimage),
 *   4. manifest counts match the enclosed arrays,
 *   5. every receipt: SIGNED tenant_id == bundle tenant_id, then payload-bound
 *      + hybrid both-required signature,
 *   6. every absence statement: same,
 *   7. vacuous fail-closed: a bundle that attests to nothing is not valid.
 */
export function verifyEvidenceBundle(bundle: EvidenceBundle): BundleVerifyResult {
  const reasons: BundleVerifyReason[] = []
  const result: BundleVerifyResult = {
    valid: false,
    reasons,
    content_digest_ok: false,
    receipt_results: [],
    absence_results: [],
    verifying_key_fingerprints: [],
  }

  if (
    !bundle ||
    typeof bundle !== 'object' ||
    !Array.isArray(bundle.receipts) ||
    !Array.isArray(bundle.absence_statements) ||
    !Array.isArray(bundle.key_history) ||
    !bundle.manifest ||
    typeof bundle.manifest !== 'object'
  ) {
    reasons.push('malformed-bundle')
    return result
  }

  result.bundle_tenant_id = typeof bundle.tenant_id === 'string' ? bundle.tenant_id : undefined

  // (v2 FAIL-CLOSED) Only v2 is verifiable. A v1 bundle carried no signed
  // completeness guarantee, so it is hard-rejected here with NO back-compat
  // window. This is fatal to validity; return early so no v1 preimage is even
  // attempted (v1's digest committed a different, weaker preimage).
  if (bundle.bundle_version !== EVIDENCE_BUNDLE_VERSION) {
    reasons.push('unsupported-bundle-version')
    return result
  }

  // (v2) honesty block is REQUIRED: its flags are folded into the signed digest,
  // so a bundle that omits it cannot have a well-defined content_digest preimage.
  if (
    !bundle.honesty ||
    typeof bundle.honesty !== 'object' ||
    typeof bundle.honesty.truncated !== 'boolean' ||
    typeof bundle.honesty.body_filtered_omission !== 'boolean'
  ) {
    reasons.push('missing-honesty')
    return result
  }

  // Every signed item MUST bind to a concrete declared tenant. A bundle with a
  // missing/non-string tenant_id cannot bind anything, so fail closed.
  const bundleTenantId = typeof bundle.tenant_id === 'string' ? bundle.tenant_id : ' __no_tenant__'

  // (1) content_digest: recompute over the v2 preimage (incl. completeness flags).
  const recomputed = computeBundleContentDigest(bundle)
  result.recomputed_content_digest = recomputed
  result.content_digest_ok = recomputed === bundle.manifest.content_digest
  if (!result.content_digest_ok) reasons.push('content-digest-mismatch')

  // (2) manifest counts must match the enclosed arrays.
  if (
    bundle.manifest.receipt_count !== bundle.receipts.length ||
    bundle.manifest.absence_count !== bundle.absence_statements.length
  ) {
    reasons.push('manifest-count-mismatch')
  }

  const fingerprints = new Set<string>()

  // (3) each receipt signature, offline against the bundle key_history.
  let anyReceiptSigBad = false
  let anyReceiptMissingAtt = false
  let anyReceiptTenantMismatch = false
  for (const r of bundle.receipts) {
    const d = verifyReceiptInBundle(r, bundle.key_history, bundleTenantId)
    result.receipt_results.push(d)
    if (d.valid && d.verifying_key_id && d.verifying_key_fingerprint) {
      fingerprints.add(`${d.verifying_key_id} ${d.verifying_key_fingerprint}`)
    }
    if (!d.valid) {
      if (d.reason === 'missing-attestation') anyReceiptMissingAtt = true
      else if (d.reason === 'tenant-mismatch') anyReceiptTenantMismatch = true
      else anyReceiptSigBad = true
    }
  }
  if (anyReceiptMissingAtt) reasons.push('receipt-missing-attestation')
  if (anyReceiptTenantMismatch) reasons.push('receipt-tenant-mismatch')
  if (anyReceiptSigBad) reasons.push('receipt-signature-invalid')

  // (4) each absence statement, offline against the bundle key_history.
  let anyAbsenceSigBad = false
  let anyAbsenceTenantMismatch = false
  for (const s of bundle.absence_statements) {
    const d = verifyAbsenceInBundle(s, bundle.key_history, bundleTenantId)
    result.absence_results.push(d)
    if (d.valid && d.verifying_key_id && d.verifying_key_fingerprint) {
      fingerprints.add(`${d.verifying_key_id} ${d.verifying_key_fingerprint}`)
    }
    if (!d.valid) {
      if (d.reason === 'tenant-mismatch') anyAbsenceTenantMismatch = true
      else anyAbsenceSigBad = true
    }
  }
  if (anyAbsenceTenantMismatch) reasons.push('absence-tenant-mismatch')
  if (anyAbsenceSigBad) reasons.push('absence-invalid')

  result.verifying_key_fingerprints = [...fingerprints].sort()

  // (5) fail closed on a VACUOUS bundle: nothing to attest to.
  if (
    bundle.receipts.length === 0 &&
    bundle.absence_statements.length === 0 &&
    result.verifying_key_fingerprints.length === 0
  ) {
    reasons.push('no-verifiable-content')
  }

  result.valid = reasons.length === 0
  return result
}
