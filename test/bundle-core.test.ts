/**
 * test/bundle-core.test.ts - the ONE evidence-bundle verifier (ADR_019 STEP 8).
 *
 * Proves verifyEvidenceBundle over the shipped golden v2 fixture
 * (../synoi-verify/vectors/evidence-bundle.v2.golden.json), whose enclosed
 * receipts + absence statements were signed through the REAL gateway hybrid DSSE
 * oracle. Covers:
 *   1. the valid v2 golden verifies,
 *   2. RETENTION-THESIS FIX - completeness tamper reds the digest:
 *      - flip honesty.truncated true->false        => content-digest-mismatch,
 *      - relabel honesty.body_filtered_omission     => content-digest-mismatch,
 *   3. FAIL-CLOSED - a v1 bundle is rejected unsupported-bundle-version,
 *   4. the retained strong checks still hold on v2:
 *      - flipped receipt body byte, mismatched digest, wrong absence payloadType,
 *        swapped key, manifest count, tenant-mismatch, forged-key different
 *        fingerprint, vacuous fail-closed.
 *
 * ONE CANONICAL TRUTH: verification reuses @synoi/sraid canonicalize +
 * cdroContentCore + verifyAttestation via verifyEvidenceBundle. No divergent
 * canonicalizer here.
 *
 * NO em dashes. NO AI attribution.
 */

import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import { createHash, createPublicKey, generateKeyPairSync, sign as nodeSign } from 'node:crypto'
import { canonicalize, pae } from '@synoi/sraid'
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js'
import {
  verifyEvidenceBundle,
  computeBundleContentDigest,
  type EvidenceBundle,
} from '../src/bundle.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const GOLDEN_V2 = join(__dirname, '..', '..', 'synoi-verify', 'vectors', 'evidence-bundle.v2.golden.json')

function loadGolden(): EvidenceBundle {
  return JSON.parse(readFileSync(GOLDEN_V2, 'utf8')) as EvidenceBundle
}
function clone<T>(x: T): T {
  return JSON.parse(JSON.stringify(x)) as T
}
/** Independent recompute of the hybrid key fingerprint (not echoing src). */
function fingerprintOf(pk: { ed25519_public_key_pem: string; ml_dsa_public_key_b64: string }): string {
  const edDer = createPublicKey({ key: pk.ed25519_public_key_pem, format: 'pem' }).export({
    format: 'der',
    type: 'spki',
  }) as Buffer
  const ml = Buffer.from(pk.ml_dsa_public_key_b64, 'base64')
  return 'sha256:' + createHash('sha256').update(edDer).update(ml).digest('hex')
}

let passed = 0
let failed = 0
function ok(label: string, cond: boolean, detail?: string): void {
  if (cond) {
    passed++
    process.stdout.write(`OK   ${label}\n`)
  } else {
    failed++
    process.stdout.write(`FAIL ${label}${detail ? ' -- ' + detail : ''}\n`)
  }
}

function main(): void {
  const golden = loadGolden()

  // ── 1. VALID v2 golden verifies ──────────────────────────────────────────────
  const v = verifyEvidenceBundle(golden)
  ok('valid v2 golden bundle verifies', v.valid === true, 'reasons: ' + v.reasons.join(','))
  ok('content_digest_ok true', v.content_digest_ok === true)
  ok(
    'every receipt verifies (hybrid both-required)',
    v.receipt_results.length === golden.receipts.length &&
      v.receipt_results.every((r) => r.valid && r.ed25519_valid && r.ml_dsa_valid),
    JSON.stringify(v.receipt_results.filter((r) => !r.valid)),
  )
  ok(
    'every absence statement verifies',
    v.absence_results.length === golden.absence_statements.length && v.absence_results.every((a) => a.valid),
    JSON.stringify(v.absence_results.filter((a) => !a.valid)),
  )

  // ── 2. RETENTION-THESIS FIX: completeness tamper reds the signed digest ───────
  // 2a. Flip honesty.truncated true->false. The v1 preimage did NOT commit this,
  //     so v1 would have verified green. In v2 the flag is INSIDE the digest, so
  //     the recomputed digest no longer matches the (unchanged) manifest digest.
  const tTrunc = clone(golden)
  tTrunc.honesty.truncated = !tTrunc.honesty.truncated // false -> true here
  const vTrunc = verifyEvidenceBundle(tTrunc)
  ok(
    'flipped honesty.truncated REDS the content_digest',
    vTrunc.valid === false && vTrunc.reasons.includes('content-digest-mismatch'),
    vTrunc.reasons.join(','),
  )

  // 2a'. The precise lie the thesis names: a TRUNCATED bundle (truncated:true) is
  //      relabeled truncated:false to present as complete. Build a truncated v2
  //      bundle (recompute its honest digest), then flip the flag back to false
  //      WITHOUT re-signing. It must red.
  const truthfulTruncated = clone(golden)
  truthfulTruncated.honesty.truncated = true
  truthfulTruncated.manifest.content_digest = computeBundleContentDigest(truthfulTruncated)
  ok('a truthfully-truncated v2 bundle verifies', verifyEvidenceBundle(truthfulTruncated).valid === true)
  const liedComplete = clone(truthfulTruncated)
  liedComplete.honesty.truncated = false // the lie: "this bundle is complete"
  const vLied = verifyEvidenceBundle(liedComplete)
  ok(
    'truncated->complete RELABEL cannot verify green (content-digest-mismatch)',
    vLied.valid === false && vLied.reasons.includes('content-digest-mismatch'),
    vLied.reasons.join(','),
  )

  // 2b. Relabel body_filtered_omission true->false to hide a dropped receipt.
  const truthfulOmit = clone(golden)
  truthfulOmit.honesty.body_filtered_omission = true
  truthfulOmit.manifest.content_digest = computeBundleContentDigest(truthfulOmit)
  ok('a truthful body_filtered_omission v2 bundle verifies', verifyEvidenceBundle(truthfulOmit).valid === true)
  const liedOmit = clone(truthfulOmit)
  liedOmit.honesty.body_filtered_omission = false // the lie: "nothing was dropped"
  const vOmit = verifyEvidenceBundle(liedOmit)
  ok(
    'body_filtered_omission RELABEL cannot verify green (content-digest-mismatch)',
    vOmit.valid === false && vOmit.reasons.includes('content-digest-mismatch'),
    vOmit.reasons.join(','),
  )

  // ── 3. FAIL-CLOSED: a v1 bundle is HARD-REJECTED, no back-compat window ───────
  const v1Bundle = clone(golden)
  v1Bundle.bundle_version = 'synoi-evidence-bundle-v1'
  const vV1 = verifyEvidenceBundle(v1Bundle)
  ok(
    'v1 bundle REJECTED unsupported-bundle-version (fail-closed)',
    vV1.valid === false && vV1.reasons.includes('unsupported-bundle-version'),
    vV1.reasons.join(','),
  )
  ok('v1 rejection is terminal (no other reasons attempted)', vV1.reasons.length === 1, vV1.reasons.join(','))

  // A missing honesty block on a v2 bundle also fails closed.
  const tNoHonesty = clone(golden) as Partial<EvidenceBundle>
  delete tNoHonesty.honesty
  const vNoHonesty = verifyEvidenceBundle(tNoHonesty as EvidenceBundle)
  ok(
    'v2 bundle with no honesty block REJECTED (missing-honesty)',
    vNoHonesty.valid === false && vNoHonesty.reasons.includes('missing-honesty'),
    vNoHonesty.reasons.join(','),
  )

  // ── 4. RETAINED STRONG CHECKS on v2 ──────────────────────────────────────────
  // 4a. flipped receipt body byte
  const tByte = clone(golden)
  ;(tByte.receipts[0].body as Record<string, unknown>)['subject_oid'] = 'arn:res/HACKED'
  const vByte = verifyEvidenceBundle(tByte)
  ok(
    'flipped receipt body byte REJECTED',
    vByte.valid === false &&
      (vByte.reasons.includes('content-digest-mismatch') || vByte.reasons.includes('receipt-signature-invalid')),
    vByte.reasons.join(','),
  )

  // 4a'. flip a field AND re-fix the digest to isolate the signature break.
  const tByteFix = clone(golden)
  ;(tByteFix.receipts[0].body as Record<string, unknown>)['status'] = 'denied'
  tByteFix.manifest.content_digest = computeBundleContentDigest(tByteFix)
  const vByteFix = verifyEvidenceBundle(tByteFix)
  ok(
    'tampered receipt with re-fixed digest still fails on signature',
    vByteFix.valid === false && vByteFix.reasons.includes('receipt-signature-invalid'),
    vByteFix.reasons.join(','),
  )

  // 4b. mismatched manifest content_digest
  const tDigest = clone(golden)
  tDigest.manifest.content_digest = 'sha256:' + '0'.repeat(64)
  const vDigest = verifyEvidenceBundle(tDigest)
  ok(
    'mismatched content_digest REJECTED',
    vDigest.valid === false && vDigest.reasons.includes('content-digest-mismatch'),
    vDigest.reasons.join(','),
  )

  // 4c. transplanted / wrong absence payloadType
  const tType = clone(golden)
  ;(tType.absence_statements[0].attestation as { payloadType: string }).payloadType = 'application/vnd.synoi.gap+json'
  tType.manifest.content_digest = computeBundleContentDigest(tType)
  const vType = verifyEvidenceBundle(tType)
  ok(
    'wrong absence payloadType REJECTED (absence-invalid)',
    vType.valid === false && vType.reasons.includes('absence-invalid'),
    vType.reasons.join(','),
  )
  ok(
    'wrong absence payloadType reason is wrong-payload-type',
    vType.absence_results.some((a) => !a.valid && a.reason === 'wrong-payload-type'),
    JSON.stringify(vType.absence_results),
  )

  // 4d. swapped public key
  const tKey = clone(golden)
  const { publicKey: otherPub } = generateKeyPairSync('ed25519', {
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    publicKeyEncoding: { type: 'spki', format: 'pem' },
  })
  tKey.key_history = tKey.key_history.map((k) => ({ ...k, ed25519_public_key_pem: otherPub as unknown as string }))
  const vKey = verifyEvidenceBundle(tKey)
  ok(
    'swapped public key REJECTED (receipt-signature-invalid)',
    vKey.valid === false && vKey.reasons.includes('receipt-signature-invalid'),
    vKey.reasons.join(','),
  )

  // 4e. manifest count disagrees with arrays. Recompute the digest so the count
  //     mismatch is isolated (receipt_count is in the v2 preimage).
  const tCount = clone(golden)
  tCount.manifest.receipt_count = 999
  const vCount = verifyEvidenceBundle(tCount)
  ok(
    'manifest count mismatch REJECTED',
    vCount.valid === false && vCount.reasons.includes('manifest-count-mismatch'),
    vCount.reasons.join(','),
  )

  // 4f. malformed bundle (missing arrays)
  const vMal = verifyEvidenceBundle({} as EvidenceBundle)
  ok('malformed bundle REJECTED', vMal.valid === false && vMal.reasons.includes('malformed-bundle'))

  // ── 5. TENANT BINDING ────────────────────────────────────────────────────────
  // Declared tenant != signed receipt tenant. Recompute the digest so the ONLY
  // failure is the tenant binding, not the digest (tenant_id is in the preimage).
  const tTenant = clone(golden)
  tTenant.tenant_id = 'other-tenant'
  tTenant.manifest.content_digest = computeBundleContentDigest(tTenant)
  const vTenant = verifyEvidenceBundle(tTenant)
  ok(
    'declared tenant != signed receipt tenant REJECTED (receipt-tenant-mismatch)',
    vTenant.valid === false && vTenant.reasons.includes('receipt-tenant-mismatch'),
    vTenant.reasons.join(','),
  )
  ok(
    'tenant-mismatch reason surfaced per receipt',
    vTenant.receipt_results.some((r) => !r.valid && r.reason === 'tenant-mismatch'),
    JSON.stringify(vTenant.receipt_results),
  )
  ok(
    'absence tenant-mismatch also flagged',
    golden.absence_statements.length === 0 || vTenant.reasons.includes('absence-tenant-mismatch'),
    vTenant.reasons.join(','),
  )

  // ── 6. VERIFYING-KEY FINGERPRINT (trust anchor) ──────────────────────────────
  const goldenFp = fingerprintOf(golden.key_history[0])
  ok(
    'golden bundle publishes the golden key fingerprint',
    v.verifying_key_fingerprints.length === 1 && v.verifying_key_fingerprints[0] === `golden-v1 ${goldenFp}`,
    JSON.stringify(v.verifying_key_fingerprints),
  )
  ok('golden result carries bundle_tenant_id', v.bundle_tenant_id === golden.tenant_id, String(v.bundle_tenant_id))

  // ── 7. FORGED-KEY BUNDLE: internally valid, DIFFERENT fingerprint ────────────
  const atkEd = generateKeyPairSync('ed25519')
  const atkEdPubPem = atkEd.publicKey.export({ format: 'pem', type: 'spki' }).toString()
  const atkMl = ml_dsa65.keygen(new Uint8Array(createHash('sha256').update('forged-key-vector').digest()))
  const forged = clone(golden)
  const reSign = (att: { payloadType: string; payload: string; signatures: unknown }): void => {
    const msg = pae(att.payloadType, att.payload)
    const edSig = nodeSign(null, Buffer.from(msg), atkEd.privateKey)
    const mlSig = ml_dsa65.sign(msg, atkMl.secretKey)
    att.signatures = [
      { alg: 'ed25519', sig: Buffer.from(edSig).toString('base64'), keyid: 'attacker-v1' },
      { alg: 'ml-dsa-65', sig: Buffer.from(mlSig).toString('base64'), keyid: 'attacker-v1' },
    ]
  }
  for (const r of forged.receipts) reSign(r.attestation as { payloadType: string; payload: string; signatures: unknown })
  for (const a of forged.absence_statements)
    reSign(a.attestation as { payloadType: string; payload: string; signatures: unknown })
  forged.key_history = [
    {
      key_id: 'attacker-v1',
      ed25519_public_key_pem: atkEdPubPem,
      ml_dsa_public_key_b64: Buffer.from(atkMl.publicKey).toString('base64'),
    },
  ]
  forged.manifest.content_digest = computeBundleContentDigest(forged)
  const vForged = verifyEvidenceBundle(forged)
  ok('forged-key bundle is internally VALID (proves a key signed it)', vForged.valid === true, vForged.reasons.join(','))
  const forgedFp = fingerprintOf(forged.key_history[0])
  ok(
    'forged-key bundle publishes a DIFFERENT fingerprint the recipient rejects',
    vForged.verifying_key_fingerprints.length === 1 &&
      vForged.verifying_key_fingerprints[0] === `attacker-v1 ${forgedFp}` &&
      forgedFp !== goldenFp,
    JSON.stringify(vForged.verifying_key_fingerprints),
  )

  // ── 8. VACUOUS BUNDLE fails closed ───────────────────────────────────────────
  const vacuous = clone(golden)
  vacuous.receipts = []
  vacuous.absence_statements = []
  vacuous.manifest = { receipt_count: 0, absence_count: 0, content_digest: '' }
  vacuous.manifest.content_digest = computeBundleContentDigest(vacuous)
  const vVacuous = verifyEvidenceBundle(vacuous)
  ok('vacuous bundle (0 receipts, 0 absence) fails closed', vVacuous.valid === false, vVacuous.reasons.join(','))
  ok(
    "vacuous bundle reason is 'no-verifiable-content'",
    vVacuous.reasons.includes('no-verifiable-content'),
    JSON.stringify(vVacuous.reasons),
  )
  ok('vacuous bundle content_digest still checks out (not the failure mode)', vVacuous.content_digest_ok === true)

  process.stdout.write(`\nbundle-core: ${passed} passed, ${failed} failed\n`)
  process.exit(failed === 0 ? 0 : 1)
}

main()
