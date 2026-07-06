/**
 * @synoi/verify-core - public surface.
 *
 * The ONE offline evidence-bundle verifier (ADR_019 STEP 8). Depends on
 * @synoi/sraid for RFC 8785 JCS canonicalize + cdroContentCore + hybrid DSSE
 * verifyAttestation, keeping @synoi/sraid a pure L0 package. The @synoi/verify
 * CLI re-exports verifyEvidenceBundle; the synoi-gateway self-verify imports it.
 * Neither keeps its own copy.
 *
 * NO em dashes. NO AI attribution.
 */

export {
  verifyEvidenceBundle,
  computeBundleContentDigest,
  bundleContentDigestPreimage,
  EVIDENCE_BUNDLE_VERSION,
  GAP_RECEIPT_PAYLOAD_TYPE,
  STATE_ABSENCE_PAYLOAD_TYPE,
  type EvidenceBundle,
  type EvidenceBundleManifest,
  type BundleHonesty,
  type PublicKeyBundle,
  type BundleVerifyReason,
  type BundleVerifyResult,
  type ReceiptVerifyDetail,
  type AbsenceVerifyDetail,
} from './bundle.js'
