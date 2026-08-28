// @nidohq/testkit — create and exercise a Nido smart account from local keys
// (ed25519, secp256r1, ML-DSA-65), with no passkey, and simulate authorization
// locally. See the tracking issue for scope + roadmap (soroban-env in the
// browser via wasmi + rs-soroban-sdk#1657 cache for lazy testnet pulls).

export {
  generateKeypair,
  ed25519Keypair,
  secp256r1Keypair,
  mlDsa65Keypair,
  type Algorithm,
  type RawKeypair,
} from './crypto.js';

export { localSigner, type LocalSigner, type LocalSignerOptions } from './signer.js';

export {
  VERIFIERS,
  verifySignature,
  type VerifierInfo,
  type SignatureData,
} from './verifiers.js';

export {
  createLocalAccount,
  deriveAccountAddress,
  DEFAULT_FACTORY,
  TESTNET_PASSPHRASE,
  type LocalAccount,
  type CreateAccountOptions,
} from './account.js';

export {
  simulateCheckAuth,
  type SimContext,
  type SimArg,
  type SimResult,
  type Verdict,
} from './checkauth.js';

export {
  computeAuthDigest,
  buildSyntheticAssertion,
  verifySyntheticAssertion,
  type SyntheticAssertion,
} from './auth.js';

// perch policy surface (vendored / mirrored from @stellar-registry/perch)
export { canonicalJson, docHash, CANON_VERSION } from './perch/canonical.js';
export {
  rule,
  selfAdmin,
  contract,
  isSelf,
  addressEq,
  stringIn,
  stringPrefix,
  u32Eq,
  type PolicyDoc,
  type Rule,
  type RuleInit,
  type SignerDecl,
  type Scope,
  type Principals,
  type ArgPred,
  type ArgConstraint,
  type CapConstraint,
} from './perch/policy.js';
export {
  reachableCalls,
  isNarrowing,
  type ReachableScope,
  type FnSet,
  type NarrowingResult,
} from './perch/analysis.js';
