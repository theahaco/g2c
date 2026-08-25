export type {
  PasskeyRegistration,
  PasskeySignature,
  NetworkConfig,
} from "./types.js";

export {
  extractPublicKey,
  parseAttestationObject,
  parseRegistration,
} from "./webauthn.js";

export { derToCompact } from "./signature.js";

export {
  buildAuthHash,
  buildAuthHashAt,
  computeAuthDigest,
  getAuthEntry,
  parseAssertionResponse,
  injectPasskeySignature,
  injectSignedAuthPayload,
  DEFAULT_EXPIRATION_OFFSET,
} from "./auth.js";

export { identifyAssertionSigner } from "./assertionMatch.js";

export { buildAuthPayloadScVal } from "./multiSigner.js";
export type { SignerSignature, AuthPayloadSpec } from "./multiSigner.js";

export {
  getContractSalt,
  computeAccountAddress,
  lookupExistingAccount,
  deploySmartAccount,
} from "./deploy.js";

export {
  buf2hex,
  hex2buf,
  buf2base64url,
  base64url2buf,
} from "./encoding.js";

export {
  isContractId,
  contractIdFromHostname,
  nameFromHostname,
  accountUrl,
  stripSubdomain,
  dappPathFromHostname,
  dappUrl,
  RESERVED_DAPP_SUBDOMAINS,
} from "./url.js";

export { resolveName, resolveNameCached, lookupName } from "./resolve.js";

export { fetchRegistryAddress, REGISTRY_FALLBACKS } from "./registry.js";
export type { FetchRegistryAddressOptions } from "./registry.js";

export {
  RelayerError,
  submitSorobanTransaction,
  getRelayerTransaction,
  waitForConfirmation,
  extractFuncAndAuth,
} from "./relayer.js";
export type { RelayerStatus, RelayerTxResponse } from "./relayer.js";

export type { PendingAccount, SessionKeyMaterial } from "./storage.js";

export {
  saveCredential,
  loadCredential,
  saveAccount,
  loadAccounts,
  savePendingAccount,
  loadPendingAccounts,
  removePendingAccount,
  activateAccount,
  saveAccountName,
  loadAccountName,
  saveFriendNickname,
  loadFriendNicknames,
  saveSessionKeyMaterial,
  loadSessionKeyMaterial,
  forgetSessionKeyMaterial,
  saveBlockLabel,
  loadBlockLabels,
} from "./storage.js";

export { extractXdrOperations } from './assembledTx.js';

export * from './policyBlocks/index.js';

export * from './resolveFriendInput.js';

export * from './sessionKey.js';

export * from './syntheticAssertion.js';

export * from './friendSigning.js';

export * from './zkRecovery/index.js';
