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
  getAuthEntry,
  parseAssertionResponse,
  injectPasskeySignature,
} from "./auth.js";

export {
  getContractSalt,
  computeAccountAddress,
  lookupExistingAccount,
  deploySmartAccount,
} from "./deploy.js";
