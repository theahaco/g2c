export type { PasskeyRegistration, PasskeySignature, NetworkConfig, } from "./types.js";
export { extractPublicKey, parseAttestationObject, getContractSalt, parseRegistration, } from "./webauthn.js";
export { derToCompact } from "./signature.js";
export { buildAuthHash, getAuthEntry, parseAssertionResponse, injectPasskeySignature, } from "./auth.js";
export { computeAccountAddress, lookupExistingAccount, deploySmartAccount, } from "./deploy.js";
//# sourceMappingURL=index.d.ts.map