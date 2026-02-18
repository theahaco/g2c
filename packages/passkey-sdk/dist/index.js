export { extractPublicKey, parseAttestationObject, parseRegistration, } from "./webauthn.js";
export { derToCompact } from "./signature.js";
export { buildAuthHash, getAuthEntry, parseAssertionResponse, injectPasskeySignature, } from "./auth.js";
export { getContractSalt, computeAccountAddress, lookupExistingAccount, deploySmartAccount, } from "./deploy.js";
export { buf2hex, hex2buf, buf2base64url, base64url2buf, } from "./encoding.js";
export { contractIdFromHostname, accountUrl, stripSubdomain, } from "./url.js";
export { saveCredential, loadCredential, saveAccount, loadAccounts, savePendingAccount, loadPendingAccounts, removePendingAccount, activateAccount, } from "./storage.js";
//# sourceMappingURL=index.js.map