import { buf2hex, buf2base64url, base64url2buf } from "./encoding.js";
export function saveCredential(contractId, credentialId, publicKey) {
    const prefix = `passkey:${contractId}:`;
    localStorage.setItem(prefix + "credentialId", buf2base64url(credentialId));
    localStorage.setItem(prefix + "publicKey", buf2hex(publicKey));
}
export function loadCredential(contractId) {
    const prefix = `passkey:${contractId}:`;
    const credId = localStorage.getItem(prefix + "credentialId");
    const pubKey = localStorage.getItem(prefix + "publicKey");
    if (credId && pubKey)
        return { credentialId: base64url2buf(credId), publicKey: pubKey };
    return null;
}
export function saveAccount(contractId) {
    const accounts = JSON.parse(localStorage.getItem("g2c:accounts") || "[]");
    if (!accounts.includes(contractId)) {
        accounts.push(contractId);
        localStorage.setItem("g2c:accounts", JSON.stringify(accounts));
    }
}
export function loadAccounts() {
    return JSON.parse(localStorage.getItem("g2c:accounts") || "[]");
}
//# sourceMappingURL=storage.js.map