import { buf2hex, buf2base64url, base64url2buf } from "./encoding.js";

declare const localStorage: {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
};

export function saveCredential(contractId: string, credentialId: Uint8Array, publicKey: Uint8Array): void {
  const prefix = `passkey:${contractId}:`;
  localStorage.setItem(prefix + "credentialId", buf2base64url(credentialId));
  localStorage.setItem(prefix + "publicKey", buf2hex(publicKey));
}

export function loadCredential(contractId: string): { credentialId: Uint8Array; publicKey: string } | null {
  const prefix = `passkey:${contractId}:`;
  const credId = localStorage.getItem(prefix + "credentialId");
  const pubKey = localStorage.getItem(prefix + "publicKey");
  if (credId && pubKey) return { credentialId: base64url2buf(credId), publicKey: pubKey };
  return null;
}

export function saveAccount(contractId: string): void {
  const accounts: string[] = JSON.parse(localStorage.getItem("g2c:accounts") || "[]");
  if (!accounts.includes(contractId)) {
    accounts.push(contractId);
    localStorage.setItem("g2c:accounts", JSON.stringify(accounts));
  }
}

export function loadAccounts(): string[] {
  return JSON.parse(localStorage.getItem("g2c:accounts") || "[]");
}
