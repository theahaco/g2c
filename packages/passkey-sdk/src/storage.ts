import { buf2hex, buf2base64url, base64url2buf } from "./encoding.js";

declare const localStorage: {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
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
  const accounts: string[] = JSON.parse(localStorage.getItem("nido:accounts") || "[]");
  if (!accounts.includes(contractId)) {
    accounts.push(contractId);
    localStorage.setItem("nido:accounts", JSON.stringify(accounts));
  }
}

export function loadAccounts(): string[] {
  return JSON.parse(localStorage.getItem("nido:accounts") || "[]");
}

export interface PendingAccount {
  contractId: string;
  setupKey: string;
  /** @deprecated old onboarding stored a temporary G secret here. */
  secretKey?: string;
}

export function savePendingAccount(contractId: string, setupKey: string): void {
  const pending: PendingAccount[] = JSON.parse(localStorage.getItem("nido:pending") || "[]");
  const existing = pending.find((p) => p.contractId === contractId);
  if (existing) {
    existing.setupKey = setupKey;
    delete existing.secretKey;
    localStorage.setItem("nido:pending", JSON.stringify(pending));
  } else {
    pending.push({ contractId, setupKey });
    localStorage.setItem("nido:pending", JSON.stringify(pending));
  }
}

export function loadPendingAccounts(): PendingAccount[] {
  const pending: PendingAccount[] = JSON.parse(localStorage.getItem("nido:pending") || "[]");
  return pending.map((p) => ({ ...p, setupKey: p.setupKey ?? p.secretKey ?? "" }));
}

export function removePendingAccount(contractId: string): void {
  const pending: PendingAccount[] = JSON.parse(localStorage.getItem("nido:pending") || "[]");
  const filtered = pending.filter((p) => p.contractId !== contractId);
  localStorage.setItem("nido:pending", JSON.stringify(filtered));
}

export function activateAccount(contractId: string): void {
  removePendingAccount(contractId);
  saveAccount(contractId);
}

export function saveAccountName(contractId: string, name: string): void {
  localStorage.setItem(`nido:names:${contractId}`, name);
}

export function loadAccountName(contractId: string): string | null {
  return localStorage.getItem(`nido:names:${contractId}`);
}

// --- Policy storage (Tier C/D from the spec) -------------------------------
//
// Friend nicknames and block labels are pure display overlay; session-key
// material is passkey-backed (credentialId + public key only — no private key
// on disk; see SessionKeyMaterial). Keys are namespaced by smart-account address.

const friendsKey = (account: string) => `nido.${account}.friends`;
const sessionKey = (account: string, target: string) =>
  `nido.${account}.session-key.${target}`;
const labelsKey = (account: string) => `nido.${account}.block-labels`;

export function saveFriendNickname(
  account: string,
  address: string,
  nickname: string,
): void {
  const existing = loadFriendNicknames(account);
  existing[address] = nickname;
  localStorage.setItem(friendsKey(account), JSON.stringify(existing));
}

export function loadFriendNicknames(account: string): Record<string, string> {
  const raw = localStorage.getItem(friendsKey(account));
  return raw ? JSON.parse(raw) : {};
}

/**
 * Material persisted at the dApp's origin for a delegated session key.
 *
 *  - `credentialId` is the base64url WebAuthn credential id created at
 *    delegation time (`createSessionPasskey`).
 *  - `publicKey` is a hex-encoded 65-byte SEC1 uncompressed P-256 point.
 *    Stored alongside the credentialId because the dApp needs it on each
 *    sign to construct the `External(verifier, pubkey)` signer; the
 *    credential id alone can't yield the pubkey.
 *
 * No private key is stored: sessions are passkey-backed (the private key stays
 * in the authenticator). Old synthetic-flow entries may still carry a plaintext
 * `privateKey` — nothing signs with it any more, so `loadSessionKeyMaterial`
 * PURGES it from storage on load rather than returning it.
 */
export interface SessionKeyMaterial {
  credentialId: string;
  publicKey: string;        // hex, 65 bytes
  label?: string;
}

export function saveSessionKeyMaterial(
  account: string,
  target: string,
  material: SessionKeyMaterial,
): void {
  const serialized: Record<string, unknown> = {
    credentialId: material.credentialId,
    publicKey: material.publicKey,
    label: material.label,
  };
  // Deliberately NO privateKey: a session private key must never touch disk.
  localStorage.setItem(sessionKey(account, target), JSON.stringify(serialized));
}

export function loadSessionKeyMaterial(
  account: string,
  target: string,
): SessionKeyMaterial | null {
  const key = sessionKey(account, target);
  const raw = localStorage.getItem(key);
  if (!raw) return null;
  const o = JSON.parse(raw);
  // Purge a deprecated synthetic-flow privateKey: nothing signs with a stored
  // session key any more, so persisted private bytes are dead + sensitive —
  // drop them from storage on first load and never hand them back.
  if (o.privateKey !== undefined) {
    delete o.privateKey;
    localStorage.setItem(key, JSON.stringify(o));
  }
  return {
    credentialId: o.credentialId,
    publicKey: o.publicKey,
    label: o.label,
  };
}

export function forgetSessionKeyMaterial(account: string, target: string): void {
  localStorage.removeItem(sessionKey(account, target));
}

export function saveBlockLabel(account: string, ruleId: number, label: string): void {
  const existing = loadBlockLabels(account);
  existing[ruleId] = label;
  localStorage.setItem(labelsKey(account), JSON.stringify(existing));
}

export function loadBlockLabels(account: string): Record<number, string> {
  const raw = localStorage.getItem(labelsKey(account));
  return raw ? JSON.parse(raw) : {};
}
