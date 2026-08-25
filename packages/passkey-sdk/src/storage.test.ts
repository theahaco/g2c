import { describe, it, expect, beforeEach } from 'vitest';
import {
  saveFriendNickname, loadFriendNicknames,
  saveSessionKeyMaterial, loadSessionKeyMaterial, forgetSessionKeyMaterial,
  saveBlockLabel, loadBlockLabels,
  savePendingAccount, loadPendingAccounts,
} from './storage.js';

const ACC = 'C' + 'A'.repeat(55); // Just an identifier here — never validated.

class MemStore {
  private m = new Map<string, string>();
  getItem(k: string) { return this.m.get(k) ?? null; }
  setItem(k: string, v: string) { this.m.set(k, v); }
  removeItem(k: string) { this.m.delete(k); }
  clear() { this.m.clear(); }
  key(_i: number) { return null; }
  get length() { return this.m.size; }
}

describe('policy storage', () => {
  beforeEach(() => { (globalThis as any).localStorage = new MemStore(); });

  it('round-trips friend nicknames', () => {
    const addr = 'C' + 'B'.repeat(55);
    saveFriendNickname(ACC, addr, "Alice's iPhone");
    expect(loadFriendNicknames(ACC)).toEqual({ [addr]: "Alice's iPhone" });
  });

  it('round-trips session-key material (no private key persisted)', () => {
    const target = 'C' + 'C'.repeat(55);
    saveSessionKeyMaterial(ACC, target, {
      credentialId: 'cred-1',
      publicKey: '04ab',
      label: 'status-message',
    });
    // Nothing under the session key on disk carries a private key.
    expect(localStorage.getItem(`nido.${ACC}.session-key.${target}`)).not.toContain('privateKey');
    const got = loadSessionKeyMaterial(ACC, target);
    expect(got).toEqual({ credentialId: 'cred-1', publicKey: '04ab', label: 'status-message' });
    forgetSessionKeyMaterial(ACC, target);
    expect(loadSessionKeyMaterial(ACC, target)).toBeNull();
  });

  it('purges a deprecated synthetic privateKey from a stale session entry on load', () => {
    const target = 'C' + 'D'.repeat(55);
    const key = `nido.${ACC}.session-key.${target}`;
    // A pre-existing entry from the old synthetic flow, with a plaintext key.
    localStorage.setItem(key, JSON.stringify({
      credentialId: 'cred-2', publicKey: '04cd', label: 'legacy', privateKey: [1, 2, 3],
    }));
    const got = loadSessionKeyMaterial(ACC, target);
    // The load never hands back the private key...
    expect(got).toEqual({ credentialId: 'cred-2', publicKey: '04cd', label: 'legacy' });
    // ...and scrubs it from storage so it can't be read again.
    expect(localStorage.getItem(key)).not.toContain('privateKey');
  });

  it('round-trips block labels', () => {
    saveBlockLabel(ACC, 7, 'Recovery');
    expect(loadBlockLabels(ACC)).toEqual({ 7: 'Recovery' });
  });

  it('updates pending setup keys and migrates old secret-key rows', () => {
    localStorage.setItem("nido:pending", JSON.stringify([{ contractId: ACC, secretKey: "SOLD" }]));
    expect(loadPendingAccounts()).toEqual([{ contractId: ACC, secretKey: "SOLD", setupKey: "SOLD" }]);

    savePendingAccount(ACC, "salt-1");
    expect(loadPendingAccounts()).toEqual([{ contractId: ACC, setupKey: "salt-1" }]);
  });
});
