import { describe, it, expect } from 'vitest';
import { StrKey } from '@stellar/stellar-sdk';
import { localSigner } from './signer.js';
import { verifySignature, VERIFIERS } from './verifiers.js';
import { computeAuthDigest } from './auth.js';
import { createLocalAccount } from './account.js';
import { simulateCheckAuth } from './checkauth.js';
import { rule, contract, isSelf } from './perch/policy.js';
import { reachableCalls, isNarrowing } from './perch/analysis.js';

const REGISTRY = 'CCA7QAA6OD6LQJTU2MKN6EAS5I52QIFPAYMMQYSU7KHWTGT26AN6N2AL';
const ALGS = ['ed25519', 'secp256r1', 'ml-dsa-65'] as const;

describe('local signers — every verifier round-trips', () => {
  for (const algorithm of ALGS) {
    it(`${algorithm}: a fresh local key signs and verifies its own auth digest`, () => {
      const s = localSigner({ id: 'k', algorithm });
      const digest = computeAuthDigest(new Uint8Array(32).fill(3), [0]);
      const sig = s.signAuth(digest);
      expect(verifySignature(algorithm, digest, s.publicKey, sig)).toBe(true);
      // a different digest must not verify
      const other = computeAuthDigest(new Uint8Array(32).fill(9), [0]);
      expect(verifySignature(algorithm, other, s.publicKey, sig)).toBe(false);
      expect(s.verifier).toBe(VERIFIERS[algorithm].address);
    });
  }
});

describe('createLocalAccount', () => {
  it('derives a valid contract C-address and a real perch doc_hash', () => {
    const admin = localSigner({ id: 'admin', algorithm: 'secp256r1' });
    const acct = createLocalAccount({ signers: [admin] });
    expect(StrKey.isValidContract(acct.address)).toBe(true);
    expect(acct.docHash).toMatch(/^[0-9a-f]{64}$/);
    // deterministic: same key ⇒ same address + hash
    const again = createLocalAccount({ signers: [admin] });
    expect(again.address).toBe(acct.address);
    expect(again.docHash).toBe(acct.docHash);
  });

  it('supports a multi-verifier account (secp256r1 + ed25519 + ML-DSA)', () => {
    const signers = ALGS.map((algorithm, i) => localSigner({ id: `s${i}`, algorithm }));
    const acct = createLocalAccount({ signers });
    expect(acct.policy.signers).toHaveLength(3);
    expect(new Set(acct.policy.signers.map((s) => s.verifier)).size).toBe(3);
  });
});

describe('simulateCheckAuth — the ci-publish policy', () => {
  const admin = localSigner({ id: 'admin', algorithm: 'secp256r1' });
  const ci = localSigner({ id: 'ci', algorithm: 'ed25519' });
  const acct = createLocalAccount({
    signers: [admin, ci],
    rules: [
      rule({ name: 'admin-root', scope: { type: 'self-admin' }, signedBy: ['admin'] }),
      rule({
        name: 'ci-publish',
        scope: contract(REGISTRY),
        signedBy: ['ci'],
        functions: ['publish', 'publish_hash'],
        args: [{ index: 1, pred: isSelf() }],
        notAfterLedger: 55_000_000,
      }),
    ],
  });
  const ctx = (fn: string, author: string, ledger = 54_000_000) => ({
    contract: REGISTRY,
    fn,
    args: [{ type: 'u32' as const, value: 0 }, { type: 'address' as const, value: author }],
    ledger,
  });

  it('allows the ci key to publish as self', () => {
    expect(simulateCheckAuth(acct, ctx('publish_hash', acct.address), ['ci']).verdict).toBe('allow');
  });
  it('denies a function outside the allowlist', () => {
    expect(simulateCheckAuth(acct, ctx('set_admin', acct.address), ['ci']).verdict).toBe('deny');
  });
  it('denies when the author is not self', () => {
    const other = createLocalAccount({ signers: [localSigner({ id: 'x', algorithm: 'ed25519' })] }).address;
    expect(simulateCheckAuth(acct, ctx('publish', other), ['ci']).verdict).toBe('deny');
  });
  it('denies with no signature (the zero-signature attack)', () => {
    expect(simulateCheckAuth(acct, ctx('publish', acct.address), []).verdict).toBe('deny');
  });
  it('denies an expired rule', () => {
    expect(simulateCheckAuth(acct, ctx('publish', acct.address, 55_000_001), ['ci']).verdict).toBe('deny');
  });
});

describe('simulateCheckAuth — tries every matching rule', () => {
  const admin = localSigner({ id: 'admin', algorithm: 'secp256r1' });
  const pq = localSigner({ id: 'pq', algorithm: 'ml-dsa-65' });
  const acct = createLocalAccount({
    signers: [admin, pq],
    rules: [
      rule({ name: 'admin-root', scope: { type: 'self-admin' }, signedBy: ['admin'] }),
      rule({ name: 'pq-admin', scope: { type: 'self-admin' }, signedBy: ['pq'] }),
    ],
  });

  it('authorizes a self-admin call via a non-first rule (the ML-DSA signer)', () => {
    // set_admin on self-admin, signed only by pq → admin-root denies (missing
    // admin) but pq-admin authorizes. Must not stop at the first matching rule.
    const res = simulateCheckAuth(acct, { contract: acct.address, fn: 'set_admin' }, ['pq']);
    expect(res.verdict).toBe('allow');
    expect(res.matchedRule).toBe('pq-admin');
  });

  it('denies when no matching rule is satisfied', () => {
    const res = simulateCheckAuth(acct, { contract: acct.address, fn: 'set_admin' }, []);
    expect(res.verdict).toBe('deny');
  });
});

describe('perch analysis — reachable + attenuation', () => {
  const acct = createLocalAccount({
    signers: [localSigner({ id: 'ci', algorithm: 'ed25519' })],
    rules: [
      rule({ name: 'ci-publish', scope: contract(REGISTRY), signedBy: ['ci'], functions: ['publish', 'publish_hash'] }),
    ],
  });

  it('reports reachable calls', () => {
    const r = reachableCalls(acct.policy);
    expect(r[0]).toMatchObject({ rule: 'ci-publish', scope: REGISTRY });
  });

  it('accepts a narrowing and rejects a widening', () => {
    const narrowed = structuredClone(acct.policy);
    narrowed.rules[0]!.functions = ['publish'];
    expect(isNarrowing(acct.policy, narrowed).ok).toBe(true);

    const widened = structuredClone(acct.policy);
    widened.rules[0]!.functions = ['publish', 'publish_hash', 'set_admin'];
    expect(isNarrowing(acct.policy, widened).ok).toBe(false);
  });
});
