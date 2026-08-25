import { describe, it, expect } from 'vitest';
import type { ChainRule } from '@nidohq/passkey-sdk';
import {
  truncate,
  bytesToHex,
  describeSigner,
  describePolicy,
  describeScope,
  describeExpiry,
  summarizeRule,
} from './policyView';

const PASSKEY_PUB = new Uint8Array([0x04, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22]);
const ADDR_C = 'CCA7QAA6OD6LQJTU2MKN6EAS5I52QIFPAYMMQYSU7KHWTGT26AN6N2AL';
const ADDR_G = 'GCY63ZN3C232UXXWENGF5I3PUHSYLR45MKCXS53MI3NSCWBFERWKHEPH';
const POLICY_ADDR = 'CCYWLNWRYDCAEM2A2EMTWAMIGWESQGUJNDTRRFIOS5CBPRO54EZ27ABG';

describe('truncate', () => {
  it('shortens long identifiers and leaves short ones alone', () => {
    expect(truncate(ADDR_C)).toBe('CCA7QA…N6N2AL');
    expect(truncate('short')).toBe('short');
  });
});

describe('bytesToHex', () => {
  it('lowercase, zero-padded', () => {
    expect(bytesToHex(new Uint8Array([0x00, 0x0f, 0xff]))).toBe('000fff');
  });
});

describe('describeSigner', () => {
  it('labels a delegated signer with its address', () => {
    expect(describeSigner({ kind: 'delegated', address: ADDR_G })).toEqual({
      kind: 'delegated',
      label: 'Delegated key',
      detail: truncate(ADDR_G),
      full: ADDR_G,
    });
  });

  it('labels an external signer as a passkey with its hex key', () => {
    const v = describeSigner({ kind: 'external', verifier: POLICY_ADDR, publicKey: PASSKEY_PUB });
    expect(v.kind).toBe('passkey');
    expect(v.label).toBe('Passkey');
    expect(v.full).toBe(bytesToHex(PASSKEY_PUB));
  });
});

describe('describePolicy', () => {
  const known = new Map([[POLICY_ADDR, 'Spending limit']]);
  it('uses the registry label for a known policy', () => {
    expect(describePolicy(POLICY_ADDR, known)).toMatchObject({ label: 'Spending limit', known: true });
  });
  it('falls back to "Custom policy" for an unknown address', () => {
    expect(describePolicy(ADDR_C, known)).toMatchObject({ label: 'Custom policy', known: false });
  });
});

describe('describeScope', () => {
  it('default → any contract', () => {
    expect(describeScope({ kind: 'default' })).toEqual({ kind: 'default', label: 'Any contract', detail: null });
  });
  it('call-contract carries the target address', () => {
    expect(describeScope({ kind: 'call-contract', contract: ADDR_C })).toEqual({
      kind: 'call-contract',
      label: 'One contract',
      detail: ADDR_C,
    });
  });
  it('create-contract → contract creation', () => {
    expect(describeScope({ kind: 'create-contract', wasm: new Uint8Array() })).toEqual({
      kind: 'create-contract',
      label: 'Contract creation',
      detail: null,
    });
  });
});

describe('describeExpiry', () => {
  it('no valid_until → no expiry', () => {
    expect(describeExpiry(null, 100)).toEqual({ state: 'none', label: 'No expiry' });
  });
  it('current ledger past valid_until → expired', () => {
    expect(describeExpiry(50, 100)).toEqual({ state: 'expired', label: 'Expired at ledger 50' });
  });
  it('current ledger before valid_until → active', () => {
    expect(describeExpiry(200, 100).state).toBe('active');
  });
  it('unknown current ledger keeps a set expiry active, never guesses expired', () => {
    expect(describeExpiry(50, null).state).toBe('active');
  });
});

function rule(partial: Partial<ChainRule>): ChainRule {
  return {
    ruleId: 1,
    contextType: { kind: 'default' },
    name: 'rule',
    signers: [],
    policies: [],
    validUntil: null,
    ...partial,
  };
}

describe('summarizeRule', () => {
  it('marks rule 0 default as the primary authority', () => {
    const v = summarizeRule(rule({ ruleId: 0, name: 'default', contextType: { kind: 'default' } }));
    expect(v.isDefault).toBe(true);
    expect(v.permission).toContain('primary authority');
  });

  it('writes a scoped-call permission sentence with signer count', () => {
    const v = summarizeRule(
      rule({
        ruleId: 2,
        name: 'ci-publish',
        contextType: { kind: 'call-contract', contract: ADDR_C },
        signers: [
          { kind: 'external', verifier: POLICY_ADDR, publicKey: PASSKEY_PUB },
          { kind: 'delegated', address: ADDR_G },
        ],
      }),
    );
    expect(v.permission).toContain('Any of 2 keys');
    expect(v.permission).toContain(truncate(ADDR_C));
    expect(v.gated).toBe(false);
  });

  it('flags a gated rule and names its attached policies', () => {
    const v = summarizeRule(
      rule({
        contextType: { kind: 'call-contract', contract: ADDR_C },
        signers: [{ kind: 'delegated', address: ADDR_G }],
        policies: [POLICY_ADDR],
      }),
      { known: new Map([[POLICY_ADDR, 'Spending limit']]) },
    );
    expect(v.gated).toBe(true);
    expect(v.policies[0].label).toBe('Spending limit');
    expect(v.permission).toContain('subject to: Spending limit');
  });

  it('classifies expiry against the current ledger', () => {
    const v = summarizeRule(rule({ validUntil: 10 }), { currentLedger: 99 });
    expect(v.expiry.state).toBe('expired');
  });
});
