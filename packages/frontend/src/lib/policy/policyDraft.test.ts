import { describe, it, expect } from 'vitest';
import {
  validateDraft,
  buildContextTypeArg,
  buildSignerArgs,
  buildAddContextRuleArgs,
  spendingLimitPlan,
  isContractAddress,
  isStellarAddress,
  isHex,
  type RuleDraft,
} from './policyDraft';

const C_ADDR = 'CCA7QAA6OD6LQJTU2MKN6EAS5I52QIFPAYMMQYSU7KHWTGT26AN6N2AL';
const VERIFIER = 'CCYWLNWRYDCAEM2A2EMTWAMIGWESQGUJNDTRRFIOS5CBPRO54EZ27ABG';
const G_ADDR = 'GCY63ZN3C232UXXWENGF5I3PUHSYLR45MKCXS53MI3NSCWBFERWKHEPH';

function base(overrides: Partial<RuleDraft> = {}): RuleDraft {
  return {
    name: 'ci-publish',
    scope: { kind: 'call-contract', contract: C_ADDR },
    signers: [{ kind: 'delegated', address: G_ADDR }],
    ...overrides,
  };
}

describe('address/hex guards', () => {
  it('accepts a valid C-address and rejects junk', () => {
    expect(isContractAddress(C_ADDR)).toBe(true);
    expect(isContractAddress(G_ADDR)).toBe(false);
    expect(isContractAddress('nope')).toBe(false);
  });
  it('isStellarAddress accepts C and G', () => {
    expect(isStellarAddress(C_ADDR)).toBe(true);
    expect(isStellarAddress(G_ADDR)).toBe(true);
  });
  it('isHex requires even-length hex', () => {
    expect(isHex('04ab')).toBe(true);
    expect(isHex('abc')).toBe(false);
    expect(isHex('xy')).toBe(false);
  });
});

describe('validateDraft', () => {
  it('accepts a well-formed delegated-signer rule', () => {
    expect(validateDraft(base())).toEqual({ ok: true, errors: [] });
  });

  it('requires a name', () => {
    const r = validateDraft(base({ name: '   ' }));
    expect(r.ok).toBe(false);
    expect(r.errors).toContain('Give the rule a name.');
  });

  it('rejects an over-long name', () => {
    const r = validateDraft(base({ name: 'x'.repeat(40) }));
    expect(r.ok).toBe(false);
    expect(r.errors.some((e) => e.includes('at most'))).toBe(true);
  });

  it('requires a valid contract for call-contract scope', () => {
    const r = validateDraft(base({ scope: { kind: 'call-contract', contract: 'bad' } }));
    expect(r.errors.some((e) => e.includes('valid C-address'))).toBe(true);
  });

  it('allows default scope with no contract', () => {
    expect(validateDraft(base({ scope: { kind: 'default' } })).ok).toBe(true);
  });

  it('requires at least one signer', () => {
    const r = validateDraft(base({ signers: [] }));
    expect(r.errors).toContain('Add at least one signer.');
  });

  it('validates a passkey signer verifier + hex key', () => {
    const good = validateDraft(
      base({ signers: [{ kind: 'passkey', verifier: VERIFIER, publicKeyHex: '04aabb' }] }),
    );
    expect(good.ok).toBe(true);
    const bad = validateDraft(
      base({ signers: [{ kind: 'passkey', verifier: 'nope', publicKeyHex: 'zz' }] }),
    );
    expect(bad.ok).toBe(false);
    expect(bad.errors.length).toBe(2);
  });

  it('rejects a non-positive spending limit', () => {
    const r = validateDraft(base({ spendingLimit: { stroops: '0', periodLedgers: 100 } }));
    expect(r.errors).toContain('Spending limit must be a positive amount.');
  });

  it('rejects a non-positive expiry ledger', () => {
    const r = validateDraft(base({ validUntilLedger: -5 }));
    expect(r.errors.some((e) => e.includes('Expiry ledger'))).toBe(true);
  });
});

describe('argument construction', () => {
  it('maps default scope to the Default tag', () => {
    expect(buildContextTypeArg(base({ scope: { kind: 'default' } }))).toEqual({
      tag: 'Default',
      values: [],
    });
  });

  it('maps call-contract scope to the CallContract tag with the address', () => {
    expect(buildContextTypeArg(base())).toEqual({ tag: 'CallContract', values: [C_ADDR] });
  });

  it('maps signer kinds to External/Delegated tags', () => {
    const args = buildSignerArgs(
      base({
        signers: [
          { kind: 'delegated', address: G_ADDR },
          { kind: 'passkey', verifier: VERIFIER, publicKeyHex: '04aabb' },
        ],
      }),
    );
    expect(args[0]).toEqual({ tag: 'Delegated', values: [G_ADDR] });
    expect(args[1]).toEqual({ tag: 'External', values: [VERIFIER, '04aabb'] });
  });

  it('spendingLimitPlan parses stroops to bigint or returns null', () => {
    expect(spendingLimitPlan(base())).toBeNull();
    expect(spendingLimitPlan(base({ spendingLimit: { stroops: '1000', periodLedgers: 17280 } }))).toEqual({
      stroops: 1000n,
      periodLedgers: 17280,
    });
  });

  it('buildAddContextRuleArgs assembles the full binding argument', () => {
    const args = buildAddContextRuleArgs(base({ validUntilLedger: 500 }));
    expect(args).toEqual({
      context_type: { tag: 'CallContract', values: [C_ADDR] },
      name: 'ci-publish',
      valid_until: 500,
      signers: [{ tag: 'Delegated', values: [G_ADDR] }],
    });
  });
});
