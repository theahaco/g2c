// Pure display model for a smart account's on-chain policy (its context rules).
//
// The Security page renders curated cards (recovery, session keys); this module
// backs the general Policy inspector, which shows EVERY context rule the way OZ
// stores it — scope, signers, attached policies, expiry — plus a plain-language
// sentence of what each rule permits. Everything here is pure so it unit-tests
// without RPC or a browser; the page supplies the fetched data.

import type { ChainRule, ChainSigner } from '@nidohq/passkey-sdk';

/** Truncate a long identifier (C-address, hex key) to `head…tail`. */
export function truncate(s: string, head = 6, tail = 6): string {
  if (s.length <= head + tail + 1) return s;
  return `${s.slice(0, head)}…${s.slice(-tail)}`;
}

/** Lowercase hex of raw key bytes. */
export function bytesToHex(bytes: Uint8Array): string {
  let out = '';
  for (const b of bytes) out += b.toString(16).padStart(2, '0');
  return out;
}

export interface SignerView {
  kind: 'passkey' | 'delegated';
  /** Short human label for the signer type. */
  label: string;
  /** Truncated identifier for display. */
  detail: string;
  /** Full identifier (address, or hex public key) for copy/verify. */
  full: string;
}

export function describeSigner(signer: ChainSigner): SignerView {
  if (signer.kind === 'delegated') {
    return {
      kind: 'delegated',
      label: 'Delegated key',
      detail: truncate(signer.address),
      full: signer.address,
    };
  }
  const hex = bytesToHex(signer.publicKey);
  return {
    kind: 'passkey',
    label: 'Passkey',
    detail: truncate(hex, 8, 8),
    full: hex,
  };
}

export interface PolicyView {
  address: string;
  short: string;
  /** Registry name if known, else "Custom policy". */
  label: string;
  known: boolean;
}

export function describePolicy(address: string, known: ReadonlyMap<string, string>): PolicyView {
  const label = known.get(address);
  return {
    address,
    short: truncate(address),
    label: label ?? 'Custom policy',
    known: label != null,
  };
}

export interface ScopeView {
  kind: ChainRule['contextType']['kind'];
  /** Short heading, e.g. "One contract". */
  label: string;
  /** Address (call-contract) or null. */
  detail: string | null;
}

export function describeScope(contextType: ChainRule['contextType']): ScopeView {
  switch (contextType.kind) {
    case 'default':
      return { kind: 'default', label: 'Any contract', detail: null };
    case 'call-contract':
      return { kind: 'call-contract', label: 'One contract', detail: contextType.contract };
    case 'create-contract':
      return { kind: 'create-contract', label: 'Contract creation', detail: null };
  }
}

export interface ExpiryView {
  state: 'none' | 'active' | 'expired';
  label: string;
}

/** Classify a rule's `valid_until` ledger against the current ledger.
 *  `currentLedger` null (unknown) keeps a set expiry as "active" rather than
 *  guessing — we never show "expired" without evidence. */
export function describeExpiry(validUntil: number | null, currentLedger: number | null): ExpiryView {
  if (validUntil == null) return { state: 'none', label: 'No expiry' };
  if (currentLedger != null && currentLedger > validUntil) {
    return { state: 'expired', label: `Expired at ledger ${validUntil}` };
  }
  return { state: 'active', label: `Expires at ledger ${validUntil}` };
}

export interface RuleView {
  ruleId: number;
  name: string;
  scope: ScopeView;
  signers: SignerView[];
  policies: PolicyView[];
  expiry: ExpiryView;
  /** Plain-language statement of what the rule allows. */
  permission: string;
  /** True when policies are attached — extra conditions gate the rule. */
  gated: boolean;
  /** Rule 0 is the account's own default authority. */
  isDefault: boolean;
}

export interface SummarizeOptions {
  /** address → registry label for attached policy contracts. */
  known?: ReadonlyMap<string, string>;
  /** Current ledger sequence, for expiry classification. */
  currentLedger?: number | null;
}

/** Build the display model for one context rule. */
export function summarizeRule(rule: ChainRule, opts: SummarizeOptions = {}): RuleView {
  const known = opts.known ?? new Map<string, string>();
  const currentLedger = opts.currentLedger ?? null;
  const scope = describeScope(rule.contextType);
  const signers = rule.signers.map(describeSigner);
  const policies = rule.policies.map((p) => describePolicy(p, known));
  const expiry = describeExpiry(rule.validUntil, currentLedger);
  const gated = policies.length > 0;
  const isDefault = rule.ruleId === 0 && scope.kind === 'default';

  return {
    ruleId: rule.ruleId,
    name: rule.name,
    scope,
    signers,
    policies,
    expiry,
    gated,
    isDefault,
    permission: permissionSentence({ scope, signers, policies, isDefault }),
  };
}

function whoCanSign(signers: SignerView[]): string {
  if (signers.length === 0) return 'No signer';
  if (signers.length === 1) return 'One key';
  return `Any of ${signers.length} keys`;
}

function scopePhrase(scope: ScopeView): string {
  switch (scope.kind) {
    case 'default':
      return 'call any function on any contract';
    case 'call-contract':
      return `call ${scope.detail ? truncate(scope.detail) : 'one contract'}`;
    case 'create-contract':
      return 'create contracts';
  }
}

function permissionSentence(args: {
  scope: ScopeView;
  signers: SignerView[];
  policies: PolicyView[];
  isDefault: boolean;
}): string {
  const base = `${whoCanSign(args.signers)} can ${scopePhrase(args.scope)}`;
  if (args.isDefault) {
    return `${base} — this is the account's primary authority.`;
  }
  if (args.policies.length > 0) {
    const names = args.policies.map((p) => p.label).join(', ');
    return `${base}, subject to: ${names}.`;
  }
  return `${base}.`;
}
