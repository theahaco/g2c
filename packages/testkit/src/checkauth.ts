// Simulate a Nido account's __check_auth locally and return a Kleene verdict.
//
// Mirrors OZ `do_check_auth` (context-rule match → signer authentication over
// the auth digest → policy enforcement) with the policy layer being perch: a
// rule's function allowlist, argument predicates, expiry, and signer floor are
// evaluated here (perch isn't on-chain yet, so the simulator IS the interpreter).
// On-chain is boolean (allow / trap); `abstain` is a testkit-side convenience
// meaning "no rule even applies to this call".

import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { computeAuthDigest } from './auth.js';
import { verifySignature } from './verifiers.js';
import type { LocalAccount } from './account.js';
import type { ArgPred, Rule } from './perch/policy.js';

export type SimArg =
  | { type: 'address'; value: string }
  | { type: 'u32'; value: number }
  | { type: 'string'; value: string }
  | { type: 'symbol'; value: string }
  | { type: 'i128'; value: bigint | string }
  | { type: 'bytes'; value: Uint8Array };

export interface SimContext {
  /** Target contract for a CallContract rule; omit for a self-admin call. */
  contract?: string;
  fn: string;
  args?: SimArg[];
  /** Current ledger sequence (for expiry). Default 0. */
  ledger?: number;
}

export type Verdict = 'allow' | 'deny' | 'abstain';

export interface SimResult {
  verdict: Verdict;
  /** hex of the digest each signer signed. */
  authDigest: string;
  matchedRule?: string;
  reasons: string[];
  signerChecks: { id: string; verifier: string; ok: boolean }[];
}

function stableContext(ctx: SimContext): string {
  const args = (ctx.args ?? []).map((a) =>
    a.type === 'bytes'
      ? { type: a.type, value: bytesToHex(a.value) }
      : a.type === 'i128'
        ? { type: a.type, value: String(a.value) }
        : a,
  );
  return JSON.stringify({ contract: ctx.contract ?? null, fn: ctx.fn, args, ledger: ctx.ledger ?? 0 });
}

function scopeMatches(rule: Rule, account: LocalAccount, ctx: SimContext): boolean {
  if (rule.scope.type === 'self-admin') return ctx.contract === undefined || ctx.contract === account.address;
  return ctx.contract === rule.scope.address;
}

function argSatisfies(pred: ArgPred, arg: SimArg | undefined, account: LocalAccount): boolean {
  if (!arg) return false;
  switch (pred.type) {
    case 'is-self':
      return arg.type === 'address' && arg.value === account.address;
    case 'address-eq':
      return arg.type === 'address' && arg.value === pred.address;
    case 'u32-eq':
      return arg.type === 'u32' && arg.value === pred.value;
    case 'string-in':
      return (arg.type === 'string' || arg.type === 'symbol') && pred.values.includes(arg.value);
    case 'string-prefix':
      return (arg.type === 'string' || arg.type === 'symbol') && arg.value.startsWith(pred.prefix);
  }
}

/** Evaluate one rule (at index `idx`) against the call: digest → authenticate
 *  signers → expiry / function / args / signer-floor. */
function evalRule(
  account: LocalAccount,
  ctx: SimContext,
  ledger: number,
  rule: Rule,
  idx: number,
  signedBy: string[],
): SimResult {
  const reasons: string[] = [];
  const payload = sha256(new TextEncoder().encode(stableContext(ctx)));
  const digest = computeAuthDigest(payload, [idx]);
  const signerChecks = signedBy.map((id) => {
    const s = account.signers.find((x) => x.id === id);
    if (!s) return { id, verifier: '(unknown)', ok: false };
    return { id, verifier: s.verifier, ok: verifySignature(s.algorithm, digest, s.publicKey, s.signAuth(digest)) };
  });
  const authenticated = new Set(signerChecks.filter((c) => c.ok).map((c) => c.id));
  const base: Omit<SimResult, 'verdict'> = {
    authDigest: bytesToHex(digest),
    matchedRule: rule.name,
    reasons,
    signerChecks,
  };
  const deny = (why: string): SimResult => {
    reasons.push(why);
    return { verdict: 'deny', ...base };
  };

  // Expiry (perch "dead at or after").
  const notAfter = rule['not-after-ledger'];
  if (notAfter !== undefined && ledger >= notAfter) return deny(`rule expired (ledger ${ledger} ≥ ${notAfter})`);
  // Function allowlist.
  if (rule.functions && !rule.functions.includes(ctx.fn)) {
    return deny(`function ${ctx.fn}() not in [${rule.functions.join(', ')}]`);
  }
  // Argument predicates.
  for (const c of rule.args ?? []) {
    if (!argSatisfies(c.pred, ctx.args?.[c.index], account)) return deny(`arg[${c.index}] fails ${c.pred.type}`);
  }
  // Signer sufficiency: perch injects MinSigners(n) = every referenced signer.
  if (rule.principals.type === 'all') {
    const missing = rule.principals.signers.filter((id) => !authenticated.has(id));
    if (missing.length) return deny(`missing signature from [${missing.join(', ')}]`);
  }
  // Cumulative cap is a stateful sibling policy — surface it, not per-call.
  if (rule.cap) {
    reasons.push(`cap ≤ ${rule.cap.limit} / ${rule.cap['period-ledgers']} ledgers applies (stateful; not checked per-call)`);
  }
  reasons.push('authorized');
  return { verdict: 'allow', ...base };
}

export function simulateCheckAuth(account: LocalAccount, ctx: SimContext, signedBy: string[]): SimResult {
  const ledger = ctx.ledger ?? 0;

  // Every rule this call could fall under (OZ lets the caller nominate a rule
  // via context_rule_ids; the sim tries them all and authorizes if any rule
  // does — matching "can these signers authorize this call?").
  const matching: Array<[Rule, number]> = [];
  account.policy.rules.forEach((r, i) => {
    if (scopeMatches(r, account, ctx)) matching.push([r, i]);
  });
  if (matching.length === 0) {
    return { verdict: 'abstain', authDigest: '', reasons: ['no rule applies to this call'], signerChecks: [] };
  }

  let firstDeny: SimResult | null = null;
  for (const [rule, idx] of matching) {
    const res = evalRule(account, ctx, ledger, rule, idx, signedBy);
    if (res.verdict === 'allow') return res;
    if (!firstDeny) firstDeny = res;
  }
  return firstDeny as SimResult;
}
