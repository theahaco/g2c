// Reachable-call analysis + monotone-attenuation check over a PolicyDoc — the
// TS mirror of perch's reachable_calls / is_narrowing (perch #19 PR4/PR8), used
// by the example to visualize "what can each key do" and to verify a narrowing.

import type { PolicyDoc } from './policy.js';

export type FnSet = { kind: 'any' } | { kind: 'only'; functions: string[] };

export interface ReachableScope {
  rule: string;
  scope: string; // 'self-admin' or a contract address
  functions: FnSet;
}

/** Every (rule, scope, function-set) the policy can authorize. */
export function reachableCalls(policy: PolicyDoc): ReachableScope[] {
  return policy.rules.map((r) => ({
    rule: r.name,
    scope: r.scope.type === 'self-admin' ? 'self-admin' : r.scope.address,
    functions: r.functions ? { kind: 'only', functions: r.functions } : { kind: 'any' },
  }));
}

function covers(parent: FnSet, child: FnSet): boolean {
  if (parent.kind === 'any') return true;
  if (child.kind === 'any') return false;
  return child.functions.every((f) => parent.functions.includes(f));
}

export type NarrowingResult = { ok: true } | { ok: false; rule: string; reason: string };

/** Whether `child` only narrows `parent`: every (scope, function) the child can
 *  authorize is one the parent already could. The fail-closed subset check that
 *  makes attenuation safe. */
export function isNarrowing(parent: PolicyDoc, child: PolicyDoc): NarrowingResult {
  const p = reachableCalls(parent);
  for (const cs of reachableCalls(child)) {
    const ps = p.find((x) => x.scope === cs.scope);
    if (!ps) return { ok: false, rule: cs.rule, reason: `scope ${cs.scope} is not in the parent` };
    if (!covers(ps.functions, cs.functions)) {
      return { ok: false, rule: cs.rule, reason: `functions widen beyond the parent on ${cs.scope}` };
    }
  }
  return { ok: true };
}
