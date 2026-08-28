// The perch PolicyDoc wire shape (kebab-case keys), plus small constructors.
// Mirrors @stellar-registry/perch's schema so `docHash` here equals on-chain
// perch. Types are the wire form directly — the testkit builds documents
// programmatically, so a full zod parse is not needed (perch validates on
// compile).

export type Scope = { type: 'self-admin' } | { type: 'contract'; address: string };

export type Principals =
  | { type: 'all'; signers: string[] }
  | { type: 'self-authenticating'; policy: string; 'install-param-hex': string; ack: string };

export type ArgPred =
  | { type: 'is-self' }
  | { type: 'address-eq'; address: string }
  | { type: 'string-in'; values: string[] }
  | { type: 'string-prefix'; prefix: string }
  | { type: 'u32-eq'; value: number };

export interface ArgConstraint {
  index: number;
  pred: ArgPred;
}

export interface CapConstraint {
  token?: string;
  /** decimal string (i128); a string, not a number — the canonical form carries
   *  only u32 numbers. */
  limit: string;
  'period-ledgers': number;
}

export interface SignerDecl {
  id: string;
  /** verifier contract C-address. */
  verifier: string;
  /** hex-encoded key material, opaque to perch. */
  key: string;
}

export interface Rule {
  name: string;
  scope: Scope;
  principals: Principals;
  functions?: string[];
  args?: ArgConstraint[];
  'not-after-ledger'?: number;
  cap?: CapConstraint;
}

export interface PolicyDoc {
  version: 1;
  network?: string;
  signers: SignerDecl[];
  rules: Rule[];
}

// -- argument predicate constructors (wire shape) --
export const isSelf = (): ArgPred => ({ type: 'is-self' });
export const addressEq = (address: string): ArgPred => ({ type: 'address-eq', address });
export const stringIn = (values: string[]): ArgPred => ({ type: 'string-in', values });
export const stringPrefix = (prefix: string): ArgPred => ({ type: 'string-prefix', prefix });
export const u32Eq = (value: number): ArgPred => ({ type: 'u32-eq', value });

/** Drop `undefined` optionals so the object matches the canonical form (which
 *  omits absent fields rather than emitting null). */
function compact<T extends Record<string, unknown>>(o: T): T {
  for (const k of Object.keys(o)) if (o[k] === undefined) delete o[k];
  return o;
}

export interface RuleInit {
  name: string;
  scope: Scope;
  signedBy: string[];
  functions?: string[];
  args?: ArgConstraint[];
  notAfterLedger?: number;
  cap?: CapConstraint;
}

/** Build one rule in wire shape from a friendly init. */
export function rule(init: RuleInit): Rule {
  return compact({
    name: init.name,
    scope: init.scope,
    principals: { type: 'all', signers: init.signedBy },
    functions: init.functions,
    args: init.args,
    'not-after-ledger': init.notAfterLedger,
    cap: init.cap,
  }) as Rule;
}

export const selfAdmin = (): Scope => ({ type: 'self-admin' });
export const contract = (address: string): Scope => ({ type: 'contract', address });
