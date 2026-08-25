// Pure validation + argument construction for the policy builder.
//
// The builder UI collects a RuleDraft; this module validates it and lowers it to
// the exact `add_context_rule` argument shape the smart-account binding expects
// (minus the policies map, which needs address resolution + ScVal encoding the
// page does). Kept pure so the rules that decide what's a valid policy are
// unit-tested without a wallet or RPC.

/** Client-side mirror of OZ's on-chain context-rule name limit. The chain
 *  rejects longer names; catching it here gives a real error instead of a
 *  failed simulation. */
export const MAX_RULE_NAME_LEN = 32;
/** OZ verifier key_data cap (bytes). */
export const MAX_SIGNER_KEY_BYTES = 256;

export type ScopeKind = 'default' | 'call-contract';

export interface DraftSigner {
  kind: 'passkey' | 'delegated';
  /** delegated: the C- or G-address that authorizes via its own require_auth. */
  address?: string;
  /** passkey: the verifier contract that checks the signature. */
  verifier?: string;
  /** passkey: hex-encoded public key the verifier understands. */
  publicKeyHex?: string;
}

export interface SpendingLimitDraft {
  /** Limit in stroops, as a decimal string (bigint-parseable). */
  stroops: string;
  /** Rolling window length in ledgers. */
  periodLedgers: number;
}

export interface RuleDraft {
  name: string;
  scope: { kind: ScopeKind; contract?: string };
  signers: DraftSigner[];
  spendingLimit?: SpendingLimitDraft | null;
  /** Expiry ledger sequence (not a timestamp), or null for no expiry. */
  validUntilLedger?: number | null;
}

/** Shape check for a Soroban contract address (C-strkey). Checksum is verified
 *  on-chain; this catches obvious typos before a doomed simulation. */
export function isContractAddress(s: string): boolean {
  return /^C[A-Z2-7]{55}$/.test(s);
}

/** Shape check for any Stellar address usable as a delegated signer (C or G). */
export function isStellarAddress(s: string): boolean {
  return /^[CG][A-Z2-7]{55}$/.test(s);
}

export function isHex(s: string): boolean {
  return s.length > 0 && s.length % 2 === 0 && /^[0-9a-fA-F]+$/.test(s);
}

export interface ValidationResult {
  ok: boolean;
  errors: string[];
}

export function validateDraft(draft: RuleDraft): ValidationResult {
  const errors: string[] = [];

  const name = draft.name?.trim() ?? '';
  if (name.length === 0) errors.push('Give the rule a name.');
  else if (new TextEncoder().encode(name).length > MAX_RULE_NAME_LEN) {
    errors.push(`Name must be at most ${MAX_RULE_NAME_LEN} bytes.`);
  }

  if (draft.scope.kind === 'call-contract') {
    const c = draft.scope.contract?.trim() ?? '';
    if (!c) errors.push('Choose the contract this rule applies to.');
    else if (!isContractAddress(c)) errors.push('Contract address is not a valid C-address.');
  }

  if (!draft.signers || draft.signers.length === 0) {
    errors.push('Add at least one signer.');
  } else {
    draft.signers.forEach((s, i) => {
      const n = i + 1;
      if (s.kind === 'delegated') {
        if (!s.address || !isStellarAddress(s.address.trim())) {
          errors.push(`Signer ${n}: delegated address is not a valid C- or G-address.`);
        }
      } else {
        if (!s.verifier || !isContractAddress(s.verifier.trim())) {
          errors.push(`Signer ${n}: verifier is not a valid C-address.`);
        }
        const hex = s.publicKeyHex?.trim() ?? '';
        if (!isHex(hex)) errors.push(`Signer ${n}: public key is not valid hex.`);
        else if (hex.length / 2 > MAX_SIGNER_KEY_BYTES) {
          errors.push(`Signer ${n}: public key exceeds ${MAX_SIGNER_KEY_BYTES} bytes.`);
        }
      }
    });
  }

  if (draft.spendingLimit) {
    let stroops: bigint | null = null;
    try {
      stroops = BigInt(draft.spendingLimit.stroops);
    } catch {
      stroops = null;
    }
    if (stroops == null || stroops <= 0n) errors.push('Spending limit must be a positive amount.');
    if (!Number.isInteger(draft.spendingLimit.periodLedgers) || draft.spendingLimit.periodLedgers <= 0) {
      errors.push('Spending-limit window must be a positive number of ledgers.');
    }
  }

  if (draft.validUntilLedger != null) {
    if (!Number.isInteger(draft.validUntilLedger) || draft.validUntilLedger <= 0) {
      errors.push('Expiry ledger must be a positive integer.');
    }
  }

  return { ok: errors.length === 0, errors };
}

// --- Argument construction (only call after validateDraft passes) ----------

export type ContextTypeArg =
  | { tag: 'Default'; values: readonly [] }
  | { tag: 'CallContract'; values: readonly [string] };

export function buildContextTypeArg(draft: RuleDraft): ContextTypeArg {
  if (draft.scope.kind === 'call-contract') {
    return { tag: 'CallContract', values: [draft.scope.contract!.trim()] as const };
  }
  return { tag: 'Default', values: [] as const };
}

export type SignerArg =
  | { tag: 'External'; values: readonly [string, string] } // [verifier, publicKeyHex]
  | { tag: 'Delegated'; values: readonly [string] };

export function buildSignerArgs(draft: RuleDraft): SignerArg[] {
  return draft.signers.map((s) =>
    s.kind === 'delegated'
      ? ({ tag: 'Delegated', values: [s.address!.trim()] as const } as const)
      : ({ tag: 'External', values: [s.verifier!.trim(), s.publicKeyHex!.trim()] as const } as const),
  );
}

export interface SpendingLimitPlan {
  stroops: bigint;
  periodLedgers: number;
}

/** The spending-limit policy to attach, or null. The page resolves the policy
 *  address from the registry and builds its param ScVal. */
export function spendingLimitPlan(draft: RuleDraft): SpendingLimitPlan | null {
  if (!draft.spendingLimit) return null;
  return {
    stroops: BigInt(draft.spendingLimit.stroops),
    periodLedgers: draft.spendingLimit.periodLedgers,
  };
}

export interface AddContextRuleArgs {
  context_type: ContextTypeArg;
  name: string;
  valid_until: number | undefined;
  signers: SignerArg[];
}

/** Lower a validated draft to the binding arguments (policies added by the page).
 *  Precondition: `validateDraft(draft).ok`. */
export function buildAddContextRuleArgs(draft: RuleDraft): AddContextRuleArgs {
  return {
    context_type: buildContextTypeArg(draft),
    name: draft.name.trim(),
    valid_until: draft.validUntilLedger ?? undefined,
    signers: buildSignerArgs(draft),
  };
}
