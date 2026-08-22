// The account the tour visualizes: signers across every verifier (secp256r1,
// post-quantum ML-DSA-65, and a Delegated "another account"), and its full
// policy as several rules — showing how perch composes with OZ-native policies.
// The CI key's rule is the one actually enforced on-chain in Act 5.
import { contract, isSelf, rule, secp256r1Keypair, mlDsa65Keypair, TESTNET_PASSPHRASE, type PolicyDoc } from '@nidohq/testkit';
import { CONTRACTS, THRESHOLD } from './config.js';
import { poster } from './perchOnchain.js';

const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const short = (s: string) => (s.length > 18 ? `${s.slice(0, 9)}…${s.slice(-6)}` : s);

export const POSTER_KEY_HEX = hex(poster.publicKey);
// Distinct, deterministic keys so the account is stable/reproducible.
const owner = secp256r1Keypair(new Uint8Array(32).fill(3));
const pq = mlDsa65Keypair(new Uint8Array(32).fill(9));
// A real testnet G-account, used illustratively as a delegated co-signer.
export const TREASURY_G = 'GA327GGWT6747B57DRWJJ3SWBVIQ354TTDRHR76CVAWO6OBPZ4Z57YGA';

export type VerifierKind = 'secp256r1' | 'ml-dsa-65' | 'delegated';
export interface SignerView {
  id: string;
  label: string;
  verifier: VerifierKind;
  kind: 'External' | 'Delegated';
  detail: string;
  status: 'live' | 'sim';
  note?: string;
}

/** Every signer type a Nido account can hold. */
export const SIGNERS: SignerView[] = [
  { id: 'owner', label: 'Owner passkey', verifier: 'secp256r1', kind: 'External', detail: `key ${short(hex(owner.publicKey))}`, status: 'live', note: 'WebAuthn / passkey — the human owner' },
  { id: 'ci', label: 'CI key', verifier: 'secp256r1', kind: 'External', detail: `key ${short(POSTER_KEY_HEX)}`, status: 'live', note: 'scoped by perch → enforced on-chain in Act 5' },
  { id: 'pq', label: 'Post-quantum key', verifier: 'ml-dsa-65', kind: 'External', detail: `key ${short(hex(pq.publicKey))} (${pq.publicKey.length} B)`, status: 'sim', note: 'ML-DSA-65 — quantum-safe; verifier groundwork #143' },
  { id: 'treasury', label: 'Treasury account', verifier: 'delegated', kind: 'Delegated', detail: `account ${short(TREASURY_G)}`, status: 'live', note: 'Delegated → another G-account authorizes on the account’s behalf' },
];

export type PolicyKind = 'policy-free' | 'perch' | 'spending-limit' | 'm-of-n';
export interface RuleView {
  name: string;
  signers: string[];
  scope: string;
  policy: PolicyKind;
  reach: string;
  status: 'live' | 'sim';
  onchain?: boolean;
}

/** The account's full policy: perch composed with OZ-native policies. */
export const RULES: RuleView[] = [
  { name: 'owner-root', signers: ['owner'], scope: 'self-admin', policy: 'policy-free', reach: 'any admin op — rides OZ’s audited signer check (INV-2)', status: 'live' },
  { name: 'ci-can-publish', signers: ['ci'], scope: 'status board', policy: 'perch', reach: 'post() · author = self', status: 'live', onchain: true },
  { name: 'pq-cosign-admin', signers: ['pq'], scope: 'self-admin', policy: 'policy-free', reach: 'admin, post-quantum signature', status: 'sim' },
  { name: 'treasury-cap', signers: ['treasury'], scope: 'XLM token', policy: 'spending-limit', reach: 'transfer() ≤ 100 XLM / day', status: 'sim' },
];

/** Everything the Act-5 builder can vary about the CI key's single rule. */
export interface BuildConfig {
  /** Allowed functions. Empty ⇒ the rule OMITS `functions`, which means *any*
   *  function — broader, not narrower (perch rejects an explicit empty list). */
  functions: string[];
  /** Attach `args[1] = self`, so the key can only post as the account itself. */
  selfArg: boolean;
  /** OZ `valid_until` expiry (perch `not-after-ledger`); null ⇒ never expires. */
  notAfterLedger: number | null;
}

/** The status board's write functions the CI key can be granted. `clear` is the
 *  dangerous one (wipes history) — the over-broad grant to narrow away. */
export const BOARD_FUNCTIONS: { name: string; risky?: boolean }[] = [
  { name: 'post' },
  { name: 'clear', risky: true },
];

/** The tour opens over-broad (post + clear) so narrowing has something to do. */
export const DEFAULT_BUILD: BuildConfig = { functions: ['post', 'clear'], selfArg: true, notAfterLedger: null };

// --- Act 6: adding signers and an M-of-N quorum ------------------------------
//
// The 2-of-3 account (deployed by scripts/prove-threshold.ts) — three secp256r1
// co-signers on the Default rule, gated by Nido's multisig policy at threshold 2.

/** The three co-signers of the 2-of-3 account, derived from their seeds. */
export const MOFN_SIGNERS: SignerView[] = THRESHOLD.signers.map((s, i) => {
  const kp = secp256r1Keypair(s.seed);
  const labels = ['Owner passkey', 'Backup key', 'Treasury key'];
  const notes = ['the human owner', 'a recovery / co-sign device', 'a finance co-signer'];
  return {
    id: s.id,
    label: labels[i] ?? s.id,
    verifier: 'secp256r1',
    kind: 'External',
    detail: `key ${short(hex(kp.publicKey))}`,
    status: 'live',
    note: notes[i],
  };
});

/** The quorum rule: any of the three may propose, but 2 signatures are required. */
export const MOFN_RULE: RuleView = {
  name: 'ops-quorum',
  signers: MOFN_SIGNERS.map((s) => s.id),
  scope: 'any call',
  policy: 'm-of-n',
  reach: `${THRESHOLD.threshold}-of-${THRESHOLD.signers.length} must sign · any account op`,
  status: 'live',
  onchain: true,
};

/** The CI key's perch policy as a PolicyDoc, assembled from a builder config. */
export function buildDoc(cfg: BuildConfig): PolicyDoc {
  return {
    version: 1,
    network: TESTNET_PASSPHRASE,
    signers: [{ id: 'ci', verifier: CONTRACTS.verifier, key: POSTER_KEY_HEX }],
    rules: [
      rule({
        name: 'ci-can-publish',
        scope: contract(CONTRACTS.board),
        signedBy: ['ci'],
        functions: cfg.functions.length ? cfg.functions : undefined,
        args: cfg.selfArg ? [{ index: 1, pred: isSelf() }] : undefined,
        notAfterLedger: cfg.notAfterLedger ?? undefined,
      }),
    ],
  };
}
