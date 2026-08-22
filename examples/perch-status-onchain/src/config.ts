// Deployed testnet pieces for the perch-on-chain demo. These are REAL contracts
// on Stellar testnet; the account below is governed by a perch policy that lets
// its secp256r1 "poster" key call board.post but not board.clear.
import { Networks } from '@stellar/stellar-sdk';

export const RPC_URL = 'https://soroban-testnet.stellar.org';
export const NETWORK = Networks.TESTNET;
export const FRIENDBOT = 'https://friendbot.stellar.org';

export const CONTRACTS = {
  /** perch interpreter (OZ Policy) — the contract that says allow/deny on-chain. */
  interpreter: 'CBO4FIGR2LP242IKWDME6NPFGCFAT5R7CSLKYLOOJFVXCCIGKVF6O44G',
  /** status board: post(message, author) / clear(author) / get(author). */
  board: 'CBVXSCMALSZBF32OGUXIXFAFMPYFOJM4BOA27PBCMJPR6ZNUREX5ELWM',
  /** real deployed WebAuthn verifier (secp256r1). */
  verifier: 'CACVGSAHYFBXY4LJKWW5B57LAAXHCZVDZOANUTYPLNV6HHQI4Q35EGMY',
  /** the perch-governed Nido smart account. */
  account: 'CAZSVYNP52AGK66S3XIAW6HJDFLMXHH3IQECRNCWKHSPIXKMD4RBNMPV',
} as const;

/** Deterministic seed for the demo's "poster" secp256r1 key (testnet only) — so
 *  the bundled account is stable and anyone can reproduce it. */
export const POSTER_SEED = new Uint8Array(32).fill(7);

/** The Default context rule the perch policy is installed on. */
export const RULE_ID = 0;

/** The M-of-N (Act 6) pieces: a separate account whose Default rule is a 2-of-3
 *  via Nido's multisig policy. Deployed + proven by `scripts/prove-threshold.ts`;
 *  the demo drives its multi-signer ceremony live. */
export const THRESHOLD = {
  /** Nido multisig policy (SimpleThresholdAccountParams) — `unverified/multisig-policy`. */
  policy: 'CCSDKJYOFCPTCCGQZPF73RJNHFC7TPO532Q36N3M2VBYZFWQOTDB7J7G',
  /** the deployed 2-of-3 account. */
  account: 'CCJLM2X6SDBX5QXFI7QCZ42Q3TAYWBWYA2IG56IUHLXRNQIKP4OU3GQL',
  threshold: 2,
  /** deterministic seeds for the three secp256r1 co-signers (fill 11/12/13). */
  signers: [
    { id: 'owner', seed: new Uint8Array(32).fill(11) },
    { id: 'backup', seed: new Uint8Array(32).fill(12) },
    { id: 'treasury', seed: new Uint8Array(32).fill(13) },
  ],
} as const;

export const explorerTx = (h: string) => `https://stellar.expert/explorer/testnet/tx/${h}`;
export const explorerContract = (c: string) => `https://stellar.expert/explorer/testnet/contract/${c}`;
