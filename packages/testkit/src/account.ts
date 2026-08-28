// Create a Nido smart account from local signers — derive its C-address and
// build its authorization policy as a perch PolicyDoc with a real doc_hash.
//
// Address derivation is the real Soroban deployer+salt scheme (identical to the
// factory's on-chain `get_c_address`); the policy layer is perch (a
// stellar-registry/perch library — not yet integrated on-chain in nido, so the
// PolicyDoc + doc_hash are the target-state model the simulator enforces).

import { sha256 } from '@noble/hashes/sha2.js';
import { xdr, hash, Address, StrKey } from '@stellar/stellar-sdk';
import { docHash } from './perch/canonical.js';
import { rule, selfAdmin, type PolicyDoc, type Rule } from './perch/policy.js';
import type { LocalSigner } from './signer.js';

/** Registry-fallback factory (the deployer whose salt derives the C-address). */
export const DEFAULT_FACTORY = 'CBQKB6GYPO7P2CGDKN7KYLEFEBBN6FY5NXZJ7HNR43ZK2DDOU5N7NCV5';

export const TESTNET_PASSPHRASE = 'Test SDF Network ; September 2015';

export interface CreateAccountOptions {
  signers: LocalSigner[];
  /** Network passphrase (default: testnet). */
  network?: string;
  /** Deployer contract whose salt derives the address (default: the factory). */
  factory?: string;
  /** 32-byte salt (default: sha256 of the first signer's public key). */
  salt?: Uint8Array;
  /** Override the default policy rules (default: one self-admin N-of-N rule). */
  rules?: Rule[];
}

export interface LocalAccount {
  /** Derived smart-account C-address. */
  readonly address: string;
  readonly signers: LocalSigner[];
  readonly policy: PolicyDoc;
  /** Real perch doc_hash of `policy`. */
  readonly docHash: string;
  readonly network: string;
}

/** The real deployer+salt contract-id derivation (matches on-chain). */
export function deriveAccountAddress(factory: string, salt: Uint8Array, passphrase: string): string {
  const preimage = xdr.HashIdPreimage.envelopeTypeContractId(
    new xdr.HashIdPreimageContractId({
      networkId: hash(Buffer.from(passphrase, 'utf-8')),
      contractIdPreimage: xdr.ContractIdPreimage.contractIdPreimageFromAddress(
        new xdr.ContractIdPreimageFromAddress({
          address: Address.fromString(factory).toScAddress(),
          salt: Buffer.from(salt),
        }),
      ),
    }),
  );
  return StrKey.encodeContract(hash(preimage.toXDR()));
}

export function createLocalAccount(opts: CreateAccountOptions): LocalAccount {
  const first = opts.signers[0];
  if (!first) throw new Error('createLocalAccount: at least one signer is required');

  const network = opts.network ?? TESTNET_PASSPHRASE;
  const factory = opts.factory ?? DEFAULT_FACTORY;
  const salt = opts.salt ?? sha256(first.publicKey);
  const address = deriveAccountAddress(factory, salt, network);

  const signerDecls = opts.signers.map((s) => ({ id: s.id, verifier: s.verifier, key: s.publicKeyHex }));
  const rules =
    opts.rules ?? [rule({ name: 'admin-root', scope: selfAdmin(), signedBy: opts.signers.map((s) => s.id) })];

  const policy: PolicyDoc = { version: 1, network, signers: signerDecls, rules };
  return { address, signers: opts.signers, policy, docHash: docHash(policy), network };
}
