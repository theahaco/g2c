/**
 * Wallet-side signing for the stellar-wallets-kit ceremony at
 * `<account>.<base>/sign/`.
 *
 * Unlike `primaryPasskeySigner.signAndSubmit` (which BUILDS the tx and SUBMITS
 * it), the kit's `signTransaction` is handed a finished XDR by the dApp and
 * must return that XDR *with the wallet's signature attached* — submission is
 * the dApp's job (SEP-43 semantics). So these helpers take a tx XDR, attach a
 * primary-passkey signature, and return the new XDR.
 *
 * Two paths:
 *   - Soroban tx (single InvokeHostFunction op): we simulate to discover the
 *     smart account's auth entry, compute the OZ v0.7 auth digest, get a
 *     WebAuthn assertion over it, and inject the passkey signature into the
 *     auth entry. Returns the signed tx XDR.
 *   - Classic tx: a Nido smart account is a contract (C-address) and cannot be
 *     the source/signer of a classic Stellar operation, so there's nothing for
 *     the passkey to sign in the classic envelope. We surface a clear error
 *     rather than returning an unsigned tx that the dApp would think is signed.
 *     (Documented limitation; see issue #29 follow-ups.)
 */

import {
  rpc,
  TransactionBuilder,
  Networks,
  xdr,
  Transaction,
  FeeBumpTransaction,
  Operation,
} from '@stellar/stellar-sdk';
import {
  loadCredential,
  buildAuthHash,
  computeAuthDigest,
  getAuthEntry,
  injectPasskeySignature,
  injectSignedAuthPayload,
  identifyAssertionSigner,
  parseAssertionResponse,
  buf2hex,
  hex2buf,
  type SignerSignature,
  type PasskeySignature,
} from '@nidohq/passkey-sdk';
import {
  resolveSignerRule,
  fetchDefaultRuleAuthInfo,
  type DefaultRuleAuthInfo,
} from './policyChainFetch.js';
import { signatureExpirationOffset } from './relayerClient';

const RPC_URL = 'https://soroban-testnet.stellar.org';

/** How many rule-0 signatures a ceremony must collect, given the rule's
 *  on-chain state. Policy-less multi-signer rules are N-of-N under OZ
 *  semantics; with a policy, the simple-threshold M (default 1) governs. */
function requiredSignatureCount(info: DefaultRuleAuthInfo): number {
  if (info.policyCount > 0) return Math.max(1, info.threshold ?? 1);
  return Math.max(1, info.externalSigners.length + info.delegatedCount);
}

/** Human explanation for a rule the ceremony cannot satisfy (issue #87). */
function nOfNHelp(required: number, total: number): string {
  return (
    `This account currently requires all ${required} of its ${total} ` +
    `passkeys to approve together (no approval policy is installed on its ` +
    `signing rule). If you don't have all of them on this device, open the ` +
    `account's Security → "Get back in" page: your trusted friends can ` +
    `repair the account so any single passkey works again.`
  );
}

/** Does this transaction carry exactly one InvokeHostFunction op (i.e. Soroban)? */
function isSorobanTx(tx: Transaction): boolean {
  return (
    tx.operations.length === 1 &&
    tx.operations[0].type === 'invokeHostFunction'
  );
}

/**
 * Sign a transaction XDR with the account's primary passkey and return the
 * signed XDR (NOT submitted).
 *
 * @param account   The smart-account C-address (must match the page subdomain
 *                  so WebAuthn's rpId matches the registered credential).
 * @param txXdr     base64 XDR of a `Transaction` or `FeeBumpTransaction`.
 * @param networkPassphrase  Network the tx is for.
 */
export async function signTransactionXdr(args: {
  account: string;
  txXdr: string;
  networkPassphrase?: string;
  /** Progress callback for multi-passkey ceremonies ("signature 1 of 2…"). */
  onStatus?: (msg: string) => void;
}): Promise<string> {
  const networkPassphrase = args.networkPassphrase ?? Networks.TESTNET;
  const cred = loadCredential(args.account);
  if (!cred) throw new Error('No passkey registered for this account.');

  const parsed = TransactionBuilder.fromXDR(args.txXdr, networkPassphrase);
  if (parsed instanceof FeeBumpTransaction) {
    throw new Error('Fee-bump transactions are not supported by the Nido passkey signer.');
  }
  const tx = parsed as Transaction;

  if (!isSorobanTx(tx)) {
    throw new Error(
      'This transaction is not a Soroban contract invocation. A Nido smart ' +
        'account (a contract address) can only authorize Soroban operations, ' +
        'so there is nothing for the passkey to sign on a classic Stellar ' +
        'transaction.',
    );
  }

  const server = new rpc.Server(RPC_URL);
  // Resolve which rule this passkey signs under + that rule's verifier in one
  // scan (see resolveSignerRule). A ZK-recovered account's passkey lives in a
  // later rule, not rule 0 — signing rule 0 fails Error(Auth, InvalidAction),
  // the same bug fixed in primaryPasskeySigner. Everything below (digest,
  // preflight, AuthPayload) must reference this resolved rule, not 0.
  const resolved = await resolveSignerRule(args.account, cred.publicKey);
  if (!resolved) {
    throw new Error(
      'This passkey is not registered on any authorization rule of the account. ' +
        'If you just recovered, wait for the completion transaction to confirm and retry.',
    );
  }
  const verifierAddress = resolved.verifier;

  // Preflight (issue #87): read the resolved rule BEFORE the WebAuthn ceremony.
  // A policy-less multi-signer rule is N-of-N under OZ semantics — one passkey
  // signature would sail through the ceremony only to fail the enforce
  // simulation with a raw `Error(Contract, #3002) UnvalidatedContext`. When
  // the rule needs multiple signatures, either collect them all (multi-
  // passkey ceremony below) or explain in human terms why signing can't work.
  let ruleInfo: DefaultRuleAuthInfo | null = null;
  try {
    ruleInfo = await fetchDefaultRuleAuthInfo(args.account, resolved.ruleId);
  } catch {
    // Rule unreadable — fall back to the single-signature ceremony rather
    // than blocking signing on a transient read failure.
  }
  const requiredSignatures = ruleInfo ? requiredSignatureCount(ruleInfo) : 1;
  if (ruleInfo && requiredSignatures > 1) {
    const total = ruleInfo.externalSigners.length + ruleInfo.delegatedCount;
    if (ruleInfo.policyCount === 0 && ruleInfo.delegatedCount > 0) {
      // A policy-less rule requires ALL signers — including Delegated
      // (account-address) ones, which this wallet ceremony cannot satisfy.
      throw new Error(nOfNHelp(requiredSignatures, total));
    }
    if (requiredSignatures > ruleInfo.externalSigners.length) {
      throw new Error(nOfNHelp(requiredSignatures, total));
    }
  }

  // Strip any auth templates and simulate fresh in recording mode so the
  // simulator regenerates the smart account's auth entry — same reasoning as
  // primaryPasskeySigner.signAndSubmit (Void signatures trap recording-mode
  // __check_auth otherwise). Rebuild the tx from the host function with no
  // auth, using the SAME source/sequence/fee the dApp chose so the simulation
  // footprint matches what the dApp will submit.
  const op = tx.operations[0] as Operation.InvokeHostFunction;
  const sourceAccount = await server.getAccount(tx.source);
  const simTx = new TransactionBuilder(sourceAccount, {
    fee: tx.fee,
    networkPassphrase,
  })
    .addOperation(Operation.invokeHostFunction({ func: op.func, auth: [] }))
    .setTimeout(0)
    .build();

  const sim = await server.simulateTransaction(simTx);
  if (rpc.Api.isSimulationError(sim)) {
    throw new Error(`Simulation failed: ${(sim as rpc.Api.SimulateTransactionErrorResponse).error}`);
  }
  const successSim = sim as rpc.Api.SimulateTransactionSuccessResponse;

  const authEntry = getAuthEntry(successSim);
  const lastLedger = successSim.latestLedger;
  // SECURITY (F6): the signed XDR this function returns is ALWAYS relayer-
  // submitted by runSign (the dApp raw-xdr path ships the signed auth entry to
  // the external Channels relayer). In relayer mode bound the auth-entry
  // validity to the same tight ~10-minute window primaryPasskeySigner uses, so
  // a relayer holding the body can't replay it for ~14h. The offset MUST be
  // identical between buildAuthHash and the injector(s) or the digest the
  // contract recomputes won't match this signature.
  const expirationOffset = signatureExpirationOffset();
  const signaturePayload = buildAuthHash(authEntry, networkPassphrase, lastLedger, expirationOffset);
  const contextRuleIds = [resolved.ruleId];
  const challengeBytes = computeAuthDigest(signaturePayload, contextRuleIds);

  const assembledTx = rpc.assembleTransaction(simTx, successSim).build();

  if (requiredSignatures <= 1) {
    // Single-passkey ceremony (the overwhelmingly common case).
    const parsedSig = await runAssertionCeremony(challengeBytes, cred.credentialId);
    injectPasskeySignature(
      assembledTx,
      parsedSig,
      verifierAddress,
      hex2buf(cred.publicKey),
      lastLedger,
      expirationOffset,
      contextRuleIds,
    );
  } else {
    // Multi-passkey ceremony (issue #87): collect `requiredSignatures`
    // assertions over the SAME auth digest — every signer in the AuthPayload
    // map is verified against that one digest — and bundle them into one
    // multi-signer payload.
    const signers = await collectMultiPasskeySignatures({
      ruleInfo: ruleInfo!,
      required: requiredSignatures,
      challengeBytes,
      storedCred: cred,
      onStatus: args.onStatus,
    });
    injectSignedAuthPayload(assembledTx, signers, lastLedger, expirationOffset, contextRuleIds);
  }

  // Re-simulate in enforce mode to recompute the footprint that __check_auth
  // touches, then splice the fresh sorobanData in (see signAndSubmit notes).
  const finalSim = await server.simulateTransaction(assembledTx, undefined, 'enforce');
  if (rpc.Api.isSimulationError(finalSim)) {
    throw new Error(`Final simulation failed: ${(finalSim as rpc.Api.SimulateTransactionErrorResponse).error}`);
  }
  const successFinalSim = finalSim as rpc.Api.SimulateTransactionSuccessResponse;
  const newSorobanData = successFinalSim.transactionData.build();
  const newResourceFee = BigInt(newSorobanData.resourceFee().toString());
  const classicFee =
    BigInt(assembledTx.fee) -
    BigInt(
      (assembledTx.toEnvelope().v1().tx().ext().value() as xdr.SorobanTransactionData | undefined)
        ?.resourceFee()
        .toString() ?? '0',
    );
  const refitted = TransactionBuilder.cloneFrom(assembledTx, {
    fee: (classicFee + newResourceFee).toString(),
    sorobanData: newSorobanData,
    networkPassphrase,
  }).build();

  // Return the signed XDR. The smart account's auth entry now carries the
  // passkey signature; the dApp is responsible for adding a tx-source
  // signature (fee payer) and submitting.
  return refitted.toXDR();
}

/** Run one `navigator.credentials.get()` ceremony over `challenge` and parse
 *  the assertion. `credentialId` scopes the prompt to a known credential;
 *  omit it for a DISCOVERABLE ceremony (the authenticator lists every
 *  resident credential for this rpId and the user picks one). */
async function runAssertionCeremony(
  challenge: Uint8Array,
  credentialId?: Uint8Array,
): Promise<PasskeySignature> {
  const challengeBuf = new ArrayBuffer(challenge.byteLength);
  new Uint8Array(challengeBuf).set(challenge);
  let assertion: PublicKeyCredential | null;
  try {
    assertion = (await navigator.credentials.get({
      publicKey: {
        challenge: challengeBuf,
        rpId: window.location.hostname,
        ...(credentialId
          ? {
              allowCredentials: [
                { id: credentialId as unknown as Uint8Array<ArrayBuffer>, type: 'public-key' as const },
              ],
            }
          : {}),
        userVerification: 'required',
        timeout: 60000,
      },
    })) as PublicKeyCredential | null;
  } catch (e) {
    if (e instanceof DOMException && e.name === 'NotAllowedError') {
      throw new Error('Passkey signing was cancelled.');
    }
    throw e;
  }
  if (!assertion) throw new Error('Passkey signing was cancelled.');
  const response = assertion.response as AuthenticatorAssertionResponse;
  return parseAssertionResponse({
    authenticatorData: response.authenticatorData,
    clientDataJSON: response.clientDataJSON,
    signature: response.signature,
  });
}

/**
 * Collect `required` passkey signatures over the same auth digest from rule
 * 0's External signers (issue #87 — N-of-N or M-of-N rules).
 *
 * Strategy: sign first with the locally-stored credential (its public key is
 * known), then run DISCOVERABLE ceremonies for the rest. A discoverable
 * assertion does not say which public key it belongs to, so each one is
 * matched against the still-unmatched rule signers by verifying its P-256
 * signature (`identifyAssertionSigner`).
 */
async function collectMultiPasskeySignatures(args: {
  ruleInfo: DefaultRuleAuthInfo;
  required: number;
  challengeBytes: Uint8Array;
  storedCred: { credentialId: Uint8Array; publicKey: string };
  onStatus?: (msg: string) => void;
}): Promise<SignerSignature[]> {
  const { ruleInfo, required, challengeBytes, storedCred, onStatus } = args;
  const total = ruleInfo.externalSigners.length + ruleInfo.delegatedCount;

  // Rule signers still awaiting a signature, keyed by lowercase pubkey hex.
  const remaining = new Map<string, { verifier: string; publicKey: Uint8Array }>(
    ruleInfo.externalSigners.map((s) => [buf2hex(s.publicKey).toLowerCase(), s]),
  );
  const collected: SignerSignature[] = [];

  const wrapCancel = async (run: () => Promise<PasskeySignature>): Promise<PasskeySignature> => {
    try {
      return await run();
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      if (/cancelled/i.test(msg)) {
        throw new Error(
          `Signing stopped after ${collected.length} of ${required} required ` +
            `passkey approvals. ` +
            nOfNHelp(required, total),
        );
      }
      throw e;
    }
  };

  // 1) The locally-stored credential first — its public key is known.
  const storedHex = storedCred.publicKey.toLowerCase();
  const storedSigner = remaining.get(storedHex);
  if (storedSigner) {
    onStatus?.(`Approve with this device's passkey (signature 1 of ${required})…`);
    const sig = await wrapCancel(() =>
      runAssertionCeremony(challengeBytes, storedCred.credentialId),
    );
    collected.push({
      kind: 'external',
      verifierAddress: storedSigner.verifier,
      publicKey: storedSigner.publicKey,
      passkeySignature: sig,
    });
    remaining.delete(storedHex);
  }

  // 2) Discoverable ceremonies for the remaining signers.
  while (collected.length < required) {
    onStatus?.(
      `Approve with another of this account's passkeys ` +
        `(signature ${collected.length + 1} of ${required})…`,
    );
    const sig = await wrapCancel(() => runAssertionCeremony(challengeBytes));
    const candidates = [...remaining.values()];
    const idx = await identifyAssertionSigner(
      sig,
      candidates.map((c) => c.publicKey),
    );
    if (idx === null) {
      throw new Error(
        'That passkey is not one of this account\'s remaining signers (or ' +
          'was already used in this ceremony). ' +
          nOfNHelp(required, total),
      );
    }
    const matched = candidates[idx];
    collected.push({
      kind: 'external',
      verifierAddress: matched.verifier,
      publicKey: matched.publicKey,
      passkeySignature: sig,
    });
    remaining.delete(buf2hex(matched.publicKey).toLowerCase());
  }

  return collected;
}

/**
 * Run the primary-passkey WebAuthn ceremony over an arbitrary 32-byte
 * challenge and return the assertion components, base64url-JSON-encoded.
 *
 * Shared by message and auth-entry signing. Because a Nido smart account
 * verifies P-256/WebAuthn assertions (not Ed25519), the "signature" the wallet
 * produces is the full WebAuthn assertion (authenticatorData + clientData +
 * P-256 signature) plus the signer public key — not a bare 64-byte Stellar
 * signature. A relying contract feeds these to the webauthn-verifier.
 */
async function passkeyAssertEnvelope(account: string, challenge32: Uint8Array): Promise<string> {
  const cred = loadCredential(account);
  if (!cred) throw new Error('No passkey registered for this account.');
  if (challenge32.byteLength !== 32) throw new Error('challenge must be 32 bytes');

  const challengeBuf = new ArrayBuffer(32);
  new Uint8Array(challengeBuf).set(challenge32);
  const assertion = (await navigator.credentials.get({
    publicKey: {
      challenge: challengeBuf,
      rpId: window.location.hostname,
      allowCredentials: [
        { id: cred.credentialId as unknown as Uint8Array<ArrayBuffer>, type: 'public-key' },
      ],
      userVerification: 'required',
      timeout: 60000,
    },
  })) as PublicKeyCredential | null;
  if (!assertion) throw new Error('Passkey signing was cancelled.');

  const response = assertion.response as AuthenticatorAssertionResponse;
  const sig = parseAssertionResponse({
    authenticatorData: response.authenticatorData,
    clientDataJSON: response.clientDataJSON,
    signature: response.signature,
  });

  const envelope = {
    type: 'nido-webauthn-assertion',
    publicKey: cred.publicKey,
    authenticatorData: bytesToHex(sig.authenticatorData),
    clientData: bytesToHex(sig.clientDataJson),
    signature: bytesToHex(sig.signature),
  };
  return base64urlJson(envelope);
}

function bytesToHex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
}

function base64urlJson(o: unknown): string {
  const json = JSON.stringify(o);
  // btoa over UTF-8-safe bytes, then URL-safe.
  const bytes = new TextEncoder().encode(json);
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

/**
 * Sign an arbitrary message string with the primary passkey. The message is
 * hashed (SHA-256) to a 32-byte challenge per common SEP-43 practice; returns
 * the base64url-JSON WebAuthn assertion envelope (see `passkeyAssertEnvelope`).
 */
export async function signMessageRaw(args: { account: string; message: string }): Promise<string> {
  const { hash } = await import('@stellar/stellar-sdk');
  const digest = new Uint8Array(hash(Buffer.from(args.message, 'utf-8')));
  return passkeyAssertEnvelope(args.account, digest);
}

/**
 * Sign a Soroban auth-entry preimage with the primary passkey. `authEntryXdr`
 * is the base64 XDR of a `HashIdPreimageSorobanAuthorization`; we SHA-256 it to
 * the signature payload, apply the OZ v0.7 auth digest over the passkey's
 * resolved signing rule, and produce the WebAuthn assertion envelope. The
 * caller assembles the entry and MUST bind the same rule id into its
 * AuthPayload's `context_rule_ids`, or the digest the contract recomputes won't
 * match this signature.
 */
export async function signAuthEntryXdr(args: { account: string; authEntryXdr: string }): Promise<string> {
  const { hash } = await import('@stellar/stellar-sdk');
  const cred = loadCredential(args.account);
  if (!cred) throw new Error('No passkey registered for this account.');
  // Resolve the passkey's actual rule (a recovered account's key is not in
  // rule 0) so the digest binds the correct context_rule_ids.
  const resolved = await resolveSignerRule(args.account, cred.publicKey);
  if (!resolved) {
    throw new Error('This passkey is not registered on any authorization rule of the account.');
  }
  const preimage = xdr.HashIdPreimage.fromXDR(args.authEntryXdr, 'base64');
  const signaturePayload = new Uint8Array(hash(preimage.toXDR()));
  const digest = new Uint8Array(computeAuthDigest(signaturePayload, [resolved.ruleId]));
  return passkeyAssertEnvelope(args.account, digest);
}
