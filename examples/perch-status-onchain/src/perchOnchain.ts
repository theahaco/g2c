// The proven on-chain invoke flow, browser-ready. Drives a real testnet call
// authorized by a perch-governed Nido account with a LOCAL secp256r1 key:
//
//   build → recording-simulate → sign the account's OZ AuthPayload with the
//   poster key → RE-simulate the SIGNED tx (enforcing mode runs __check_auth:
//   webauthn verify + perch enforce, capturing their footprint the recording
//   pass omits) → submit with that footprint.
//
// The DENY case surfaces at the enforcing re-simulation as the interpreter's
// `Denied` — the same verdict the chain reaches — and we still submit it (with
// the allow case's footprint) to land a real, cleanly-failed on-chain tx.
import {
  Address,
  BASE_FEE,
  Keypair,
  Networks,
  Operation,
  TransactionBuilder,
  nativeToScVal,
  rpc,
  xdr,
} from '@stellar/stellar-sdk';
import { buildSyntheticAssertion, computeAuthDigest, secp256r1Keypair } from '@nidohq/testkit';
import { buildAuthHash, injectPasskeySignature, injectSignedAuthPayload } from '@nidohq/passkey-sdk';
import { CONTRACTS, NETWORK, POSTER_SEED, RPC_URL, RULE_ID, THRESHOLD } from './config.js';

export type Fn = 'post' | 'clear';
export interface InvokeOutcome {
  fn: Fn;
  ok: boolean;
  denied: boolean;
  hash?: string;
  /** on-chain reason (perch's Denied error, or a validation message). */
  reason?: string;
  sorobanData?: xdr.SorobanTransactionData;
}

export interface Progress {
  (step: string): void;
}

export const server = new rpc.Server(RPC_URL);
export const poster = secp256r1Keypair(POSTER_SEED);

/** Generate + friendbot-fund an ephemeral classic account to pay fees. */
export async function fundedFeeSource(note: Progress = () => {}): Promise<Keypair> {
  const kp = Keypair.random();
  note('Funding an ephemeral fee account (friendbot)…');
  const res = await fetch(`https://friendbot.stellar.org/?addr=${kp.publicKey()}`);
  if (!res.ok && res.status !== 400) throw new Error(`friendbot: ${res.status}`);
  // Poll until the account is visible to RPC.
  for (let i = 0; i < 10; i++) {
    try {
      await server.getAccount(kp.publicKey());
      return kp;
    } catch {
      await new Promise((r) => setTimeout(r, 1000));
    }
  }
  throw new Error('fee account never materialized');
}

function externalSigner(verifier: string, pubkey: Uint8Array): xdr.ScVal {
  return xdr.ScVal.scvVec([
    xdr.ScVal.scvSymbol('External'),
    Address.fromString(verifier).toScVal(),
    xdr.ScVal.scvBytes(Buffer.from(pubkey)),
  ]);
}
// (exported for the deploy script's constructor args)
export { externalSigner };

async function poll(hash: string): Promise<rpc.Api.GetTransactionResponse> {
  return server.pollTransaction(hash, { attempts: 15, sleepStrategy: () => 2000 });
}

/**
 * Invoke board.<fn> authorized by the perch-governed account.
 * `reuseSorobanData` lets the deny case borrow the allow case's footprint.
 */
export async function invokeBoardCall(
  feeKp: Keypair,
  fn: Fn,
  message: string | null,
  reuseSorobanData?: xdr.SorobanTransactionData,
  note: Progress = () => {},
): Promise<InvokeOutcome> {
  const account = CONTRACTS.account;
  const args =
    fn === 'post'
      ? [nativeToScVal(message ?? '', { type: 'string' }), Address.fromString(account).toScVal()]
      : [Address.fromString(account).toScVal()];
  const op = Operation.invokeContractFunction({ contract: CONTRACTS.board, function: fn, args });

  note('Recording-simulating…');
  const src = await server.getAccount(feeKp.publicKey());
  const tx = new TransactionBuilder(src, { fee: (Number(BASE_FEE) * 100).toString(), networkPassphrase: NETWORK })
    .addOperation(op)
    .setTimeout(120)
    .build();
  const sim = await server.simulateTransaction(tx);
  if (rpc.Api.isSimulationError(sim)) return { fn, ok: false, denied: false, reason: `simulation: ${sim.error}` };

  const lastLedger = (await server.getLatestLedger()).sequence;
  const assembled = rpc.assembleTransaction(tx, sim).build();

  note('Signing the account’s authorization with the local secp256r1 key…');
  const entry = (assembled.operations[0] as Operation.InvokeHostFunction).auth![0]!;
  const authDigest = computeAuthDigest(buildAuthHash(entry, NETWORK, lastLedger), [RULE_ID]);
  const a = buildSyntheticAssertion(poster.secretKey, authDigest);
  injectPasskeySignature(
    assembled,
    { authenticatorData: a.authenticatorData, clientDataJson: a.clientDataJSON, signature: a.signature },
    CONTRACTS.verifier,
    poster.publicKey,
    lastLedger,
    undefined,
    [RULE_ID],
  );

  note('Enforcing re-simulation (runs __check_auth: verifier + perch on-chain)…');
  let sorobanData = reuseSorobanData;
  const sim2 = await server.simulateTransaction(assembled);
  if (rpc.Api.isSimulationError(sim2)) {
    const reason = perchReason(sim2.error);
    if (!reuseSorobanData) return { fn, ok: false, denied: true, reason };
    // else: land a real failed tx with the borrowed footprint.
  } else {
    sorobanData = sim2.transactionData.build();
  }
  const resourceFee = Number((sim2 as rpc.Api.SimulateTransactionSuccessResponse).minResourceFee ?? 0);

  note('Submitting to testnet…');
  const finalTx = TransactionBuilder.cloneFrom(assembled, { fee: (resourceFee + 2_000_000).toString() })
    .setSorobanData(sorobanData!)
    .build();
  finalTx.sign(feeKp);
  const sent = await server.sendTransaction(finalTx);
  if (sent.status === 'ERROR') return { fn, ok: false, denied: fn === 'clear', hash: sent.hash, reason: 'send error', sorobanData };
  const final = await poll(sent.hash);
  const ok = final.status === 'SUCCESS';
  return { fn, ok, denied: !ok && fn === 'clear', hash: sent.hash, reason: ok ? undefined : 'reverted in __check_auth (perch Denied)', sorobanData };
}

/** The three secp256r1 co-signers of the 2-of-3 account (deterministic seeds). */
const thresholdKeys = THRESHOLD.signers.map((s) => secp256r1Keypair(s.seed));

export interface ThresholdOutcome {
  keyCount: number;
  ok: boolean;
  denied: boolean;
  hash?: string;
  reason?: string;
  sorobanData?: xdr.SorobanTransactionData;
}

/**
 * Drive the 2-of-3 account's Default rule live: `post` signed by `keyCount` of
 * the three co-signers. `keyCount >= threshold` → the multisig policy passes;
 * fewer → it denies. Same proven flow as `invokeBoardCall`, but M assertions
 * over the one auth digest go into a single AuthPayload (`injectSignedAuthPayload`).
 * `reuseSorobanData` lets the below-threshold case borrow the passing footprint
 * so it still lands a real, cleanly-failed on-chain tx.
 */
export async function proveThreshold(
  feeKp: Keypair,
  keyCount: number,
  reuseSorobanData?: xdr.SorobanTransactionData,
  note: Progress = () => {},
): Promise<ThresholdOutcome> {
  const account = THRESHOLD.account;
  const message =
    keyCount >= THRESHOLD.threshold ? `${keyCount}-of-3 authorized this on-chain` : `${keyCount} signer is below the 2-of-3 threshold`;
  const op = Operation.invokeContractFunction({
    contract: CONTRACTS.board,
    function: 'post',
    args: [nativeToScVal(message, { type: 'string' }), Address.fromString(account).toScVal()],
  });

  note('Recording-simulating…');
  const src = await server.getAccount(feeKp.publicKey());
  const tx = new TransactionBuilder(src, { fee: (Number(BASE_FEE) * 100).toString(), networkPassphrase: NETWORK })
    .addOperation(op)
    .setTimeout(120)
    .build();
  const sim = await server.simulateTransaction(tx);
  if (rpc.Api.isSimulationError(sim)) return { keyCount, ok: false, denied: false, reason: `simulation: ${sim.error}` };

  const lastLedger = (await server.getLatestLedger()).sequence;
  const assembled = rpc.assembleTransaction(tx, sim).build();

  note(`Signing with ${keyCount} of 3 co-signers…`);
  const entry = (assembled.operations[0] as Operation.InvokeHostFunction).auth![0]!;
  const authDigest = computeAuthDigest(buildAuthHash(entry, NETWORK, lastLedger), [RULE_ID]);
  const signed = thresholdKeys.slice(0, keyCount).map((kp) => {
    const a = buildSyntheticAssertion(kp.secretKey, authDigest);
    return {
      kind: 'external' as const,
      verifierAddress: CONTRACTS.verifier,
      publicKey: kp.publicKey,
      passkeySignature: { authenticatorData: a.authenticatorData, clientDataJson: a.clientDataJSON, signature: a.signature },
    };
  });
  injectSignedAuthPayload(assembled, signed, lastLedger, undefined, [RULE_ID]);

  note('Enforcing re-simulation (runs __check_auth: multisig threshold on-chain)…');
  let sorobanData = reuseSorobanData;
  const sim2 = await server.simulateTransaction(assembled);
  if (rpc.Api.isSimulationError(sim2)) {
    const reason = thresholdReason(sim2.error);
    if (!reuseSorobanData) return { keyCount, ok: false, denied: true, reason };
  } else {
    sorobanData = sim2.transactionData.build();
  }
  const resourceFee = Number((sim2 as rpc.Api.SimulateTransactionSuccessResponse).minResourceFee ?? 0);

  note('Submitting to testnet…');
  const finalTx = TransactionBuilder.cloneFrom(assembled, { fee: (resourceFee + 2_000_000).toString() })
    .setSorobanData(sorobanData!)
    .build();
  finalTx.sign(feeKp);
  const sent = await server.sendTransaction(finalTx);
  const belowThreshold = keyCount < THRESHOLD.threshold;
  if (sent.status === 'ERROR') return { keyCount, ok: false, denied: belowThreshold, hash: sent.hash, reason: 'send error', sorobanData };
  const final = await poll(sent.hash);
  const ok = final.status === 'SUCCESS';
  return { keyCount, ok, denied: !ok && belowThreshold, hash: sent.hash, reason: ok ? undefined : 'reverted in __check_auth (threshold not met)', sorobanData };
}

function thresholdReason(err: string): string {
  if (/InvalidAction|Threshold|InsufficientSigners|Denied|Auth|#\d+/i.test(err))
    return 'multisig enforce → threshold not met (need 2 of 3 signatures)';
  return err.split('\n')[0] ?? err;
}

/** Map a raw enforcing-sim error to a human line — perch's Denied is contract error #1. */
function perchReason(err: string): string {
  if (/InvalidAction|Denied|#1\b|contract, code:? ?1|Auth/i.test(err))
    return 'perch enforce → Denied (function not in the policy’s allowed set)';
  return err.split('\n')[0] ?? err;
}
