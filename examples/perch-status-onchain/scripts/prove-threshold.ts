/**
 * Deploy a 2-of-3 (M-of-N) Nido smart account to testnet and PROVE, on-chain,
 * that the multisig policy enforces the threshold:
 *
 *   account (Default rule, id 0)
 *     signers: owner, backup, treasury  (3 × secp256r1, local keys)
 *     policy:  nido multisig-policy, SimpleThresholdAccountParams { threshold: 2 }
 *
 *   post(_, author=account) signed by 2 keys → 2-of-3 met  → tx succeeds
 *   post(_, author=account) signed by 1 key  → threshold   → tx fails (Denied)
 *
 * The multi-signer ceremony puts M assertions over the SAME auth digest into one
 * AuthPayload (`injectSignedAuthPayload`). Everything is @stellar/stellar-sdk +
 * @nidohq/{testkit,passkey-sdk} against public testnet RPC; source = `perch-demo`.
 *
 * Run:  npx tsx examples/perch-status-onchain/scripts/prove-threshold.ts
 */
import { execFileSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  Address,
  BASE_FEE,
  Keypair,
  nativeToScVal,
  Networks,
  Operation,
  TransactionBuilder,
  rpc,
  xdr,
} from '@stellar/stellar-sdk';
import { secp256r1Keypair, buildSyntheticAssertion, computeAuthDigest, deriveAccountAddress } from '@nidohq/testkit';
import { buildAuthHash, injectSignedAuthPayload } from '@nidohq/passkey-sdk';

const RPC_URL = 'https://soroban-testnet.stellar.org';
const NET = Networks.TESTNET;
const BOARD = 'CBVXSCMALSZBF32OGUXIXFAFMPYFOJM4BOA27PBCMJPR6ZNUREX5ELWM';
const VERIFIER = 'CACVGSAHYFBXY4LJKWW5B57LAAXHCZVDZOANUTYPLNV6HHQI4Q35EGMY';
const ACCOUNT_WASM_HASH = '5bb9f585fa7d1485c3252ff00a521b1247ab71d57436fbc8c8b8e4a0ff010afb';
const MULTISIG = 'CCSDKJYOFCPTCCGQZPF73RJNHFC7TPO532Q36N3M2VBYZFWQOTDB7J7G';
const SOURCE_ALIAS = process.env.SOURCE_ALIAS ?? 'perch-demo';
const OUT = process.env.OUT ?? join(process.cwd(), 'examples/perch-status-onchain/src/thresholdProof.json');

const server = new rpc.Server(RPC_URL);

// The 2-of-3 signer set: deterministic keys → a stable, reproducible account.
const SIGNERS = [
  { id: 'owner', kp: secp256r1Keypair(new Uint8Array(32).fill(11)) },
  { id: 'backup', kp: secp256r1Keypair(new Uint8Array(32).fill(12)) },
  { id: 'treasury', kp: secp256r1Keypair(new Uint8Array(32).fill(13)) },
];
const THRESHOLD = 2;
const SALT = new Uint8Array(32).fill(87); // #87 — the M-of-N issue

function sourceKeypair(): Keypair {
  return Keypair.fromSecret(execFileSync('stellar', ['keys', 'show', SOURCE_ALIAS]).toString().trim());
}

function externalSigner(pubkey: Uint8Array): xdr.ScVal {
  return xdr.ScVal.scvVec([
    xdr.ScVal.scvSymbol('External'),
    Address.fromString(VERIFIER).toScVal(),
    xdr.ScVal.scvBytes(Buffer.from(pubkey)),
  ]);
}

/** `SimpleThresholdAccountParams { threshold }` as its ScVal (struct → symbol map). */
function thresholdInstall(threshold: number): xdr.ScVal {
  return xdr.ScVal.scvMap([
    new xdr.ScMapEntry({ key: xdr.ScVal.scvSymbol('threshold'), val: xdr.ScVal.scvU32(threshold) }),
  ]);
}

async function submit(tx: Awaited<ReturnType<typeof server.prepareTransaction>>, kp: Keypair, label: string) {
  tx.sign(kp);
  const sent = await server.sendTransaction(tx);
  if (sent.status === 'ERROR') {
    return { ok: false, hash: sent.hash, status: 'SEND_ERROR' as const };
  }
  const final = await server.pollTransaction(sent.hash, { attempts: 20, sleepStrategy: () => 2000 });
  return { ok: final.status === 'SUCCESS', hash: sent.hash, status: final.status, final };
}

async function accountExists(addr: string): Promise<boolean> {
  try {
    return !!(await server.getContractData(addr, xdr.ScVal.scvLedgerKeyContractInstance()));
  } catch {
    return false;
  }
}

async function deployAccount(): Promise<string> {
  const kp = sourceKeypair();
  const derived = deriveAccountAddress(kp.publicKey(), SALT, NET);
  if (await accountExists(derived)) {
    console.log(`  reusing existing 2-of-3 account: ${derived}`);
    return derived;
  }
  const signers = xdr.ScVal.scvVec(SIGNERS.map((s) => externalSigner(s.kp.publicKey)));
  const policies = xdr.ScVal.scvMap([
    new xdr.ScMapEntry({ key: Address.fromString(MULTISIG).toScVal(), val: thresholdInstall(THRESHOLD) }),
  ]);
  const op = Operation.createCustomContract({
    address: Address.fromString(kp.publicKey()),
    wasmHash: Buffer.from(ACCOUNT_WASM_HASH, 'hex'),
    constructorArgs: [signers, policies, xdr.ScVal.scvVoid()],
    salt: Buffer.from(SALT),
  });
  const tx = new TransactionBuilder(await server.getAccount(kp.publicKey()), { fee: BASE_FEE, networkPassphrase: NET })
    .addOperation(op)
    .setTimeout(60)
    .build();
  const res = await submit(await server.prepareTransaction(tx), kp, 'deploy');
  if (!res.ok) throw new Error(`account deploy failed: ${JSON.stringify(res)}`);
  const addr = Address.fromScVal((res.final as rpc.Api.GetSuccessfulTransactionResponse).returnValue!).toString();
  console.log(`  deployed 2-of-3 account: ${addr}  (tx ${res.hash})`);
  return addr;
}

/** Invoke `post` as the account, signing the default-rule auth digest with `keys`. */
async function postSignedBy(
  account: string,
  message: string,
  keys: { publicKey: Uint8Array; secretKey: Uint8Array }[],
  reuse?: xdr.SorobanTransactionData,
) {
  const kp = sourceKeypair();
  const op = Operation.invokeContractFunction({
    contract: BOARD,
    function: 'post',
    args: [nativeToScVal(message, { type: 'string' }), Address.fromString(account).toScVal()],
  });
  const tx = new TransactionBuilder(await server.getAccount(kp.publicKey()), {
    fee: (Number(BASE_FEE) * 100).toString(),
    networkPassphrase: NET,
  })
    .addOperation(op)
    .setTimeout(120)
    .build();

  const sim = await server.simulateTransaction(tx);
  if (rpc.Api.isSimulationError(sim)) return { ok: false, error: `record-sim: ${sim.error}` };
  const lastLedger = (await server.getLatestLedger()).sequence;
  const assembled = rpc.assembleTransaction(tx, sim).build();

  // M assertions over the one auth digest → one AuthPayload.
  const entry = (assembled.operations[0] as Operation.InvokeHostFunction).auth![0];
  const authDigest = computeAuthDigest(buildAuthHash(entry, NET, lastLedger), [0]);
  const signed = keys.map((k) => {
    const a = buildSyntheticAssertion(k.secretKey, authDigest);
    return {
      kind: 'external' as const,
      verifierAddress: VERIFIER,
      publicKey: k.publicKey,
      passkeySignature: { authenticatorData: a.authenticatorData, clientDataJson: a.clientDataJSON, signature: a.signature },
    };
  });
  injectSignedAuthPayload(assembled, signed, lastLedger, undefined, [0]);

  // Enforcing re-simulation runs __check_auth (multisig enforce over the threshold).
  let sorobanData = reuse;
  const sim2 = await server.simulateTransaction(assembled);
  if (rpc.Api.isSimulationError(sim2)) {
    const denied = /Denied|Threshold|UnauthorizedSigner|InsufficientSigners|#\d+/.test(sim2.error);
    console.log(`  post signed by ${keys.length} → ${denied ? 'DENIED (threshold)' : 'error'}: ${sim2.error.split('\n')[0]}`);
    if (!reuse) return { ok: false, denied, error: sim2.error };
  } else {
    sorobanData = sim2.transactionData.build();
  }
  const resourceFee = Number((sim2 as rpc.Api.SimulateTransactionSuccessResponse).minResourceFee ?? 0);
  const finalTx = TransactionBuilder.cloneFrom(assembled, { fee: (resourceFee + 2_000_000).toString() })
    .setSorobanData(sorobanData!)
    .build();
  const res = await submit(finalTx, kp, `post/${keys.length}`);
  return { ok: res.ok, hash: res.hash, status: res.status, sorobanData };
}

async function main() {
  console.log('▶ deploying 2-of-3 account (multisig policy, threshold=2)…');
  const account = await deployAccount();

  console.log('▶ MEETS threshold: post signed by owner + backup (2 of 3)');
  const two = await postSignedBy(account, '2-of-3 authorized this on-chain', [SIGNERS[0].kp, SIGNERS[1].kp]);
  console.log(`  → ${two.ok ? 'ALLOWED ✓' : 'denied ✕'} ${two.hash ?? ''} ${two.error ?? ''}`);

  console.log('▶ BELOW threshold: post signed by owner only (1 of 3)');
  const one = await postSignedBy(account, 'one signer should not pass', [SIGNERS[0].kp], two.sorobanData);
  console.log(`  → ${one.ok ? 'ALLOWED (unexpected!) ✗' : 'DENIED ✓'} ${one.hash ?? ''} ${one.status ?? ''}`);

  const verdict = two.ok && !one.ok;
  const proof = {
    account,
    board: BOARD,
    multisig: MULTISIG,
    verifier: VERIFIER,
    threshold: THRESHOLD,
    signerCount: SIGNERS.length,
    met: { hash: two.hash, ok: two.ok },
    below: { hash: one.hash, ok: one.ok, status: one.status },
    verdict,
  };
  writeFileSync(OUT, JSON.stringify(proof, null, 2) + '\n');
  console.log(`\n${verdict ? '✅ PROVEN' : '❌ NOT proven'}: 2-of-3 ${verdict ? 'passed with 2 sigs and was denied with 1' : 'did not behave as expected'}`);
  console.log(`  wrote ${OUT}`);
  process.exit(verdict ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
