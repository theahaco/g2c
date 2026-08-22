/**
 * Deploy a perch-governed Nido smart account to testnet and PROVE, on-chain,
 * that perch allows an in-policy call and denies an out-of-policy one.
 *
 *   account (Default rule, id 0)
 *     signer:  poster  (secp256r1 / real webauthn-verifier, driven by a LOCAL key)
 *     policy:  perch interpreter, program = FnIn{post} ∧ arg[1]=self ∧ MinSigners≥1
 *
 *   post("gm", author=account)  → perch ALLOW  → tx succeeds
 *   clear(author=account)       → perch DENY   → tx fails in __check_auth
 *
 * The RPN lowering is Rust-only, so the perch program is compiled by the
 * `perch-plan` CLI (perch repo) and dropped in as an InstallParams ScVal — the
 * exact bytes the chain enforces. Everything else is @stellar/stellar-sdk +
 * @nidohq/{testkit,passkey-sdk} against public testnet RPC.
 *
 * Run:  npx tsx examples/perch-status-onchain/scripts/deploy-and-prove.ts
 */
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
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
import { buildAuthHash, injectPasskeySignature } from '@nidohq/passkey-sdk';

// ---- deployed testnet pieces (see scratchpad/deployed.json) ----
const RPC_URL = 'https://soroban-testnet.stellar.org';
const NET = Networks.TESTNET;
const INTERP = 'CBO4FIGR2LP242IKWDME6NPFGCFAT5R7CSLKYLOOJFVXCCIGKVF6O44G';
const INTERP_WASM_HASH = 'd0f93aacc9a19c4d29a46f61d1e602caa0f4779adcebb4c5b618d090b2fd24de';
const BOARD = 'CBVXSCMALSZBF32OGUXIXFAFMPYFOJM4BOA27PBCMJPR6ZNUREX5ELWM';
const VERIFIER = 'CACVGSAHYFBXY4LJKWW5B57LAAXHCZVDZOANUTYPLNV6HHQI4Q35EGMY';
const ACCOUNT_WASM_HASH = '5bb9f585fa7d1485c3252ff00a521b1247ab71d57436fbc8c8b8e4a0ff010afb';
const PERCH_CLI_DIR = process.env.PERCH_DIR ?? '/Users/willem/c/stellar-registry/perch-testnet';
const SOURCE_ALIAS = process.env.SOURCE_ALIAS ?? 'perch-demo';

const server = new rpc.Server(RPC_URL);
const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');

// Deterministic poster key so the deployed account is stable/reproducible.
const poster = secp256r1Keypair(new Uint8Array(32).fill(7));
const SALT = new Uint8Array(32).fill(42);

function sourceKeypair(): Keypair {
  const secret = execFileSync('stellar', ['keys', 'show', SOURCE_ALIAS]).toString().trim();
  return Keypair.fromSecret(secret);
}

/** Compile the demo PolicyDoc → InstallParams XDR via the perch-plan CLI. */
function compilePolicy(): { installXdr: string; docHash: string } {
  const doc = {
    version: 1,
    network: NET,
    signers: [{ id: 'poster', verifier: VERIFIER, key: hex(poster.publicKey) }],
    rules: [
      {
        name: 'poster-can-post',
        scope: { type: 'contract', address: BOARD },
        principals: { type: 'all', signers: ['poster'] },
        functions: ['post'],
        args: [{ index: 1, pred: { type: 'is-self' } }],
      },
    ],
  };
  const dir = mkdtempSync(join(tmpdir(), 'perch-doc-'));
  const docPath = join(dir, 'doc.json');
  writeFileSync(docPath, JSON.stringify(doc, null, 2));
  const out = execFileSync('cargo', ['run', '-q', '-p', 'perch-plan-cli', '--', docPath, INTERP_WASM_HASH], {
    cwd: PERCH_CLI_DIR,
  }).toString();
  const plan = JSON.parse(out);
  const rule = plan.rules[0];
  if (!rule.install_xdr) throw new Error('expected an interpreter-attached rule');
  return { installXdr: rule.install_xdr, docHash: plan.doc_hash };
}

/** Signer::External(verifier, pubkey) as an ScVal Vec[Symbol, Address, Bytes]. */
function externalSigner(verifier: string, pubkey: Uint8Array): xdr.ScVal {
  return xdr.ScVal.scvVec([
    xdr.ScVal.scvSymbol('External'),
    Address.fromString(verifier).toScVal(),
    xdr.ScVal.scvBytes(Buffer.from(pubkey)),
  ]);
}

async function loadSource(kp: Keypair) {
  return server.getAccount(kp.publicKey());
}

async function submit(tx: Awaited<ReturnType<typeof server.prepareTransaction>>, kp: Keypair, label: string) {
  tx.sign(kp);
  const sent = await server.sendTransaction(tx);
  if (sent.status === 'ERROR') {
    console.log(`  ${label}: send ERROR`, JSON.stringify(sent.errorResult?.result?.() ?? sent));
    return { ok: false, hash: sent.hash, detail: 'send-error' as const };
  }
  const final = await server.pollTransaction(sent.hash, { attempts: 15, sleepStrategy: () => 2000 });
  return { ok: final.status === 'SUCCESS', hash: sent.hash, status: final.status, final };
}

async function accountExists(addr: string): Promise<boolean> {
  try {
    const r = await server.getContractData(addr, xdr.ScVal.scvLedgerKeyContractInstance());
    return !!r;
  } catch {
    return false;
  }
}

async function deployAccount(installXdr: string): Promise<string> {
  const kp = sourceKeypair();
  // Deterministic address (createCustomContract derives contract-id from the
  // deployer address + salt, identical to the factory's deployer+salt scheme).
  const derived = deriveAccountAddress(kp.publicKey(), Buffer.from(SALT), NET);
  if (await accountExists(derived)) {
    console.log(`  reusing existing account: ${derived}`);
    return derived;
  }
  const signers = xdr.ScVal.scvVec([externalSigner(VERIFIER, poster.publicKey)]);
  const policies = xdr.ScVal.scvMap([
    new xdr.ScMapEntry({
      key: Address.fromString(INTERP).toScVal(),
      val: xdr.ScVal.fromXDR(installXdr, 'hex'),
    }),
  ]);
  const recovery = xdr.ScVal.scvVoid(); // Option::None
  const op = Operation.createCustomContract({
    address: Address.fromString(kp.publicKey()),
    wasmHash: Buffer.from(ACCOUNT_WASM_HASH, 'hex'),
    constructorArgs: [signers, policies, recovery],
    salt: Buffer.from(SALT),
  });
  const tx = new TransactionBuilder(await loadSource(kp), { fee: BASE_FEE, networkPassphrase: NET })
    .addOperation(op)
    .setTimeout(60)
    .build();
  const prepared = await server.prepareTransaction(tx);
  const res = await submit(prepared, kp, 'deploy');
  if (!res.ok) throw new Error(`account deploy failed: ${JSON.stringify(res)}`);
  const rv = (res.final as rpc.Api.GetSuccessfulTransactionResponse).returnValue!;
  const addr = Address.fromScVal(rv).toString();
  console.log(`  deployed account: ${addr}  (tx ${res.hash})`);
  return addr;
}

interface InvokeResult {
  ok: boolean;
  denied?: boolean;
  hash?: string;
  status?: string;
  error?: string;
  sorobanData?: xdr.SorobanTransactionData;
}

/**
 * Build → recording-simulate → sign the account's auth entry → RE-simulate the
 * SIGNED tx (enforcing mode runs __check_auth: verifier.verify + perch enforce,
 * capturing their footprint the recording pass omits) → submit with that
 * footprint. `reuseSorobanData` lets the deny case borrow the allow case's
 * footprint (same ledger keys) so a rejected call still submits a real,
 * cleanly-Denied on-chain tx instead of tripping ExceededLimit.
 */
async function invokeAsAccount(
  account: string,
  fn: 'post' | 'clear',
  message: string | null,
  reuseSorobanData?: xdr.SorobanTransactionData,
): Promise<InvokeResult> {
  const kp = sourceKeypair();
  const args =
    fn === 'post'
      ? [nativeToScVal(message ?? '', { type: 'string' }), Address.fromString(account).toScVal()]
      : [Address.fromString(account).toScVal()];
  const op = Operation.invokeContractFunction({ contract: BOARD, function: fn, args });
  const tx = new TransactionBuilder(await loadSource(kp), { fee: (Number(BASE_FEE) * 100).toString(), networkPassphrase: NET })
    .addOperation(op)
    .setTimeout(120)
    .build();

  const sim = await server.simulateTransaction(tx);
  if (rpc.Api.isSimulationError(sim)) return { ok: false, error: `record-sim: ${sim.error}` };
  const lastLedger = (await server.getLatestLedger()).sequence;
  const assembled = rpc.assembleTransaction(tx, sim).build();

  // Sign the account's auth entry with the poster key.
  const entry = (assembled.operations[0] as Operation.InvokeHostFunction).auth![0];
  const authDigest = computeAuthDigest(buildAuthHash(entry, NET, lastLedger), [0]);
  const a = buildSyntheticAssertion(poster.secretKey, authDigest);
  injectPasskeySignature(
    assembled,
    { authenticatorData: a.authenticatorData, clientDataJson: a.clientDataJSON, signature: a.signature },
    VERIFIER,
    poster.publicKey,
    lastLedger,
    undefined,
    [0],
  );

  // Enforcing re-simulation: runs __check_auth for real. Success → correct
  // footprint; error → the account rejected it (for `clear`, that's perch).
  let sorobanData = reuseSorobanData;
  const sim2 = await server.simulateTransaction(assembled);
  if (rpc.Api.isSimulationError(sim2)) {
    const denied = /Denied|UnauthorizedSigner|InvalidAction|#\d+/.test(sim2.error);
    console.log(`  ${fn}: enforcing __check_auth → ${denied ? 'DENIED by account/policy' : 'error'}: ${sim2.error.split('\n')[0]}`);
    if (!reuseSorobanData) return { ok: false, denied, error: sim2.error };
    // else: submit anyway with the borrowed footprint to land a real failed tx.
  } else {
    sorobanData = sim2.transactionData.build();
  }

  const resourceFee = Number((sim2 as rpc.Api.SimulateTransactionSuccessResponse).minResourceFee ?? 0);
  // Clone the signed tx (preserves the op's injected AuthPayload) but swap in the
  // enforcing footprint + a fee that covers the real resource cost.
  const finalTx = TransactionBuilder.cloneFrom(assembled, { fee: (resourceFee + 2_000_000).toString() })
    .setSorobanData(sorobanData!)
    .build();
  const res = await submit(finalTx, kp, fn);
  return { ok: res.ok, hash: res.hash, status: res.status, sorobanData };
}

async function main() {
  console.log('▶ compiling perch policy (Rust perch-plan CLI)…');
  const { installXdr, docHash } = compilePolicy();
  console.log(`  doc_hash ${docHash}`);
  console.log(`  install_xdr ${installXdr.length / 2} bytes`);

  console.log('▶ deploying perch-governed account…');
  const account = await deployAccount(installXdr);

  console.log('▶ ALLOW case: poster.post("gm on-chain", self)');
  const allow = await invokeAsAccount(account, 'post', 'gm on-chain via perch');
  console.log(`  → ${allow.ok ? 'ALLOWED ✓' : 'denied ✕'} ${allow.hash ?? ''} ${allow.error ?? ''}`);

  console.log('▶ DENY case: poster.clear(self)  [perch FnIn{post} should refuse]');
  const deny = await invokeAsAccount(account, 'clear', null, allow.sorobanData);
  console.log(`  → ${deny.ok ? 'ALLOWED (unexpected!) ✗' : 'DENIED ✓'} ${deny.hash ?? ''} ${deny.status ?? ''}`);

  const verdict = allow.ok && !deny.ok;
  console.log(`\n${verdict ? '✅ PROVEN' : '❌ NOT proven'}: perch ${verdict ? 'allowed post and denied clear on-chain' : 'did not behave as expected'}`);
  writeFileSync(
    join(PERCH_CLI_DIR, '..', 'perch-onchain-proof.json'),
    JSON.stringify(
      { account, board: BOARD, interpreter: INTERP, docHash, allow: { ...allow, sorobanData: undefined }, deny: { ...deny, sorobanData: undefined }, verdict },
      null,
      2,
    ),
  );
  process.exit(verdict ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
