#!/usr/bin/env node
// Deploy zk-recovery (and, when --verifier absent, zk-verifier) by building the
// create-contract-with-constructor operation directly via @stellar/stellar-sdk.
// stellar-cli 26.0.0 fails ("Missing Entry Context") on constructors that take
// contract-Address arguments; the SDK path does not. Targets testnet by
// default; `--mainnet` (or an explicit mainnet --passphrase) switches network,
// RPC, and the recovery params to the production spec and enables the safety
// guard below.
//
// Testnet usage:
//   DEPLOY_SECRET=$(stellar keys show ci-publisher-testnet) \
//   node scripts/deploy-zk-recovery.mjs \
//     --wasm target/wasm32v1-none/contract/nido_zk_recovery.wasm \
//     --factory C... --verifier C... --webauthn C... --admin C... \
//     --delay 60 --window 604800 --max-cancels 2 --floor 0 \
//     --passphrase "Test SDF Network ; September 2015"
//
// Mainnet usage (params default to spec 14d/30d/7d; --admin REQUIRED):
//   DEPLOY_SECRET=$(...) node scripts/deploy-zk-recovery.mjs --mainnet \
//     --wasm ... --factory C... --verifier C... --webauthn C... \
//     --admin <MULTISIG_C_ADDRESS>
//   # then verify: node scripts/preflight-recovery-config.mjs --contract <NEW_POOL>
//
// --admin is the upgrade/rotate governance key (issue #26); on mainnet this
// MUST be a multisig (ideally behind an upgrade timelock), NOT the deployer.
// Defaults to the deployer's own address when omitted (testnet convenience).
import { readFileSync } from 'node:fs';
import { randomBytes, createHash } from 'node:crypto';
import {
  Keypair, TransactionBuilder, Operation, Address, xdr, nativeToScVal, rpc,
} from '@stellar/stellar-sdk';

function arg(name, def) {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 ? process.argv[i + 1] : def;
}

const MAINNET_PASSPHRASE = 'Public Global Stellar Network ; September 2015';
const TESTNET_PASSPHRASE = 'Test SDF Network ; September 2015';

// `--mainnet` flips every default to the production spec (§3.3): 14d delay,
// 30d completion window, 7d floor, the public network passphrase + RPC. Pass
// it (or set the values explicitly) for a real cutover; omit for testnet.
const mainnet = process.argv.includes('--mainnet');

const secret = process.env.DEPLOY_SECRET?.trim();
if (!secret || !secret.startsWith('S')) { console.error('DEPLOY_SECRET (S...) required'); process.exit(1); }

const wasmPath = arg('wasm');
const factory = arg('factory');
const verifier = arg('verifier');
const webauthn = arg('webauthn');
// Governance admin for upgrade()/set_admin (issue #26). Defaults to the
// deployer for testnet; REQUIRED (and must be a multisig) on mainnet -- see
// the mainnet guard below.
const admin = arg('admin');
const passphrase = arg('passphrase', mainnet ? MAINNET_PASSPHRASE : TESTNET_PASSPHRASE);
const RPC = arg('rpc', mainnet ? 'https://mainnet.sorobanrpc.com' : 'https://soroban-testnet.stellar.org');
const delay = BigInt(arg('delay', mainnet ? '1209600' : '60')); // 14d vs 60s
const window = BigInt(arg('window', mainnet ? '2592000' : '604800')); // 30d vs 7d
const maxCancels = Number(arg('max-cancels', '2'));
const floor = BigInt(arg('floor', mainnet ? '604800' : '0')); // 7d vs 0

// Mainnet safety guard (blocker A1): the RecoveryConfig is IMMUTABLE, so a
// testnet-tuned pool on mainnet (60s delay, 0s floor) can never be fixed and
// makes every leaked-passkey account stealable in minutes. This fires whenever
// the target network is mainnet -- keyed on the passphrase, so it also catches
// a hand-passed `--passphrase <mainnet>` without `--mainnet`. Verify against
// scripts/preflight-recovery-config.mjs after deploy.
if (passphrase === MAINNET_PASSPHRASE) {
  const problems = [];
  if (!admin) problems.push('--admin is REQUIRED on mainnet (a multisig, not the deployer; issue #26)');
  if (delay < 86400n) problems.push(`--delay ${delay}s is below the 1-day safety floor (spec: 14d = 1209600s)`);
  if (floor < 86400n) problems.push(`--floor ${floor}s is below the 1-day safety floor (spec: 7d = 604800s)`);
  if (window < 604800n) problems.push(`--window ${window}s is below the 7-day safety floor (spec: 30d = 2592000s)`);
  if (problems.length) {
    console.error('MAINNET GUARD refused deploy:');
    for (const p of problems) console.error(`  - ${p}`);
    console.error('Set the production values (or --mainnet) before deploying to the public network.');
    process.exit(1);
  }
}

const server = new rpc.Server(RPC);
const kp = Keypair.fromSecret(secret);
const wasmBytes = readFileSync(wasmPath);
const wasmHash = createHash('sha256').update(wasmBytes).digest();
console.error(`wasm ${wasmPath} sha256=${wasmHash.toString('hex')}`);

const ctorArgs = [
  new Address(factory).toScVal(),
  new Address(verifier).toScVal(),
  nativeToScVal(delay, { type: 'u64' }),
  nativeToScVal(window, { type: 'u64' }),
  nativeToScVal(maxCancels, { type: 'u32' }),
  nativeToScVal(floor, { type: 'u64' }),
  xdr.ScVal.scvBytes(Buffer.from(passphrase, 'utf8')),
  new Address(webauthn).toScVal(),
  new Address(admin ?? kp.publicKey()).toScVal(),
];

const source = await server.getAccount(kp.publicKey());
const op = Operation.createCustomContract({
  address: Address.fromString(kp.publicKey()),
  wasmHash,
  salt: randomBytes(32),
  constructorArgs: ctorArgs,
});
const tx = new TransactionBuilder(source, { fee: '10000000', networkPassphrase: passphrase })
  .addOperation(op).setTimeout(120).build();

const sim = await server.simulateTransaction(tx);
if (rpc.Api.isSimulationError(sim)) { console.error('SIM ERROR:', sim.error); process.exit(1); }
const prepared = rpc.assembleTransaction(tx, sim).build();
prepared.sign(kp);
const sent = await server.sendTransaction(prepared);
console.error('sent', sent.hash, sent.status);
let get = await server.getTransaction(sent.hash);
for (let i = 0; i < 30 && get.status === 'NOT_FOUND'; i++) {
  await new Promise((r) => setTimeout(r, 2000));
  get = await server.getTransaction(sent.hash);
}
if (get.status !== 'SUCCESS') { console.error('TX FAILED', get.status, JSON.stringify(get.resultXdr)); process.exit(1); }
// The created contract address is the return value of createContract.
const addr = Address.fromScVal(get.returnValue).toString();
console.log(addr);
