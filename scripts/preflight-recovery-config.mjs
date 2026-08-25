#!/usr/bin/env node
// Mainnet PREFLIGHT go/no-go gate for blocker A1: read a LIVE zk-recovery
// pool's immutable config on-chain and assert it matches the production spec
// BEFORE any account is created against it.
//
// Why this exists: the pool's RecoveryConfig (delay / completion-window /
// timelock-floor / network passphrase / bound verifier+factory) is set once at
// construction and is IMMUTABLE (contracts/zk-recovery/src/pool.rs). The live
// testnet pool was built with a 60s delay, 0s floor, and 7d window -- all wrong
// for mainnet, where the spec is delay 14d / floor 7d / window 30d. A 60s
// recovery timelock on mainnet means any account with a leaked passkey is
// stealable in ~a minute. Because the config can't be fixed after deploy, a
// misconfigured pool has to be caught here, pre-launch, not later.
//
// This script simulates the pool's read-only `config()` view (added for exactly
// this purpose) and exits NON-ZERO on any mismatch, so it can gate a mainnet
// cutover in CI or a runbook step.
//
// Usage:
//   node scripts/preflight-recovery-config.mjs \
//     --contract C...            # the deployed zk-recovery pool to check
//     [--rpc https://...]        # Soroban RPC (default: mainnet public RPC)
//     [--passphrase "Public Global Stellar Network ; September 2015"]
//     [--delay 1209600] [--window 2592000] [--floor 604800]
//     [--expect-factory C...] [--expect-verifier C...] [--expect-webauthn C...]
//
// All --delay/--window/--floor default to the mainnet spec; pass overrides only
// for a deliberately-different deployment (e.g. asserting a staging pool).
import {
  rpc, Contract, TransactionBuilder, Account, Networks, scValToNative,
} from '@stellar/stellar-sdk';

function arg(name, def) {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 ? process.argv[i + 1] : def;
}

const MAINNET_PASSPHRASE = 'Public Global Stellar Network ; September 2015';
const DEFAULT_RPC = 'https://mainnet.sorobanrpc.com';
const DUMMY_SOURCE = 'GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF';

// Production spec (§3.3 "Defaults"): 14d timelock, 30d completion window, 7d
// floor. Kept here as the go/no-go target; overridable via flags.
const SPEC = {
  delay_secs: BigInt(arg('delay', '1209600')), // 14 days
  completion_window_secs: BigInt(arg('window', '2592000')), // 30 days
  timelock_floor_secs: BigInt(arg('floor', '604800')), // 7 days
};

const contract = arg('contract');
if (!contract || !contract.startsWith('C')) {
  console.error('ERROR: --contract C... (the zk-recovery pool address) is required');
  process.exit(2);
}
const rpcUrl = arg('rpc', DEFAULT_RPC);
const expectedPassphrase = arg('passphrase', MAINNET_PASSPHRASE);
const expectFactory = arg('expect-factory');
const expectVerifier = arg('expect-verifier');
const expectWebauthn = arg('expect-webauthn');

const server = new rpc.Server(rpcUrl);
const pool = new Contract(contract);
const source = new Account(DUMMY_SOURCE, '0');
const tx = new TransactionBuilder(source, { fee: '100', networkPassphrase: expectedPassphrase })
  .addOperation(pool.call('config'))
  .setTimeout(30)
  .build();

const sim = await server.simulateTransaction(tx);
if (rpc.Api.isSimulationError(sim)) {
  console.error(`ERROR: simulate config() on ${contract} failed: ${sim.error}`);
  console.error('(Is --contract a zk-recovery pool that has the config() view? Pre-A1 pools predate it.)');
  process.exit(2);
}
if (!sim.result) {
  console.error('ERROR: config() returned no value');
  process.exit(2);
}

const cfg = scValToNative(sim.result.retval);
// network_passphrase comes back as Bytes -> Uint8Array; decode to a string.
const passphrase = Buffer.from(cfg.network_passphrase).toString('utf8');

// Collect every check so the operator sees the FULL diff in one shot, rather
// than fixing one mismatch and re-running to find the next.
const checks = [
  ['delay_secs', BigInt(cfg.delay_secs), SPEC.delay_secs],
  ['completion_window_secs', BigInt(cfg.completion_window_secs), SPEC.completion_window_secs],
  ['timelock_floor_secs', BigInt(cfg.timelock_floor_secs), SPEC.timelock_floor_secs],
  ['network_passphrase', passphrase, expectedPassphrase],
];
if (expectFactory) checks.push(['factory', cfg.factory, expectFactory]);
if (expectVerifier) checks.push(['verifier', cfg.verifier, expectVerifier]);
if (expectWebauthn) checks.push(['webauthn_verifier', cfg.webauthn_verifier, expectWebauthn]);

console.error(`Preflight: zk-recovery pool ${contract}`);
console.error(`  RPC ${rpcUrl}`);
let failed = 0;
for (const [name, actual, expected] of checks) {
  const ok = String(actual) === String(expected);
  if (!ok) failed += 1;
  console.error(`  ${ok ? 'OK  ' : 'FAIL'} ${name}: ${actual}${ok ? '' : `  (expected ${expected})`}`);
}
// max_cancels is informational (spec allows 2-3); print it but don't gate.
console.error(`  --   max_cancels: ${cfg.max_cancels} (informational)`);

if (failed > 0) {
  console.error(`\nNO-GO: ${failed} config field(s) do not match the production spec. Do NOT create accounts against this pool.`);
  process.exit(1);
}
console.error('\nGO: pool config matches the production spec.');
console.log(contract);
