/**
 * Frontend action layer for ZK account recovery (M4). Mirrors the shape of
 * `recoveryActions.ts`: build via the SDK, submit via `relayerClient` when
 * available (else self-submit through an ephemeral funded G-address), stage
 * only NON-secret data in `localStorage` via the SDK's `overlay.ts`, and
 * resolve every contract address through `policyChainFetch.ts::
 * fetchRegistryAddress` — never hardcoded.
 *
 * Three call shapes, matching the controller's auth model
 * (`contracts/zk-recovery/src/controller.rs`):
 *
 *   - `initiate_recovery` is PERMISSIONLESS (no `require_auth` at all) — the
 *     entire security property is the ZK proof's `auth_hash` public input.
 *     Submission here needs no signer, only a funded fee-payer.
 *   - `cancel_recovery` / `burn_nullifier` require the recovering account's
 *     OWN passkey auth (rule 0) *plus* a fresh action=2/3 proof — these route
 *     through `primaryPasskeySigner.ts::signAndSubmit`, exactly like
 *     `recoveryActions.ts::installRecovery`.
 *   - The recovery *completion* (`add_context_rule` on the account itself) is
 *     authorized by a ZERO-signer `AuthPayload` selecting the account's
 *     zero-signer recovery rule (spec §3.1) — no passkey, no proof; the
 *     zk-recovery contract's own `Policy::enforce` is the sole authority,
 *     cross-called by the smart account's `__check_auth`. The SDK's
 *     `buildAuthPayloadScVal` refuses an empty signers map (by design, for
 *     the multisig-recovery flows that always need >=1 signer), so this
 *     module builds that one zero-signer payload directly.
 */
import { Buffer } from 'buffer';
import {
  rpc,
  Contract,
  TransactionBuilder,
  Address,
  StrKey,
  xdr,
  scValToNative,
  nativeToScVal,
  type Operation,
} from '@stellar/stellar-sdk';
import type { Spec } from '@stellar/stellar-sdk/contract';
import { Client as ZkRecoveryClient } from '@nidohq/zk-recovery';
import {
  wrapLeafInner,
  wrapLeafStored,
  computeNullifier,
  computeAuthHash,
  commitmentForCreation,
  mergeLeaves,
  verifyAgainstOnChainRoot,
  locateLeaf,
  buildInitiateRecovery,
  buildCancelRecovery,
  buildBurnNullifier,
  buildCompleteRecovery,
  stageRecovery,
  clearStaged,
  fieldToBytes32,
  bytesToFieldCanonical,
  split16,
  u256FromU64,
  getAuthEntry,
  buf2hex,
  type Fr,
  type Leaf,
  type TxBuild,
} from '@nidohq/passkey-sdk';
import { sha256 } from '@noble/hashes/sha2.js';
import { fetchRegistryAddress, simulateView } from './policyChainFetch.js';
import { signAndSubmit, getSubmitter } from './primaryPasskeySigner.js';
import { relayerEnabled, signatureExpirationOffset } from './relayerClient.js';
import { relayerSubmitAndConfirm, classicSubmitAndPoll } from './signing/submit.js';
import { RPC_URL, NETWORK_PASSPHRASE, RELAYER_SIM_SOURCE } from './network.js';
import { prove } from './zk/prover.js';
import type { NoirInputMap } from './zk/prover.worker.js';

/**
 * Testnet-only: `zk-recovery`'s deployed `delay_secs` (see the M4 plan's
 * Global Constraints / `DEPLOYED.md`). `initiate_recovery` requires
 * `timelock_secs` to match the contract's configured `delay_secs` EXACTLY
 * (`RecoveryError::TimelockMismatch` otherwise) — the controller exposes no
 * view for this, so it's pinned here rather than read on-chain. Mainnet will
 * need a much longer delay; keep this near the top so it's easy to find.
 */
const TESTNET_ZK_RECOVERY_DELAY_SECS = 60;

/** The zk_recovery circuit's public inputs: [root, nullifier, auth_hash]. The
 *  blob header MUST declare exactly this many (see assembleCircuitInputs). */
const ZK_PUBLIC_INPUT_COUNT = 3;

/**
 * The prover returns a blob `u32-BE(#pubs) ‖ pubs(32B each) ‖ proof`. The
 * on-chain `verify_proof` takes the RAW proof only (the public inputs are
 * passed separately and recomputed on-chain from the initiate args), so the
 * `proof` submitted to the controller must be the blob with its header +
 * public inputs stripped — otherwise the verifier parses the prepended bytes
 * as proof data and traps (`UnreachableCodeReached`).
 *
 * Validates the header rather than trusting it: an unwrapped/truncated/foreign
 * blob would otherwise read a garbage `nPubs`, `subarray` past the end (JS
 * clamps, never throws), and submit an EMPTY proof that only fails on-chain
 * after a full round-trip. Fail fast, in-app, with a clear error instead.
 */
function rawProofFromBlob(blob: Uint8Array): Uint8Array {
  const headerLen = 4 + ZK_PUBLIC_INPUT_COUNT * 32;
  if (blob.length < headerLen) {
    throw new Error(
      `recovery proof blob too short: ${blob.length} bytes < ${headerLen}-byte header ` +
        `(u32 count + ${ZK_PUBLIC_INPUT_COUNT} public inputs) — prover returned a malformed blob`,
    );
  }
  const nPubs = new DataView(blob.buffer, blob.byteOffset, 4).getUint32(0, false);
  if (nPubs !== ZK_PUBLIC_INPUT_COUNT) {
    throw new Error(
      `recovery proof blob declares ${nPubs} public inputs, expected ${ZK_PUBLIC_INPUT_COUNT} ` +
        `— blob is unwrapped or from a different circuit`,
    );
  }
  return blob.subarray(headerLen);
}

/**
 * Topic name for the pool's `LeafInserted` event
 * (`contracts/zk-recovery/src/types.rs::LeafInserted` --
 * `#[contractevent(topics = ["leaf_inserted"], data_format = "map")]`).
 */
const LEAF_INSERTED_EVENT_NAME = 'leaf_inserted';

const encoder = new TextEncoder();

// ===========================================================================
// Enrollment
// ===========================================================================

/** Thin wrapper: the `commitment` the creation flow submits as
 *  `create_account_v2(salt, key, commitment)`'s third argument. */
export function enrollAtCreation(secret: Fr): Uint8Array {
  return commitmentForCreation(secret);
}

const ZK_RECOVERY_SPEC_CONTRACT_ID = 'CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4';

// Dummy contract id -- we only need the embedded static `.spec`, never an RPC
// call (same trick as `passkey-sdk/src/zkRecovery/recovery.ts::zkRecoverySpec`).
let memoizedZkRecoverySpec: Spec | undefined;
function zkRecoverySpec(): Spec {
  memoizedZkRecoverySpec ??= new ZkRecoveryClient({
    contractId: ZK_RECOVERY_SPEC_CONTRACT_ID,
    networkPassphrase: NETWORK_PASSPHRASE,
    rpcUrl: RPC_URL,
  }).spec;
  return memoizedZkRecoverySpec;
}

/**
 * Builds the (unsubmitted) `insert_for` migration/re-enrollment operation via
 * the `@nidohq/zk-recovery` generated bindings' `Spec`. Caller is responsible
 * for submitting (the account's own auth is required on-chain — `insert_for`
 * calls `account.require_auth()` — so this mirrors `signAndSubmit`'s normal
 * primary-passkey flow, same as any other self-authorized rotation).
 */
export async function buildMigrationEnrollTx(account: string, secret: Fr): Promise<TxBuild> {
  const controllerId = await fetchRegistryAddress('zk-recovery');
  const commitment = commitmentForCreation(secret);
  const scVals = zkRecoverySpec().funcArgsToScVals('insert_for', {
    account,
    commitment: Buffer.from(commitment),
  });
  return {
    operations: [new Contract(controllerId).call('insert_for', ...scVals)],
    description: 'Enroll a new ZK-recovery secret',
  };
}

// ===========================================================================
// Trust-free pool sync
// ===========================================================================

function hexToBytes32(hex: string): Uint8Array {
  const s = hex.startsWith('0x') || hex.startsWith('0X') ? hex.slice(2) : hex;
  if (!/^[0-9a-fA-F]{64}$/.test(s)) {
    throw new Error(`hexToBytes32: expected a 0x-prefixed 32-byte hex string, got ${JSON.stringify(hex)}`);
  }
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return out;
}

async function fetchCurrentRootFr(controllerId: string): Promise<Fr> {
  const server = new rpc.Server(RPC_URL);
  const rv = await simulateView(server, new Contract(controllerId), 'current_root');
  const native = scValToNative(rv) as ArrayLike<number>;
  return bytesToFieldCanonical(new Uint8Array(native));
}

async function fetchNextNonce(controllerId: string, account: string): Promise<bigint> {
  const server = new rpc.Server(RPC_URL);
  const rv = await simulateView(
    server,
    new Contract(controllerId),
    'next_nonce',
    Address.fromString(account).toScVal(),
  );
  return BigInt(scValToNative(rv) as bigint | number | string);
}

export interface PoolWitness {
  index: number;
  siblings: Fr[];
  bits: number[];
  root: Fr;
}

/** Fetches the indexer's `{ leaves: [{index, leaf}] }` snapshot over HTTP.
 *  Only used when `PUBLIC_POOL_INDEXER_URL` is explicitly configured -- the
 *  default (unset) path is `fetchLeavesFromChain` below. */
async function fetchLeavesFromIndexer(indexerUrlRaw: string): Promise<Leaf[]> {
  const indexerUrl = indexerUrlRaw.replace(/\/+$/, '');
  const resp = await fetch(`${indexerUrl}/leaves`);
  if (!resp.ok) {
    throw new Error(`syncPoolAndLocate: pool-indexer fetch failed (HTTP ${resp.status})`);
  }
  const body = (await resp.json()) as { leaves: { index: number; leaf: string }[] };
  return body.leaves.map((l) => ({ index: l.index, leaf: hexToBytes32(l.leaf) }));
}

/**
 * Reads the pool's `LeafInserted` events
 * (`contracts/zk-recovery/src/types.rs::LeafInserted`) directly from chain
 * via `rpc.Server.getEvents` -- the default leaf source when no pool-indexer
 * is configured (see `syncPoolAndLocate`). Mirrors
 * `tests/e2e/testnet/zk-recovery.testnet.spec.ts::fetchPoolLeavesFromChain`
 * (same topic filter, same `data_format = "map"` decode of `{ leaf }`), used
 * here as the default availability path rather than only a test bypass --
 * this is what lets a freshly-deployed preview pool (no indexer instance at
 * all) be synced.
 *
 * `startLedger` is read from `getHealth()`'s own `oldestLedger` (the RPC
 * node's actual retention floor) rather than a guessed `latestLedger - N`
 * lookback constant -- this can never go "out of range" regardless of how
 * long ago the pool contract was deployed, and for a small pool (the preview
 * pool, or any fresh testnet deploy) it still comfortably fits in one
 * `getEvents` page.
 *
 * Pages on the response `cursor` until the cursor's ledger reaches the chain
 * tip (`latestLedger`). `getEvents` scans FORWARD in fixed ledger windows, so
 * from a far-back `startLedger` the early pages are empty (events cluster near
 * the tip) yet still advance the cursor -- an empty page is therefore NOT an
 * exhaustion signal, and the loop must run until the cursor catches up to the
 * tip, or a real pool's leaves are silently missed.
 *
 * This is convenience-only, exactly like the indexer path: the caller
 * (`syncPoolAndLocate`) always re-verifies the rebuilt root against the
 * contract's own on-chain `current_root` before trusting anything read here.
 */
export async function fetchLeavesFromChain(zkRecoveryAddress: string): Promise<Leaf[]> {
  const server = new rpc.Server(RPC_URL);
  const health = await server.getHealth();
  const startLedger = Math.max(1, health.oldestLedger);
  const eventNameXdr = nativeToScVal(LEAF_INSERTED_EVENT_NAME, { type: 'symbol' }).toXDR('base64');
  const filters: rpc.Api.EventFilter[] = [
    {
      type: 'contract',
      contractIds: [zkRecoveryAddress],
      topics: [[eventNameXdr, '*']],
    },
  ];

  const PAGE_LIMIT = 1000;
  // Hard cap so a misbehaving RPC (a cursor that never advances past the tip, a
  // non-numeric cursor that keeps returning events) can't spin forever on the
  // critical path of a user action. Generous: 1000 full pages is ~1M events.
  const MAX_PAGES = 1000;
  const leaves: Leaf[] = [];
  let cursor: string | undefined;
  let pages = 0;
  for (;;) {
    const response = cursor
      ? await server.getEvents({ filters, cursor, limit: PAGE_LIMIT })
      : await server.getEvents({ filters, startLedger, limit: PAGE_LIMIT });
    for (const ev of response.events) {
      if (ev.topic.length < 2) continue;
      const index = Number(scValToNative(ev.topic[1]));
      const data = scValToNative(ev.value) as { leaf?: ArrayLike<number> } | undefined;
      const leafBytes = data?.leaf;
      if (leafBytes == null || leafBytes.length !== 32) continue;
      leaves.push({ index, leaf: new Uint8Array(leafBytes) });
    }
    if (++pages >= MAX_PAGES) {
      throw new Error(
        `fetchLeavesFromChain: exceeded ${MAX_PAGES} getEvents pages for ${zkRecoveryAddress} — ` +
          'aborting to avoid an unbounded scan',
      );
    }
    // getEvents pages FORWARD through the ledger range in fixed windows: when
    // startLedger is far back, the early pages are EMPTY (events cluster near
    // the tip) yet still return a cursor. So an empty page is NOT exhaustion --
    // keep paging until the cursor's ledger catches up to the chain tip. The
    // real cursor is a TOID ("<toid>-<n>"); its ledger is the high 32 bits.
    if (!response.cursor) break;
    cursor = response.cursor;
    const toidStr = response.cursor.split('-')[0];
    if (/^\d+$/.test(toidStr)) {
      // Stop only once the cursor reached the tip AND the last page wasn't
      // limit-capped -- a FULL page whose cursor sits at the tip can still hide
      // more events in that same tip ledger (e.g. a bulk insert_for migration
      // emitting >PAGE_LIMIT leaf_inserted in one ledger), so keep paging until
      // a short page confirms exhaustion.
      if (
        Number(BigInt(toidStr) >> 32n) >= response.latestLedger &&
        response.events.length < PAGE_LIMIT
      ) {
        break;
      }
    } else if (response.events.length === 0) {
      // Non-TOID cursor (e.g. a test double): fall back to empty-page stop.
      break;
    }
  }
  leaves.sort((a, b) => a.index - b.index);
  return leaves;
}

/**
 * Fetches leaves (from an explicitly-configured pool-indexer, or -- by
 * default -- directly from chain), rebuilds the Merkle tree client-side, and
 * verifies the rebuilt root against the contract's OWN on-chain
 * `current_root` (resolved via the registry) -- TRUST-FREE either way: both
 * sources are convenience-only, and a mismatch is a hard error, never a
 * silent fallback.
 *
 * Source selection: `PUBLIC_POOL_INDEXER_URL` set explicitly -> that
 * indexer's `/leaves` HTTP endpoint; unset (the default, including every
 * PR-preview build) -> `fetchLeavesFromChain` against the resolved
 * (registry- or preview-overridden, see `policyChainFetch.ts`) zk-recovery
 * address. This is what lets the factory-v2 preview pool be recovered
 * against without a deployed indexer instance.
 *
 * Returns `null` if `myStoredLeaf` isn't present in a verified pool snapshot.
 */
export async function syncPoolAndLocate(
  account: string,
  myStoredLeaf: Uint8Array,
): Promise<PoolWitness | null> {
  void account; // the account is only needed by the caller to derive myStoredLeaf; kept for API symmetry.
  const controllerId = await fetchRegistryAddress('zk-recovery');
  const indexerUrlOverride = import.meta.env.PUBLIC_POOL_INDEXER_URL as string | undefined;

  const incoming: Leaf[] = indexerUrlOverride
    ? await fetchLeavesFromIndexer(indexerUrlOverride)
    : await fetchLeavesFromChain(controllerId);
  const merged = mergeLeaves([], incoming);

  const onChainRoot = await fetchCurrentRootFr(controllerId);

  if (!verifyAgainstOnChainRoot(merged, onChainRoot)) {
    throw new Error(
      "syncPoolAndLocate: rebuilt Merkle root does not match the contract's on-chain root -- " +
        'refusing to trust an unverified pool snapshot.',
    );
  }

  const located = locateLeaf(merged, myStoredLeaf);
  if (!located) return null;
  return { ...located, root: onChainRoot };
}

// ===========================================================================
// Circuit input assembly (shared by initiate/cancel/burn)
// ===========================================================================

/** Splits a 65-byte SEC1 uncompressed P-256 key into the circuit's pubkey
 *  fields, or all-zero fields for `null` (cancel/revoke, spec §2.4). */
function pubkeyFields(newPubkey65: Uint8Array | null): {
  pkPrefix: Fr;
  pkXHi: Fr;
  pkXLo: Fr;
  pkYHi: Fr;
  pkYLo: Fr;
} {
  if (newPubkey65 === null) {
    return { pkPrefix: 0n, pkXHi: 0n, pkXLo: 0n, pkYHi: 0n, pkYLo: 0n };
  }
  if (newPubkey65.length !== 65) {
    throw new Error(`pubkeyFields: expected a 65-byte SEC1 uncompressed pubkey, got ${newPubkey65.length}`);
  }
  const pkPrefix = u256FromU64(newPubkey65[0]);
  const [pkXHi, pkXLo] = split16(newPubkey65.subarray(1, 33));
  const [pkYHi, pkYLo] = split16(newPubkey65.subarray(33, 65));
  return { pkPrefix, pkXHi, pkXLo, pkYHi, pkYLo };
}

/** BE-encodes a canonical field element as a `0x`-prefixed hex string --
 *  the Noir input encoding `circuits/zk_recovery/Prover.toml` uses. */
function frToNoirField(x: Fr): string {
  return '0x' + x.toString(16);
}

interface AssembleInputsArgs {
  action: 1 | 2 | 3;
  accountId32: Uint8Array;
  controllerId32: Uint8Array;
  secret: Fr;
  root: Fr;
  siblings: Fr[];
  bits: number[];
  nullifier: Fr;
  newPubkey65: Uint8Array | null;
  nonce: bigint;
  timelockSecs: number;
}

/**
 * Assembles the `zk_recovery` circuit's full Noir input map
 * (`circuits/zk_recovery/src/main.nr`'s `main` signature, field-for-field)
 * plus the `auth_hash` public input the circuit itself recomputes and
 * asserts against. Both are derived from the SAME exported SDK primitives
 * (`split16`/`sha256`/`u256FromU64`/`computeAuthHash`) `authHash.ts` uses
 * internally, so the two can never silently disagree.
 */
function assembleCircuitInputs(a: AssembleInputsArgs): { inputs: NoirInputMap; authHash: Fr } {
  const [acctHi, acctLo] = split16(a.accountId32);
  const [ctrlHi, ctrlLo] = split16(a.controllerId32);
  const [npassHi, npassLo] = split16(sha256(encoder.encode(NETWORK_PASSPHRASE)));
  const { pkPrefix, pkXHi, pkXLo, pkYHi, pkYLo } = pubkeyFields(a.newPubkey65);

  const authHash = computeAuthHash({
    action: a.action,
    accountId32: a.accountId32,
    networkPassphrase: NETWORK_PASSPHRASE,
    controllerId32: a.controllerId32,
    newPubkey65: a.newPubkey65,
    nonce: a.nonce,
    timelockSecs: a.timelockSecs,
  });

  const inputs: NoirInputMap = {
    root: frToNoirField(a.root),
    nullifier: frToNoirField(a.nullifier),
    auth_hash: frToNoirField(authHash),
    secret: frToNoirField(a.secret),
    acct_hi: frToNoirField(acctHi),
    acct_lo: frToNoirField(acctLo),
    path_siblings: a.siblings.map(frToNoirField),
    path_bits: a.bits.map((b) => frToNoirField(BigInt(b))),
    action: frToNoirField(BigInt(a.action)),
    npass_hi: frToNoirField(npassHi),
    npass_lo: frToNoirField(npassLo),
    ctrl_hi: frToNoirField(ctrlHi),
    ctrl_lo: frToNoirField(ctrlLo),
    pk_prefix: frToNoirField(pkPrefix),
    pk_x_hi: frToNoirField(pkXHi),
    pk_x_lo: frToNoirField(pkXLo),
    pk_y_hi: frToNoirField(pkYHi),
    pk_y_lo: frToNoirField(pkYLo),
    nonce: frToNoirField(a.nonce),
    timelock_secs: frToNoirField(BigInt(a.timelockSecs)),
  };
  return { inputs, authHash };
}

// ===========================================================================
// Permissionless submission (initiate_recovery -- no require_auth at all)
// ===========================================================================

async function submitPermissionlessOp(
  operation: xdr.Operation,
): Promise<{ hash: string; retval: xdr.ScVal | undefined }> {
  const server = new rpc.Server(RPC_URL);
  const useRelayer = relayerEnabled();
  if (useRelayer && !RELAYER_SIM_SOURCE) {
    throw new Error('Relayer misconfigured: PUBLIC_RELAYER_URL is set but PUBLIC_RELAYER_SIM_SOURCE is not.');
  }
  const submitter = useRelayer ? null : await getSubmitter();
  const sourceAccount = submitter
    ? await server.getAccount(submitter.publicKey())
    : await server.getAccount(RELAYER_SIM_SOURCE);

  // Recording-mode simulation needs a fresh (unsigned) op -- there is no auth
  // to strip here (permissionless), but cloning keeps this symmetric with
  // every other build/simulate/submit path in this codebase.
  const opClone = xdr.Operation.fromXDR(operation.toXDR());
  const simTx = new TransactionBuilder(sourceAccount, {
    fee: '10000000',
    networkPassphrase: NETWORK_PASSPHRASE,
  })
    .addOperation(opClone)
    .setTimeout(0)
    .build();

  const sim = await server.simulateTransaction(simTx);
  if (rpc.Api.isSimulationError(sim)) {
    throw new Error(`Simulation failed: ${(sim as rpc.Api.SimulateTransactionErrorResponse).error}`);
  }
  const successSim = sim as rpc.Api.SimulateTransactionSuccessResponse;
  const retval = successSim.result?.retval;

  const assembled = rpc.assembleTransaction(simTx, successSim).build();

  if (useRelayer) {
    const { hash } = await relayerSubmitAndConfirm(assembled);
    return { hash, retval };
  }
  if (!submitter) throw new Error('unreachable: classic path without submitter');
  const sendResult = await classicSubmitAndPoll(assembled, submitter, server);
  return { hash: sendResult.hash, retval };
}

// ===========================================================================
// initiate_recovery
// ===========================================================================

export interface InitiateZkRecoveryArgs {
  account: string;
  /** The recovery secret (already derived via M1/M2 -- this module never derives it). */
  secret: Fr;
  /** 65-byte SEC1 uncompressed P-256 key the recovery will install. */
  newPubkey65: Uint8Array;
}

export interface InitiateZkRecoveryResult {
  txHash: string;
  executableAfter: number;
}

export async function initiateZkRecovery(
  args: InitiateZkRecoveryArgs,
): Promise<InitiateZkRecoveryResult> {
  const { account, secret, newPubkey65 } = args;
  if (newPubkey65.length !== 65) {
    throw new Error(`initiateZkRecovery: newPubkey65 must be 65 bytes, got ${newPubkey65.length}`);
  }

  const controllerId = await fetchRegistryAddress('zk-recovery');
  const accountId32 = StrKey.decodeContract(account);
  const controllerId32 = StrKey.decodeContract(controllerId);

  const storedLeaf = wrapLeafStored(accountId32, wrapLeafInner(secret));
  const located = await syncPoolAndLocate(account, fieldToBytes32(storedLeaf));
  if (!located) {
    throw new Error(
      "initiateZkRecovery: this account's enrollment leaf was not found in the recovery pool.",
    );
  }

  const nonce = await fetchNextNonce(controllerId, account);
  const nullifierFr = computeNullifier(accountId32, secret);

  const { inputs } = assembleCircuitInputs({
    action: 1,
    accountId32,
    controllerId32,
    secret,
    root: located.root,
    siblings: located.siblings,
    bits: located.bits,
    nullifier: nullifierFr,
    newPubkey65,
    nonce,
    timelockSecs: TESTNET_ZK_RECOVERY_DELAY_SECS,
  });

  const { blob } = await prove('zk_recovery', inputs);

  const built = buildInitiateRecovery({
    controllerId,
    account,
    nonce,
    root: fieldToBytes32(located.root),
    nullifier: fieldToBytes32(nullifierFr),
    proof: rawProofFromBlob(blob),
    newPubkey65,
    timelockSecs: TESTNET_ZK_RECOVERY_DELAY_SECS,
  });

  const { hash, retval } = await submitPermissionlessOp(built.operations[0]);
  const executableAfter = retval ? Number(scValToNative(retval)) : 0;

  // Advisory only (SDK overlay.ts) -- NO secrets: just the (public) new
  // pubkey and plain timestamps.
  stageRecovery(account, {
    newPubkey65Hex: buf2hex(newPubkey65),
    initiatedAt: Math.floor(Date.now() / 1000),
    executableAfter,
  });

  return { txHash: hash, executableAfter };
}

// ===========================================================================
// cancel_recovery / burn_nullifier -- owner's passkey auth + a fresh proof
// ===========================================================================

export interface CancelZkRecoveryArgs {
  account: string;
  secret: Fr;
}

async function buildOwnerAuthedProofTx(
  action: 2 | 3,
  args: { account: string; secret: Fr },
): Promise<{ controllerId: string; account: string; nonce: bigint; root: Uint8Array; nullifier: Uint8Array; proof: Uint8Array }> {
  const { account, secret } = args;
  const controllerId = await fetchRegistryAddress('zk-recovery');
  const accountId32 = StrKey.decodeContract(account);
  const controllerId32 = StrKey.decodeContract(controllerId);

  const storedLeaf = wrapLeafStored(accountId32, wrapLeafInner(secret));
  const located = await syncPoolAndLocate(account, fieldToBytes32(storedLeaf));
  if (!located) {
    throw new Error("this account's enrollment leaf was not found in the recovery pool.");
  }

  const nonce = await fetchNextNonce(controllerId, account);
  const nullifierFr = computeNullifier(accountId32, secret);

  // Cancel/revoke proofs ZERO the pubkey/timelock fields (spec §2.4) -- a
  // cancel/revoke proves "I authorize stopping/killing this", not "install
  // this key".
  const { inputs } = assembleCircuitInputs({
    action,
    accountId32,
    controllerId32,
    secret,
    root: located.root,
    siblings: located.siblings,
    bits: located.bits,
    nullifier: nullifierFr,
    newPubkey65: null,
    nonce,
    timelockSecs: 0,
  });

  const { blob } = await prove('zk_recovery', inputs);

  return {
    controllerId,
    account,
    nonce,
    root: fieldToBytes32(located.root),
    nullifier: fieldToBytes32(nullifierFr),
    proof: rawProofFromBlob(blob),
  };
}

/** Stops a pending recovery during its timelock. Requires the account's own
 *  (still-live) primary passkey -- exactly what an attacker who only knows a
 *  leaked enrollment secret cannot provide. Releases (does not burn) the
 *  nullifier reservation. */
export async function cancelZkRecovery(args: CancelZkRecoveryArgs): Promise<string> {
  const proofArgs = await buildOwnerAuthedProofTx(2, args);
  const built = buildCancelRecovery(proofArgs);
  const result = await signAndSubmit({ account: args.account, operation: built.operations[0] });
  clearStaged(args.account);
  return result.hash;
}

export interface BurnZkNullifierArgs {
  account: string;
  secret: Fr;
}

/** Permanently spends a (possibly leaked) enrollment secret's nullifier, so
 *  it can never be used to initiate recovery again -- requires the account's
 *  own primary passkey plus a fresh action=3 proof of secret-knowledge. */
export async function burnZkNullifier(args: BurnZkNullifierArgs): Promise<string> {
  const proofArgs = await buildOwnerAuthedProofTx(3, args);
  const built = buildBurnNullifier(proofArgs);
  const result = await signAndSubmit({ account: args.account, operation: built.operations[0] });
  clearStaged(args.account);
  return result.hash;
}

// ===========================================================================
// Recovery completion -- zero-signer AuthPayload (no passkey, no proof)
// ===========================================================================

/**
 * Builds the OZ v0.7 `AuthPayload { context_rule_ids, signers: {} }` ScVal
 * with an EMPTY signers map -- the SDK's `buildAuthPayloadScVal` refuses this
 * on purpose (every multisig-recovery caller needs >=1 real signer), but the
 * zk-recovery completion rule is deliberately zero-signer (spec §3.1): the
 * account's `__check_auth` has nothing to check per-signer for this rule, and
 * authorization comes entirely from the attached `Policy::enforce` cross-call
 * (this contract's own pending/timelock/context checks).
 */
export function zeroSignerAuthPayloadScVal(contextRuleIds: readonly number[]): xdr.ScVal {
  const contextRuleIdsVec = xdr.ScVal.scvVec(contextRuleIds.map((id) => xdr.ScVal.scvU32(id)));
  return xdr.ScVal.scvMap([
    new xdr.ScMapEntry({ key: xdr.ScVal.scvSymbol('context_rule_ids'), val: contextRuleIdsVec }),
    new xdr.ScMapEntry({ key: xdr.ScVal.scvSymbol('signers'), val: xdr.ScVal.scvMap([]) }),
  ]);
}

export interface CompleteZkRecoveryArgs {
  /** The recovering smart account -- also the target of this direct self-call. */
  account: string;
  /** The account's zero-signer `zk-recovery` rule id (spec §3.1). */
  recoveryRuleId: number;
  /** 65-byte SEC1 uncompressed P-256 key that matured through `initiate_recovery`. */
  newPubkey65: Uint8Array;
  /** WebAuthn verifier contract address the new signer is registered against. */
  webauthnVerifierId: string;
}

/**
 * Permissionless completion: installs the recovered passkey as a brand-new
 * Default rule, authorized purely by the zero-signer recovery rule's
 * attached `zk-recovery` policy (its `enforce` checks the pending record's
 * timelock + the exact shape of this call). No WebAuthn ceremony -- anyone
 * (the account owner, a relayer, a friend) may submit this once matured.
 */
export async function completeZkRecovery(args: CompleteZkRecoveryArgs): Promise<string> {
  const built = buildCompleteRecovery(args);
  const hash = await submitZeroSignerCompletion(built.operations[0], built.contextRuleIds);
  clearStaged(args.account);
  return hash;
}

async function submitZeroSignerCompletion(
  operation: xdr.Operation,
  contextRuleIds: readonly number[],
): Promise<string> {
  const server = new rpc.Server(RPC_URL);
  const useRelayer = relayerEnabled();
  if (useRelayer && !RELAYER_SIM_SOURCE) {
    throw new Error('Relayer misconfigured: PUBLIC_RELAYER_URL is set but PUBLIC_RELAYER_SIM_SOURCE is not.');
  }
  const submitter = useRelayer ? null : await getSubmitter();
  const sourceAccount = submitter
    ? await server.getAccount(submitter.publicKey())
    : await server.getAccount(RELAYER_SIM_SOURCE);

  // Strip any auth template so recording-mode simulation generates one fresh
  // (same rationale as `primaryPasskeySigner.ts::signAndSubmit`).
  const opClone = xdr.Operation.fromXDR(operation.toXDR());
  opClone.body().invokeHostFunctionOp().auth([]);
  const simTx = new TransactionBuilder(sourceAccount, {
    fee: '10000000',
    networkPassphrase: NETWORK_PASSPHRASE,
  })
    .addOperation(opClone)
    .setTimeout(0)
    .build();

  const sim = await server.simulateTransaction(simTx);
  if (rpc.Api.isSimulationError(sim)) {
    throw new Error(`Simulation failed: ${(sim as rpc.Api.SimulateTransactionErrorResponse).error}`);
  }
  const successSim = sim as rpc.Api.SimulateTransactionSuccessResponse;
  // Confirms the simulator actually produced an auth-entry template for this
  // self-call before we bother assembling -- a clearer error than the
  // post-assemble injection check below would give.
  getAuthEntry(successSim);
  const lastLedger = successSim.latestLedger;

  const assembled = rpc.assembleTransaction(simTx, successSim).build();

  // Replace the assembled auth entry's signature with the zero-signer
  // AuthPayload -- mirrors `injectSignedAuthPayload`'s XDR round-trip
  // (clone-and-replace, not in-place mutation; see its comment for why).
  const op = assembled.operations[0] as Operation.InvokeHostFunction;
  if (!op.auth || op.auth.length === 0) {
    throw new Error('submitZeroSignerCompletion: no authorization entry in the assembled transaction');
  }
  const signedEntry = xdr.SorobanAuthorizationEntry.fromXDR(op.auth[0].toXDR());
  const creds = signedEntry.credentials().address();
  const expirationOffset = signatureExpirationOffset(useRelayer);
  creds.signatureExpirationLedger(lastLedger + expirationOffset);
  creds.signature(zeroSignerAuthPayloadScVal(contextRuleIds));
  (op.auth as xdr.SorobanAuthorizationEntry[])[0] = signedEntry;

  if (useRelayer) {
    const { hash } = await relayerSubmitAndConfirm(assembled);
    return hash;
  }
  if (!submitter) throw new Error('unreachable: classic path without submitter');
  const sendResult = await classicSubmitAndPoll(assembled, submitter, server);
  return sendResult.hash;
}

// ===========================================================================
// Pending read
// ===========================================================================

export interface ZkPending {
  executableAfter: number;
  expiresAt: number;
  /** The 65-byte SEC1-uncompressed P-256 pubkey staged by `initiate_recovery`
   *  (`PendingRecovery::new_pubkey`), read straight from on-chain state. Lets
   *  recovery completion work even if this device's local staging record
   *  (`readStaged`) was cleared, or this is a different device than the one
   *  that started the recovery. */
  newPubkey65: Uint8Array;
}

/** Reads the controller's `get_pending(account)` view. `null` if none (the
 *  contract's `Option<PendingRecovery>` decodes to `undefined` when absent). */
export async function getZkPending(account: string): Promise<ZkPending | null> {
  const controllerId = await fetchRegistryAddress('zk-recovery');
  const server = new rpc.Server(RPC_URL);
  const rv = await simulateView(
    server,
    new Contract(controllerId),
    'get_pending',
    Address.fromString(account).toScVal(),
  );
  const native = scValToNative(rv) as
    | {
        new_pubkey?: ArrayLike<number>;
        executable_after?: bigint | number;
        expires_at?: bigint | number;
      }
    | undefined;
  if (native == null) return null;
  return {
    executableAfter: Number(native.executable_after ?? 0),
    expiresAt: Number(native.expires_at ?? 0),
    newPubkey65: new Uint8Array(native.new_pubkey ?? []),
  };
}

// Re-exported so callers of this module don't need a second import from the
// SDK just to read the advisory staged-recovery record.
export { readStaged, clearStaged } from '@nidohq/passkey-sdk';
