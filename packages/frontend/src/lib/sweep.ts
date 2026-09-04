import { Networks, Operation, TransactionBuilder, nativeToScVal, Address, Contract, rpc, scValToNative } from "@stellar/stellar-sdk";
import type { i128, Spec } from "@stellar/stellar-sdk/contract";
import { Client as SmartAccountClient } from '@nidohq/smart-account';
import { NATIVE_SAC_ID, RELAYER_SIM_SOURCE, RELAYER_URL, NETWORK_PASSPHRASE } from "./network";
import { relayerSubmitAndConfirm } from "./signing/submit";
import { injectSignedAuthPayload } from "../../../passkey-sdk/dist/auth";
import { signatureExpirationOffset } from "./relayerClient";
const RPC_URL = "https://soroban-testnet.stellar.org";
// Operation, Address, Account, Keypair, nativeToScVal, rpc, xdr, hash, Contract, authorizeEntry } from "@stellar/stellar-sdk";

const DUMMY_CONTRACT_ID = 'CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4';
  let memoizedSmartAccountSpec: Spec | undefined;
  function smartAccountSpec(): Spec {
    memoizedSmartAccountSpec ??= new SmartAccountClient({
      contractId: DUMMY_CONTRACT_ID,
      networkPassphrase: NETWORK_PASSPHRASE,
      rpcUrl: RPC_URL,
    }).spec;
    return memoizedSmartAccountSpec!;
  }

// TODO(sponsored-reserves): this reserve carve-out only exists because G is
// friendbot-funded today and owns its own base reserve. Once G's reserves
// are covered by relayer sponsorship (beginSponsoringFutureReserves), G's
// balance can be swept to zero and this entire adjustment goes away.
const G_BASE_RESERVE_STROOPS = 1_0000000n; // 1 XLM, G has no subentries

export interface SweepReadiness {
  provisioned: boolean;
  hasFunds: boolean;
  sweepRuleId: number | null;
  allowanceGranted: boolean;
  gBalance: bigint;      // raw balance, including the reserve
  sweepableAmount: bigint; // gBalance minus the reserve — what can actually be swept
  gNeutralized: boolean | null;
}

async function findSweepRuleId(c: string): Promise<number | null> {
  const server = new rpc.Server(RPC_URL);
  const spec = smartAccountSpec();
  const sourceAccount = await server.getAccount(RELAYER_SIM_SOURCE);

  const countOp = new Contract(c).call("get_context_rules_count");
  const countTx = new TransactionBuilder(sourceAccount, {
    fee: "100",
    networkPassphrase: Networks.TESTNET,
  }).addOperation(countOp).setTimeout(0).build();

  const countSim = await server.simulateTransaction(countTx);
  if (rpc.Api.isSimulationError(countSim)) {
    throw new Error(`get_context_rules_count failed: ${countSim.error}`);
  }
  const count: number = spec.funcResToNative("get_context_rules_count", countSim.result!.retval);

  for (let id = 0; id < count; id++) {
    const scVals = spec.funcArgsToScVals("get_context_rule", { context_rule_id: id });
    const op = new Contract(c).call("get_context_rule", ...scVals);
    const tx = new TransactionBuilder(sourceAccount, {
      fee: "100",
      networkPassphrase: Networks.TESTNET,
    }).addOperation(op).setTimeout(0).build();

    const sim = await server.simulateTransaction(tx);
    if (rpc.Api.isSimulationError(sim)) continue;

    const rule = spec.funcResToNative("get_context_rule", sim.result!.retval);
    if (rule.context_type.tag === "CallContract" && rule.context_type.values[0] === NATIVE_SAC_ID) {
      return rule.id;
    }
  }
  return null;
}

async function getAllowance(g: string, c: string): Promise<bigint> {
  const server = new rpc.Server(RPC_URL);
  const sourceAccount = await server.getAccount(RELAYER_SIM_SOURCE);

  const op = Operation.invokeContractFunction({
    contract: NATIVE_SAC_ID,
    function: "allowance",
    args: [Address.fromString(g).toScVal(), Address.fromString(c).toScVal()],
  });

  const tx = new TransactionBuilder(sourceAccount, {
    fee: "100",
    networkPassphrase: Networks.TESTNET,
  }).addOperation(op).setTimeout(0).build();

  const sim = await server.simulateTransaction(tx);
  if (rpc.Api.isSimulationError(sim)) throw new Error(`allowance check failed: ${sim.error}`);
  return scValToNative(sim.result!.retval) as bigint;
}

async function getGBalance(g: string): Promise<bigint> {
  const server = new rpc.Server(RPC_URL);
  const sourceAccount = await server.getAccount(RELAYER_SIM_SOURCE);

  const op = Operation.invokeContractFunction({
    contract: NATIVE_SAC_ID,
    function: "balance",
    args: [Address.fromString(g).toScVal()],
  });

  const tx = new TransactionBuilder(sourceAccount, {
    fee: "100",
    networkPassphrase: Networks.TESTNET,
  }).addOperation(op).setTimeout(0).build();

  const sim = await server.simulateTransaction(tx);
  if (rpc.Api.isSimulationError(sim)) throw new Error(`balance check failed: ${sim.error}`);
  return scValToNative(sim.result!.retval) as bigint;
}

export async function readyToTriggerSweep(c: string, g: string): Promise<SweepReadiness> {
  const [sweepRuleId, allowance, gBalance] = await Promise.all([
    findSweepRuleId(c),
    getAllowance(g, c),
    getGBalance(g),
  ]);

  const allowanceGranted = allowance > 0n;
  const sweepableAmount = gBalance > G_BASE_RESERVE_STROOPS ? gBalance - G_BASE_RESERVE_STROOPS : 0n;

  return {
    provisioned: sweepRuleId !== null && allowanceGranted,
    hasFunds: sweepableAmount > 0n,
    sweepRuleId,
    allowanceGranted,
    gBalance,
    sweepableAmount,
    gNeutralized: null,
  };
}

export async function triggerSweep(c: string, g: string): Promise<string | null> {
  const ready = await readyToTriggerSweep(c, g);
  if (!ready.provisioned) {
    console.log("not provisioned yet, add a retry");
    return null;
  }
  if (!ready.hasFunds) {
    console.log("no sweepable funds in G yet (balance is at or below reserve)");
    return null;
  }

  const server = new rpc.Server(RPC_URL);
  const sourceAccount = await server.getAccount(RELAYER_SIM_SOURCE);
  const amount = ready.sweepableAmount;

  const op = Operation.invokeContractFunction({
    contract: NATIVE_SAC_ID,
    function: "transfer_from",
    args: [
      Address.fromString(c).toScVal(),
      Address.fromString(g).toScVal(),
      Address.fromString(c).toScVal(),
      nativeToScVal(amount, { type: "i128" }),
    ],
  });

  const simTx = new TransactionBuilder(sourceAccount, {
    fee: "10000000",
    networkPassphrase: Networks.TESTNET,
  }).addOperation(op).setTimeout(0).build();

  const sim = await server.simulateTransaction(simTx);
  if (rpc.Api.isSimulationError(sim)) {
    throw new Error(`Sweep simulation failed: ${sim.error}`);
  }

  const assembled = rpc.assembleTransaction(simTx, sim).build();

  injectSignedAuthPayload(
    assembled,
    [],
    sim.latestLedger,
    signatureExpirationOffset(),
    [ready.sweepRuleId!],
  );

  const result = await relayerSubmitAndConfirm(assembled);
  console.log("result ", result);
  return result.hash;
}