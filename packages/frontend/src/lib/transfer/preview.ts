import { Networks, TransactionBuilder, rpc, xdr } from "@stellar/stellar-sdk";
import { RPC_URL, RELAYER_SIM_SOURCE } from "../network.js";
import { getSubmitter } from "../primaryPasskeySigner.js";
import { relayerEnabled } from "../relayerClient.js";

export type PreviewResult =
  | { ok: true; resourceFee: bigint }
  | { ok: false; error: string };

/**
 * Recording-mode simulation of an operation against the smart account, WITHOUT
 * the passkey ceremony — used by the transfer review step to (a) validate the
 * transfer will actually land before we prompt for the passkey (catching an
 * insufficient balance / bad recipient up front, instead of after a wasted
 * Face-ID prompt) and (b) surface the network fee.
 *
 * The operation must carry no auth entries (`buildSendOperation` builds it
 * fresh), so the simulator generates them in recording mode — exactly what
 * `signAndSubmit`'s first pass does. This is read-only: it never consumes the
 * submitter's sequence or submits anything, so it is safe to call repeatedly.
 */
export async function previewOperation(args: {
  operation: xdr.Operation;
  rpcUrl?: string;
}): Promise<PreviewResult> {
  try {
    const server = new rpc.Server(args.rpcUrl ?? RPC_URL);
    // Recording-mode simulation just needs SOME existing on-chain source
    // account (it never signs, pays, or consumes sequence). In relayer mode use
    // the relayer's public fund address — mirroring signAndSubmit — so no
    // ephemeral G is friendbot-funded or persisted as `nido:name-keypair`. This
    // also unbreaks the preview on mainnet: getSubmitter's friendbot funding is
    // testnet-only and would throw on the public network. Classic mode
    // (relayer disabled) keeps the friendbot-funded ephemeral submitter.
    if (relayerEnabled() && !RELAYER_SIM_SOURCE) {
      return {
        ok: false,
        error: "Relayer misconfigured: PUBLIC_RELAYER_URL is set but PUBLIC_RELAYER_SIM_SOURCE is not.",
      };
    }
    const submitter = relayerEnabled() ? null : await getSubmitter();
    const source = submitter
      ? await server.getAccount(submitter.publicKey())
      : await server.getAccount(RELAYER_SIM_SOURCE);
    const tx = new TransactionBuilder(source, {
      fee: "10000000",
      networkPassphrase: Networks.TESTNET,
    })
      .addOperation(args.operation)
      .setTimeout(0)
      .build();

    const sim = await server.simulateTransaction(tx);
    if (rpc.Api.isSimulationError(sim)) {
      return { ok: false, error: (sim as rpc.Api.SimulateTransactionErrorResponse).error };
    }
    const success = sim as rpc.Api.SimulateTransactionSuccessResponse;
    const resourceFee = success.transactionData
      ? BigInt(success.transactionData.build().resourceFee().toString())
      : 0n;
    return { ok: true, resourceFee };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : String(e) };
  }
}
