/**
 * Submit strategies extracted from signAndSubmit.
 *
 * - relayerSubmitAndConfirm: ships {func, auth} to the Channels relayer and
 *   polls until confirmed. Skips enforce re-sim (Channels does it server-side).
 * - classicSubmitAndPoll: enforce re-sim + fee refit + sign + RPC send + poll.
 */
import { rpc, TransactionBuilder, Networks, Keypair, xdr } from "@stellar/stellar-sdk";
import type { Transaction } from "@stellar/stellar-sdk";
import {
  type RelayerStatus,
  extractFuncAndAuth,
  submitXdrTransaction,
  submitSorobanTransaction,
  waitForConfirmation,
} from "../relayerClient";
import { RELAYER_URL } from "../network";

export { type RelayerStatus };

export async function relayerSubmitAndConfirm(
  signedTx: Transaction,
  opts?: {
    onPoll?: (info: {
      status: RelayerStatus | null;
      attempt: number;
      maxAttempts: number;
    }) => void;
    baseUrl?: string;
  },
): Promise<{ hash: string }> {
  const baseUrl = opts?.baseUrl ?? RELAYER_URL;
  const { func, auth } = extractFuncAndAuth(signedTx);
  if (auth.length > 1) {
    throw new Error(
      `Expected a single auth entry, got ${auth.length} — only the first is passkey-signed.`,
    );
  }
  const submitted = await submitSorobanTransaction({ func, auth }, baseUrl);
  if (!submitted.transactionId) {
    throw new Error("Relayer accepted the transaction but returned no transaction id");
  }
  const confirmed = await waitForConfirmation(submitted.transactionId, baseUrl, {
    onPoll: opts?.onPoll,
  });
  if (!confirmed.hash) throw new Error("Relayer confirmed without a transaction hash");
  return { hash: confirmed.hash };
}

export async function classicSubmitAndPoll(
  assembledTx: Transaction,
  submitter: Keypair,
  server: rpc.Server,
): Promise<rpc.Api.SendTransactionResponse> {
  // Re-simulate in ENFORCE mode — verifies the auth and recomputes the
  // resource footprint to cover __check_auth's reads.
  const final_sim = await server.simulateTransaction(assembledTx, undefined, "enforce");
  if (rpc.Api.isSimulationError(final_sim)) {
    throw new Error(
      `Final simulation failed: ${(final_sim as rpc.Api.SimulateTransactionErrorResponse).error}`,
    );
  }
  const successFinalSim = final_sim as rpc.Api.SimulateTransactionSuccessResponse;
  const newSorobanData = successFinalSim.transactionData.build();
  const newResourceFee = BigInt(newSorobanData.resourceFee().toString());
  const classicFee =
    BigInt(assembledTx.fee) -
    BigInt(
      (
        assembledTx
          .toEnvelope()
          .v1()
          .tx()
          .ext()
          .value() as xdr.SorobanTransactionData | undefined
      )
        ?.resourceFee()
        .toString() ?? "0",
    );
  const refittedBuilder = TransactionBuilder.cloneFrom(assembledTx, {
    fee: (classicFee + newResourceFee).toString(),
    sorobanData: newSorobanData,
    networkPassphrase: Networks.TESTNET,
  });
  // cloneFrom carries operations across as-is (including the signed auth
  // entries on our InvokeHostFunction op). build() emits a new Transaction
  // with the right footprint AND our signature intact.
  const refitted_tx = refittedBuilder.build();
  refitted_tx.sign(submitter);
  const sendResult = await server.sendTransaction(refitted_tx);
  if (sendResult.status === "ERROR") {
    const detail = sendResult.errorResult?.toXDR("base64") ?? "unknown";
    throw new Error(`Submit rejected: ${detail}`);
  }
  if (sendResult.status === "DUPLICATE" || sendResult.status === "TRY_AGAIN_LATER") {
    throw new Error(`Submit ${sendResult.status}: ${sendResult.hash}`);
  }
  // PENDING — poll until we see SUCCESS or FAILED.
  let getResult = await server.getTransaction(sendResult.hash);
  for (let i = 0; getResult.status === "NOT_FOUND" && i < 30; i++) {
    await new Promise((r) => setTimeout(r, 1500));
    getResult = await server.getTransaction(sendResult.hash);
  }
  if (getResult.status !== "SUCCESS") {
    throw new Error(`Tx ${sendResult.hash} ${getResult.status}`);
  }
  return sendResult;
}
