import {
  StrKey,
  xdr,
  hash,
  Address,
  Account,
  TransactionBuilder,
  Operation,
  rpc,
  Keypair,
} from "@stellar/stellar-sdk";
import type { NetworkConfig } from "./types.js";

/**
 * Compute the deterministic smart account address that the factory will deploy to.
 *
 * @param factoryContractId - The factory contract address
 * @param salt - The contract salt (SHA-256 of credential ID)
 * @param networkPassphrase - Stellar network passphrase
 */
export function computeAccountAddress(
  factoryContractId: string,
  salt: Buffer,
  networkPassphrase: string
): string {
  return StrKey.encodeContract(
    hash(
      xdr.HashIdPreimage.envelopeTypeContractId(
        new xdr.HashIdPreimageContractId({
          networkId: hash(Buffer.from(networkPassphrase, "utf-8")),
          contractIdPreimage:
            xdr.ContractIdPreimage.contractIdPreimageFromAddress(
              new xdr.ContractIdPreimageFromAddress({
                address: Address.fromString(factoryContractId).toScAddress(),
                salt,
              })
            ),
        })
      ).toXDR()
    )
  );
}

/**
 * Check if a smart account has already been deployed at the expected address.
 *
 * @param config - Network configuration
 * @param salt - The contract salt
 * @returns The contract address if it exists, or null
 */
export async function lookupExistingAccount(
  config: NetworkConfig,
  salt: Buffer
): Promise<string | null> {
  const server = new rpc.Server(config.rpcUrl);
  const address = computeAccountAddress(
    config.factoryContractId,
    salt,
    config.networkPassphrase
  );

  try {
    await server.getContractData(
      address,
      xdr.ScVal.scvLedgerKeyContractInstance()
    );
    return address;
  } catch {
    return null;
  }
}

/**
 * Deploy a new smart account via the factory contract.
 *
 * @param config - Network configuration
 * @param bundlerKeypair - Keypair that pays for the transaction
 * @param salt - The contract salt (SHA-256 of credential ID)
 * @param publicKey - 65-byte uncompressed P-256 public key
 * @returns The deployed contract address
 */
export async function deploySmartAccount(
  config: NetworkConfig,
  bundlerKeypair: Keypair,
  salt: Buffer,
  publicKey: Uint8Array
): Promise<string> {
  const server = new rpc.Server(config.rpcUrl);
  const expectedAddress = computeAccountAddress(
    config.factoryContractId,
    salt,
    config.networkPassphrase
  );

  const sourceAccount = await server
    .getAccount(bundlerKeypair.publicKey())
    .then((res: Account) => new Account(res.accountId(), res.sequenceNumber()));

  const simTxn = new TransactionBuilder(sourceAccount, {
    fee: "100",
    networkPassphrase: config.networkPassphrase,
  })
    .addOperation(
      Operation.invokeContractFunction({
        contract: config.factoryContractId,
        function: "deploy",
        args: [
          xdr.ScVal.scvBytes(salt),
          xdr.ScVal.scvBytes(Buffer.from(publicKey)),
        ],
      })
    )
    .setTimeout(0)
    .build();

  const sim = await server.simulateTransaction(simTxn);

  if (
    rpc.Api.isSimulationError(sim) ||
    rpc.Api.isSimulationRestore(sim)
  ) {
    throw sim;
  }

  const transaction = rpc.assembleTransaction(simTxn, sim)
    .setTimeout(0)
    .build();

  transaction.sign(bundlerKeypair);

  const response = await server.sendTransaction(transaction);

  if (response.status === "ERROR") {
    throw new Error(`Transaction submission failed: ${response.status}`);
  }

  // Poll for completion
  let getResponse = await server.getTransaction(response.hash);
  while (getResponse.status === "NOT_FOUND") {
    await new Promise((resolve) => setTimeout(resolve, 1000));
    getResponse = await server.getTransaction(response.hash);
  }

  if (getResponse.status === "SUCCESS") {
    return expectedAddress;
  }

  throw new Error(`Transaction failed: ${getResponse.status}`);
}
