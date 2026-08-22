// Diagnostic: what does recording simulation return as the account's auth tree
// for a perch-gated call? Does it include the nested interpreter.enforce
// sub-invocation (whose smart_account.require_auth must be satisfied)?
import { Address, BASE_FEE, Keypair, nativeToScVal, Networks, Operation, TransactionBuilder, rpc, xdr } from '@stellar/stellar-sdk';
import { execFileSync } from 'node:child_process';

const server = new rpc.Server('https://soroban-testnet.stellar.org');
const NET = Networks.TESTNET;
const BOARD = 'CBVXSCMALSZBF32OGUXIXFAFMPYFOJM4BOA27PBCMJPR6ZNUREX5ELWM';
const ACCOUNT = process.argv[2] ?? 'CAZSVYNP52AGK66S3XIAW6HJDFLMXHH3IQECRNCWKHSPIXKMD4RBNMPV';

function dumpInvocation(inv: xdr.SorobanAuthorizedInvocation, depth = 0): void {
  const pad = '  '.repeat(depth);
  const fn = inv.function();
  if (fn.switch().name === 'sorobanAuthorizedFunctionTypeContractFn') {
    const c = fn.contractFn();
    const addr = Address.fromScAddress(c.contractAddress()).toString();
    console.log(`${pad}• ${addr}.${c.functionName().toString()}(${c.args().length} args)`);
  } else {
    console.log(`${pad}• [create-contract]`);
  }
  for (const sub of inv.subInvocations()) dumpInvocation(sub, depth + 1);
}

async function main() {
  const src = Keypair.fromSecret(execFileSync('stellar', ['keys', 'show', 'perch-demo']).toString().trim());
  const op = Operation.invokeContractFunction({
    contract: BOARD,
    function: 'post',
    args: [nativeToScVal('diag', { type: 'string' }), Address.fromString(ACCOUNT).toScVal()],
  });
  const tx = new TransactionBuilder(await server.getAccount(src.publicKey()), { fee: (Number(BASE_FEE) * 100).toString(), networkPassphrase: NET })
    .addOperation(op).setTimeout(60).build();
  const sim = await server.simulateTransaction(tx);
  if (rpc.Api.isSimulationError(sim)) { console.log('SIM ERROR:', sim.error); return; }
  const auth = sim.result?.auth ?? [];
  console.log(`auth entries: ${auth.length}`);
  auth.forEach((e, i) => {
    const c = e.credentials();
    console.log(`\n[entry ${i}] credentials: ${c.switch().name}`);
    if (c.switch().name === 'sorobanCredentialsAddress') {
      console.log(`  address: ${Address.fromScAddress(c.address().address()).toString()}`);
    }
    console.log('  rootInvocation tree:');
    dumpInvocation(e.rootInvocation(), 2);
  });
}
main().catch((e) => { console.error(e); process.exit(1); });
