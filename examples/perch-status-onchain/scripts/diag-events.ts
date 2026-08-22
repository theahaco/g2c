// Fetch the diagnostic events of a (failed) testnet tx to see exactly which
// contract panicked and why — verifier reject vs interpreter C1/C4/Denied.
import { rpc, scValToNative, xdr } from '@stellar/stellar-sdk';
const server = new rpc.Server('https://soroban-testnet.stellar.org');

async function main() {
  const hash = process.argv[2];
  if (!hash) throw new Error('usage: diag-events <txhash>');
  const tx = await server.getTransaction(hash);
  console.log(`status: ${tx.status}`);
  const anyTx = tx as unknown as { resultMetaXdr?: xdr.TransactionMeta; diagnosticEventsXdr?: xdr.DiagnosticEvent[]; returnValue?: xdr.ScVal };
  // Newer SDKs expose diagnosticEventsXdr directly on failed txs.
  const raw = (tx as unknown as { diagnosticEventsXdr?: unknown }).diagnosticEventsXdr as xdr.DiagnosticEvent[] | undefined;
  const events = raw ?? [];
  console.log(`diagnostic events: ${events.length}`);
  for (const ev of events) {
    try {
      const e = ev.event();
      const body = e.body().v0();
      const topics = body.topics().map((t) => {
        try { return JSON.stringify(scValToNative(t)); } catch { return t.switch().name; }
      });
      let data = '';
      try { data = JSON.stringify(scValToNative(body.data())); } catch { data = body.data().switch().name; }
      const ctype = e.contractId() ? require('@stellar/stellar-sdk').StrKey.encodeContract(e.contractId()!) : '(host)';
      console.log(`  [${e.type().name}] ${ctype} topics=${topics.join(',')} data=${data}`);
    } catch (err) {
      console.log('  (undecodable event)', (err as Error).message);
    }
  }
}
main().catch((e) => { console.error(e); process.exit(1); });
