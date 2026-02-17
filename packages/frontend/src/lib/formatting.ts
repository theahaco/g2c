export function formatSignResult(result: {
  authenticatorData: string;
  clientDataJSON: string;
  signature: string;
  publicKey: string;
}) {
  let clientDataReadable = "";
  try {
    const bytes = new Uint8Array(
      result.clientDataJSON.match(/.{2}/g)!.map((b) => parseInt(b, 16))
    );
    const decoded = new TextDecoder().decode(bytes);
    const parsed = JSON.parse(decoded);
    clientDataReadable = JSON.stringify(parsed, null, 2);
  } catch {
    clientDataReadable = "(failed to decode)";
  }

  return (
    `<div style="margin-bottom:0.75rem"><strong>Authenticator Data</strong><br><code>${result.authenticatorData}</code></div>` +
    `<div style="margin-bottom:0.75rem"><strong>Client Data (readable)</strong><pre style="margin-top:0.25rem">${clientDataReadable}</pre></div>` +
    `<div style="margin-bottom:0.75rem"><strong>Client Data (hex)</strong><br><code>${result.clientDataJSON}</code></div>` +
    `<div style="margin-bottom:0.75rem"><strong>Signature</strong><br><code>${result.signature}</code></div>` +
    `<div><strong>Public Key</strong><br><code>${result.publicKey}</code></div>`
  );
}
