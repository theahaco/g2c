import {
  generateSessionKey,
  saveSessionKeyMaterial,
  forgetSessionKeyMaterial,
  buf2hex,
} from '@nidohq/passkey-sdk';
import { delegateSessionKey } from './sessionKeyActions.js';

/** Approximate stroop blocks per duration. Soroban testnet has ~5s ledger
 *  closes → 17280 ledgers ≈ 24h. */
const DURATIONS: Record<string, number | null> = {
  '24h': 17280,
  '7d': 17280 * 7,
  '30d': 17280 * 30,
  'none': null,
};

export function mountDelegationForm(container: HTMLElement, account: string): void {
  container.hidden = false;
  container.innerHTML = `
    <h3>Let an app in</h3>
    <p class="muted">Generate a fresh session key on this device and authorize it to sign for one app. The session key never leaves your browser.</p>
    <label style="display:block;margin-top:1rem">
      App address (C…)
      <input id="target" placeholder="C…" style="display:block;margin-top:0.25rem;width:100%"/>
    </label>
    <label style="display:block;margin-top:1rem">
      Duration
      <select id="duration" style="display:block;margin-top:0.25rem">
        <option value="24h">24 hours</option>
        <option value="7d">7 days</option>
        <option value="30d" selected>30 days</option>
        <option value="none">No expiry</option>
      </select>
    </label>
    <label style="display:block;margin-top:1rem">
      Label (optional)
      <input id="label" style="display:block;margin-top:0.25rem"/>
    </label>
    <div class="actions" style="margin-top:1rem">
      <button id="cancel" type="button">Cancel</button>
      <button id="save" type="button">Sign &amp; delegate</button>
    </div>
  `;

  container.querySelector('#cancel')!.addEventListener('click', () => {
    container.hidden = true;
    container.innerHTML = '';
  });

  container.querySelector('#save')!.addEventListener('click', async () => {
    const existingError = container.querySelector('.form-error');
    if (existingError) existingError.textContent = '';
    const target = (container.querySelector('#target') as HTMLInputElement).value.trim();
    const duration = (container.querySelector('#duration') as HTMLSelectElement).value;
    const label =
      (container.querySelector('#label') as HTMLInputElement).value.trim() || undefined;

    const showError = (msg: string) => {
      let errEl = container.querySelector<HTMLElement>('.form-error');
      if (!errEl) {
        errEl = document.createElement('p');
        errEl.className = 'form-error muted';
        errEl.style.cssText = 'color:var(--warn,#b45309);margin-top:0.5rem;font-size:13px;';
        container.querySelector('.actions')!.before(errEl);
      }
      errEl.textContent = msg;
    };
    if (!target) { showError('App address is required.'); return; }
    if (!target.startsWith('C') || target.length !== 56) {
      showError('App address must start with C and be 56 characters.');
      return;
    }

    const saveBtn = container.querySelector('#save') as HTMLButtonElement;
    saveBtn.disabled = true;
    saveBtn.textContent = 'Generating key...';

    try {
      // NOTE: this in-wallet flow predates the cross-origin handover and
      // still uses a synthetic P-256 key (stored in localStorage). The new
      // canonical path is `startDelegation` from the dApp's origin, which
      // creates a real passkey at the dApp via `createSessionPasskey`. Once
      // every dApp is on the new flow this form (and the synthetic key)
      // can be removed.
      const k = await generateSessionKey();
      // The synthetic privateKey is intentionally NOT persisted — nothing signs
      // with a stored session key any more (passkey-backed handover superseded
      // this legacy in-wallet flow), so it must not touch disk.
      saveSessionKeyMaterial(account, target, {
        credentialId: k.credentialId,
        publicKey: buf2hex(k.publicKey),
        label,
      });

      saveBtn.textContent = 'Signing & submitting...';
      await delegateSessionKey({
        account,
        target,
        sessionPubkey: k.publicKey,
        validUntilOffset: DURATIONS[duration] ?? DURATIONS['30d'],
        label,
      });

      container.innerHTML = '<p>Session key delegated. Refreshing…</p>';
      setTimeout(() => location.reload(), 800);
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      forgetSessionKeyMaterial(account, target);
      console.error('Failed to delegate:', e);
      let errEl = container.querySelector<HTMLElement>('.form-error');
      if (!errEl) {
        errEl = document.createElement('p');
        errEl.className = 'form-error muted';
        errEl.style.cssText = 'color:var(--warn,#b45309);margin-top:0.5rem;font-size:13px;';
        container.querySelector('.actions')!.before(errEl);
      }
      errEl.textContent = 'Failed to let app in: ' + msg;
      saveBtn.disabled = false;
      saveBtn.textContent = 'Sign & delegate';
    }
  });
}
