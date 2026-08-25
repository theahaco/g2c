// The policy builder: compose a new context rule and add it to the account.
//
// Collects a RuleDraft from the form, validates it with the pure lib, lowers it
// to the smart-account binding's add_context_rule arguments, attaches an
// optional spending-limit policy, and submits through the account's existing
// passkey signing path (signAndSubmit). The actual on-chain write always goes
// through the user's passkey ceremony — this module never signs silently.

import { Client as SmartAccountClient } from '@nidohq/smart-account';
import { extractXdrOperations, hex2buf } from '@nidohq/passkey-sdk';
import { Networks } from '@stellar/stellar-sdk';
import { esc } from '../lib/html.js';
import { toast } from '../lib/toast.js';
import { RPC_URL } from '../lib/network.js';
import { fetchRegistryAddress } from '../lib/policyChainFetch.js';
import { spendingLimitParamsScVal, stroopsFromXlm, PERIOD_LEDGERS } from '../lib/spendingLimitParams.js';
import { signAndSubmit } from '../lib/primaryPasskeySigner.js';
import {
  validateDraft,
  buildAddContextRuleArgs,
  spendingLimitPlan,
  type RuleDraft,
  type DraftSigner,
} from '../lib/policy/policyDraft.js';

const NETWORK_PASSPHRASE = Networks.TESTNET;

interface BuilderOptions {
  account: string;
  /** Called after a rule is successfully added, so the page can refresh. */
  onSubmitted?: () => void;
}

export function mountPolicyBuilder(container: HTMLElement, opts: BuilderOptions): void {
  // Local signer draft state; the row inputs are the source of truth on submit.
  let signers: DraftSigner[] = [{ kind: 'passkey' }];

  function render(): void {
    container.innerHTML = `
      <form class="nido-form pol-builder" novalidate>
        <label class="pol-input-label">Rule name
          <input name="name" class="input" maxlength="32" placeholder="e.g. ci-publish" />
        </label>

        <fieldset class="pol-fieldset">
          <legend class="pol-field-label">Scope</legend>
          <label class="pol-radio"><input type="radio" name="scope" value="default" /> Any contract (default authority)</label>
          <label class="pol-radio"><input type="radio" name="scope" value="call-contract" checked /> One contract</label>
          <input name="contract" class="input pol-mono" placeholder="C… contract address" />
        </fieldset>

        <div class="pol-field-label" style="margin-top:6px;">Signers</div>
        <div id="pol-signer-rows"></div>
        <button type="button" id="pol-add-signer" class="btn ghost sm">+ Add signer</button>

        <label class="pol-check">
          <input type="checkbox" name="limit-on" /> Attach a spending limit
        </label>
        <div id="pol-limit-fields" class="pol-limit" hidden>
          <input name="limit-xlm" class="input" inputmode="decimal" placeholder="Amount (XLM)" />
          <select name="limit-period" class="input">
            <option value="day">per day</option>
            <option value="week">per week</option>
            <option value="30d">per 30 days</option>
          </select>
        </div>

        <label class="pol-check">
          <input type="checkbox" name="expiry-on" /> Set an expiry
        </label>
        <div id="pol-expiry-fields" class="pol-limit" hidden>
          <input name="expiry-ledger" class="input" inputmode="numeric" placeholder="Expiry ledger sequence" />
        </div>

        <div id="pol-errors" class="alert danger" role="alert" hidden style="margin-top:10px;"></div>

        <div class="actions" style="display:flex;gap:8px;margin-top:14px;">
          <button type="submit" id="pol-submit" class="btn soft sm">Add rule</button>
        </div>
        <p id="pol-status" class="mut" style="font-size:12px;margin-top:8px;"></p>
      </form>`;
    renderSignerRows();
    wire();
  }

  function renderSignerRows(): void {
    const rows = container.querySelector<HTMLElement>('#pol-signer-rows');
    if (!rows) return;
    rows.innerHTML = signers
      .map((s, i) => {
        const passkey = s.kind === 'passkey';
        return `<div class="pol-signer-row" data-i="${i}">
          <select class="input pol-signer-kind" data-i="${i}">
            <option value="passkey" ${passkey ? 'selected' : ''}>Passkey</option>
            <option value="delegated" ${passkey ? '' : 'selected'}>Delegated key</option>
          </select>
          ${
            passkey
              ? `<input class="input pol-mono pol-sig-verifier" data-i="${i}" placeholder="Verifier (C…)" value="${esc(s.verifier ?? '')}" />
                 <input class="input pol-mono pol-sig-pubkey" data-i="${i}" placeholder="Public key (hex)" value="${esc(s.publicKeyHex ?? '')}" />`
              : `<input class="input pol-mono pol-sig-addr" data-i="${i}" placeholder="Address (C… or G…)" value="${esc(s.address ?? '')}" />`
          }
          ${signers.length > 1 ? `<button type="button" class="btn ghost sm pol-sig-remove" data-i="${i}" aria-label="Remove signer">✕</button>` : ''}
        </div>`;
      })
      .join('');

    rows.querySelectorAll<HTMLSelectElement>('.pol-signer-kind').forEach((sel) => {
      sel.addEventListener('change', () => {
        const i = Number(sel.dataset.i);
        readSignersFromDom();
        signers[i] = { kind: sel.value as DraftSigner['kind'] };
        renderSignerRows();
      });
    });
    rows.querySelectorAll<HTMLButtonElement>('.pol-sig-remove').forEach((btn) => {
      btn.addEventListener('click', () => {
        readSignersFromDom();
        signers.splice(Number(btn.dataset.i), 1);
        renderSignerRows();
      });
    });
  }

  /** Read current input values back into the signers state (preserve on re-render). */
  function readSignersFromDom(): void {
    const rows = container.querySelectorAll<HTMLElement>('.pol-signer-row');
    rows.forEach((row) => {
      const i = Number(row.dataset.i);
      const kind = row.querySelector<HTMLSelectElement>('.pol-signer-kind')?.value as DraftSigner['kind'];
      if (kind === 'delegated') {
        signers[i] = { kind, address: row.querySelector<HTMLInputElement>('.pol-sig-addr')?.value.trim() };
      } else {
        signers[i] = {
          kind: 'passkey',
          verifier: row.querySelector<HTMLInputElement>('.pol-sig-verifier')?.value.trim(),
          publicKeyHex: row.querySelector<HTMLInputElement>('.pol-sig-pubkey')?.value.trim(),
        };
      }
    });
  }

  function collectDraft(): RuleDraft {
    readSignersFromDom();
    const q = <T extends HTMLElement>(sel: string) => container.querySelector<T>(sel);
    const scopeKind =
      q<HTMLInputElement>('input[name="scope"]:checked')?.value === 'default' ? 'default' : 'call-contract';
    const limitOn = q<HTMLInputElement>('input[name="limit-on"]')?.checked ?? false;
    const expiryOn = q<HTMLInputElement>('input[name="expiry-on"]')?.checked ?? false;

    const draft: RuleDraft = {
      name: q<HTMLInputElement>('input[name="name"]')?.value ?? '',
      scope:
        scopeKind === 'call-contract'
          ? { kind: 'call-contract', contract: q<HTMLInputElement>('input[name="contract"]')?.value ?? '' }
          : { kind: 'default' },
      signers: signers.map((s) => ({ ...s })),
    };

    if (limitOn) {
      const xlm = q<HTMLInputElement>('input[name="limit-xlm"]')?.value ?? '';
      const period = (q<HTMLSelectElement>('select[name="limit-period"]')?.value ?? 'day') as keyof typeof PERIOD_LEDGERS;
      let stroops = '0';
      try {
        stroops = stroopsFromXlm(xlm).toString();
      } catch {
        stroops = '0';
      }
      draft.spendingLimit = { stroops, periodLedgers: PERIOD_LEDGERS[period] };
    }
    if (expiryOn) {
      const n = Number(q<HTMLInputElement>('input[name="expiry-ledger"]')?.value);
      draft.validUntilLedger = Number.isFinite(n) ? n : NaN;
    }
    return draft;
  }

  function showErrors(errors: string[]): void {
    const box = container.querySelector<HTMLElement>('#pol-errors');
    if (!box) return;
    if (errors.length === 0) {
      box.hidden = true;
      box.innerHTML = '';
      return;
    }
    box.hidden = false;
    box.innerHTML = `<ul style="margin:0;padding-left:18px;">${errors.map((e) => `<li>${esc(e)}</li>`).join('')}</ul>`;
  }

  async function submit(): Promise<void> {
    const draft = collectDraft();
    const check = validateDraft(draft);
    if (!check.ok) {
      showErrors(check.errors);
      return;
    }
    showErrors([]);

    const submitBtn = container.querySelector<HTMLButtonElement>('#pol-submit');
    const status = container.querySelector<HTMLElement>('#pol-status');
    if (submitBtn) submitBtn.disabled = true;
    const setStatus = (t: string) => {
      if (status) status.textContent = t;
    };

    try {
      const args = buildAddContextRuleArgs(draft);

      // Attach the optional spending-limit policy (address resolved from the
      // registry, params ScVal-encoded — same path the delegate flow uses).
      const policies = new Map<string, ReturnType<typeof spendingLimitParamsScVal>>();
      const plan = spendingLimitPlan(draft);
      if (plan) {
        setStatus('Resolving spending-limit policy…');
        const policyAddr = await fetchRegistryAddress('spending-limit-policy');
        policies.set(policyAddr, spendingLimitParamsScVal(plan.stroops, plan.periodLedgers));
      }

      const client = new SmartAccountClient({
        contractId: opts.account,
        networkPassphrase: NETWORK_PASSPHRASE,
        rpcUrl: RPC_URL,
      });

      setStatus('Building transaction…');
      const assembled = await client.add_context_rule({
        context_type:
          args.context_type.tag === 'CallContract'
            ? { tag: 'CallContract', values: args.context_type.values as readonly [string] }
            : { tag: 'Default', values: void 0 as unknown as undefined },
        name: args.name,
        valid_until: args.valid_until,
        signers: args.signers.map((s) =>
          s.tag === 'External'
            ? {
                tag: 'External' as const,
                values: [s.values[0], hex2buf(s.values[1]) as Buffer] as readonly [string, Buffer],
              }
            : { tag: 'Delegated' as const, values: [s.values[0]] as readonly [string] },
        ),
        policies,
      });

      const operation = extractXdrOperations(assembled, 'add-context-rule')[0]!;

      await signAndSubmit({
        account: opts.account,
        operation,
        onProgress: (p) => setStatus(`${p.phase}${p.detail ? `: ${p.detail}` : ''}…`),
      });

      toast('Policy rule added.');
      setStatus('');
      // Reset the form and refresh the inspector.
      signers = [{ kind: 'passkey' }];
      render();
      opts.onSubmitted?.();
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      showErrors([msg]);
      setStatus('');
    } finally {
      if (submitBtn) submitBtn.disabled = false;
    }
  }

  function wire(): void {
    container.querySelector<HTMLButtonElement>('#pol-add-signer')?.addEventListener('click', () => {
      readSignersFromDom();
      signers.push({ kind: 'passkey' });
      renderSignerRows();
    });
    container.querySelector<HTMLInputElement>('input[name="limit-on"]')?.addEventListener('change', (e) => {
      const on = (e.target as HTMLInputElement).checked;
      const box = container.querySelector<HTMLElement>('#pol-limit-fields');
      if (box) box.hidden = !on;
    });
    container.querySelector<HTMLInputElement>('input[name="expiry-on"]')?.addEventListener('change', (e) => {
      const on = (e.target as HTMLInputElement).checked;
      const box = container.querySelector<HTMLElement>('#pol-expiry-fields');
      if (box) box.hidden = !on;
    });
    container.querySelector<HTMLFormElement>('form')?.addEventListener('submit', (e) => {
      e.preventDefault();
      void submit();
    });
  }

  render();
}
