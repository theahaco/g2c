// Renders the full list of a smart account's context rules — the general
// "what can happen on this account and who authorizes it" view. Pure DOM from
// the pure display model in lib/policy/policyView; the page fetches the data.

import type { ChainRule } from '@nidohq/passkey-sdk';
import { esc } from '../lib/html.js';
import { summarizeRule, type RuleView, type SignerView, type PolicyView } from '../lib/policy/policyView.js';

export interface InspectorContext {
  /** policy contract address → registry label. */
  known?: ReadonlyMap<string, string>;
  /** current ledger sequence, for expiry classification. */
  currentLedger?: number | null;
}

function signerRow(s: SignerView): string {
  const icon = s.kind === 'passkey' ? '🔑' : '👤';
  return `<li class="pol-signer">
    <span class="pol-signer-ico" aria-hidden="true">${icon}</span>
    <span class="pol-signer-label">${esc(s.label)}</span>
    <code class="pol-mono" title="${esc(s.full)}">${esc(s.detail)}</code>
  </li>`;
}

function policyChip(p: PolicyView): string {
  const cls = p.known ? 'pol-chip known' : 'pol-chip custom';
  return `<span class="${cls}" title="${esc(p.address)}">${esc(p.label)} · ${esc(p.short)}</span>`;
}

function expiryBadge(view: RuleView): string {
  const { state, label } = view.expiry;
  if (state === 'none') return '';
  const cls = state === 'expired' ? 'pol-badge danger' : 'pol-badge';
  return `<span class="${cls}">${esc(label)}</span>`;
}

function ruleCard(view: RuleView): string {
  const badges = [
    view.isDefault ? '<span class="pol-badge primary">Primary authority</span>' : '',
    view.gated ? '<span class="pol-badge gated">Conditions apply</span>' : '',
    expiryBadge(view),
  ]
    .filter(Boolean)
    .join('');

  const scopeDetail = view.scope.detail
    ? `<code class="pol-mono" title="${esc(view.scope.detail)}">${esc(view.scope.detail)}</code>`
    : '';

  const signers = view.signers.length
    ? `<ul class="pol-signers">${view.signers.map(signerRow).join('')}</ul>`
    : `<p class="mut" style="font-size:12.5px;margin:0;">No signers — authorized entirely by attached conditions.</p>`;

  const policies = view.policies.length
    ? `<div class="pol-chips">${view.policies.map(policyChip).join('')}</div>`
    : '';

  return `<article class="card pol-card" data-rule-id="${view.ruleId}" style="padding:16px;">
    <header class="pol-head">
      <div>
        <span class="section-label">Rule ${view.ruleId}</span>
        <h3 class="pol-name disp">${esc(view.name || '(unnamed)')}</h3>
      </div>
      <div class="pol-badges">${badges}</div>
    </header>
    <p class="pol-perm">${esc(view.permission)}</p>
    <div class="pol-grid">
      <div class="pol-field">
        <span class="pol-field-label">Scope</span>
        <span class="pol-field-val">${esc(view.scope.label)} ${scopeDetail}</span>
      </div>
      <div class="pol-field">
        <span class="pol-field-label">Signers (${view.signers.length})</span>
        ${signers}
      </div>
      ${
        policies
          ? `<div class="pol-field"><span class="pol-field-label">Conditions</span>${policies}</div>`
          : ''
      }
    </div>
  </article>`;
}

/** Render (or re-render) the rule list into `container`. */
export function renderPolicyList(
  container: HTMLElement,
  rules: ChainRule[],
  ctx: InspectorContext = {},
): void {
  if (rules.length === 0) {
    container.innerHTML = `<p class="mut" style="font-size:13.5px;">No policy rules found on this account.</p>`;
    return;
  }
  const views = rules
    .slice()
    .sort((a, b) => a.ruleId - b.ruleId)
    .map((r) => summarizeRule(r, { known: ctx.known, currentLedger: ctx.currentLedger }));
  container.innerHTML = views.map(ruleCard).join('');
}
