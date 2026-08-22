import { test, expect } from '@playwright/test';

// LIVE testnet test: walks all five acts of the tour, exercises attenuation
// (offline), then drives REAL testnet transactions (post + clear) in Act 5.
// Writes artifacts/*.png. Needs network + testnet, so it is NOT in the offline
// CI lane — run it explicitly.
test('perch tour: five acts, attenuation, and live on-chain enforce', async ({ page }) => {
  test.setTimeout(180_000);
  await page.goto('/');

  // Act 1 — the problem
  await expect(page.getByRole('heading', { name: /total power/i })).toBeVisible();
  await page.waitForTimeout(550); // let the act entrance animation settle
  await page.screenshot({ path: 'artifacts/01-act1-problem.png', fullPage: true });

  // Act 2 — smart account
  await page.getByRole('button', { name: /^Next/ }).click();
  await expect(page.getByRole('heading', { name: /auth becomes code/i })).toBeVisible();
  await page.waitForTimeout(550); // let the act entrance animation settle
  await page.screenshot({ path: 'artifacts/02-act2-smart-account.png', fullPage: true });

  // Act 3 — OZ model + contrast device
  await page.getByRole('button', { name: /^Next/ }).click();
  await expect(page.getByText(/you write the policy/i)).toBeVisible();
  await page.waitForTimeout(550); // let the act entrance animation settle
  await page.screenshot({ path: 'artifacts/03-act3-oz-model.png', fullPage: true });

  // Act 4 — connect a Nido account
  await page.getByRole('button', { name: /^Next/ }).click();
  await page.getByRole('button', { name: /Connect Nido account/ }).click();
  await expect(page.getByText(/ML-DSA-65 · post-quantum/)).toBeVisible(); // the post-quantum signer
  await expect(page.getByText('Treasury account')).toBeVisible(); // the Delegated "another account"
  await page.waitForTimeout(550); // let the act entrance animation settle
  await page.screenshot({ path: 'artifacts/04-act4-nido.png', fullPage: true });

  // Act 5 — perch: describe → attenuate → enforce
  await page.getByRole('button', { name: /^Next/ }).click();
  await expect(page.getByRole('heading', { name: /Watch it enforce/i })).toBeVisible();
  await expect(page.getByText(/full policy/i)).toBeVisible(); // the composed multi-rule view
  await expect(page.getByText('perch interpreter').first()).toBeVisible();

  // ① the policy builder is live: the default grant is over-broad, and toggling
  //    clear() off re-derives the document + safety read to "tightly scoped".
  await expect(page.locator('#doc-hash')).toContainText('doc_hash');
  await expect(page.getByText(/Over-broad/)).toBeVisible();
  await page.getByRole('button', { name: /clear\(\)/ }).click();
  await expect(page.getByText(/Tightly scoped/)).toBeVisible();
  await page.getByRole('button', { name: /clear\(\)/ }).click(); // restore over-broad for the narrow step below
  await expect(page.getByText(/Over-broad/)).toBeVisible();

  await page.locator('#narrow').click();
  await expect(page.getByText(/Verified narrowing/)).toBeVisible();
  await page.locator('#widen').click();
  await expect(page.getByText(/Refused — not a narrowing/)).toBeVisible();
  await page.waitForTimeout(550); // let the act entrance animation settle
  await page.screenshot({ path: 'artifacts/05-act5-attenuate.png', fullPage: true });

  // On-chain: publish (allow) then wipe (deny) — real testnet.
  await page.locator('#on-post').click();
  await expect(page.locator('#res-post .alert.good')).toBeVisible({ timeout: 120_000 });
  await expect(page.locator('#res-post a')).toHaveAttribute('href', /stellar\.expert\/explorer\/testnet\/tx/);
  await page.waitForTimeout(550); // let the act entrance animation settle
  await page.screenshot({ path: 'artifacts/06-post-allowed.png', fullPage: true });

  await page.locator('#on-clear').click();
  await expect(page.locator('#res-clear .alert.danger')).toBeVisible({ timeout: 120_000 });
  await page.waitForTimeout(550); // let the act entrance animation settle
  await page.screenshot({ path: 'artifacts/07-clear-denied.png', fullPage: true });

  // Act 6 — add signers, M-of-N. The policy panel gains a 2-of-3 quorum rule,
  // and the threshold is PROVEN live: 2 co-signers pass, 1 alone is denied.
  await page.getByRole('button', { name: /^Next/ }).click();
  await expect(page.getByRole('heading', { name: /Require a quorum/i })).toBeVisible();
  await expect(page.getByText('ops-quorum')).toBeVisible(); // the M-of-N rule in the policy panel
  await expect(page.getByText(/OZ multisig · M-of-N/)).toBeVisible();
  await page.waitForTimeout(550);
  await page.screenshot({ path: 'artifacts/08-act6-quorum.png', fullPage: true });

  await page.locator('#mofn-2').click(); // 2 of 3 → meets threshold
  await expect(page.locator('#res-mofn-2 .alert.good')).toBeVisible({ timeout: 120_000 });
  await expect(page.locator('#res-mofn-2 a')).toHaveAttribute('href', /stellar\.expert\/explorer\/testnet\/tx/);
  await page.waitForTimeout(550);
  await page.screenshot({ path: 'artifacts/09-mofn-2of3-allowed.png', fullPage: true });

  await page.locator('#mofn-1').click(); // 1 of 3 → below threshold
  await expect(page.locator('#res-mofn-1 .alert.danger')).toBeVisible({ timeout: 120_000 });
  await page.waitForTimeout(550);
  await page.screenshot({ path: 'artifacts/10-mofn-1of3-denied.png', fullPage: true });
});
