/**
 * Dashboard against the real API: decrypted names, filters, copy link (keyless for password drops), delete,
 * and the vault locking while the page is open (Review Focus 4).
 */
import { expect, test } from './support/fixtures';
import { dropIdOf } from './support/db';
import {
  accountMenu,
  logIn,
  randomPassword,
  registerAccount,
  sendDrop,
  textFile,
  uniqueEmail,
} from './support/flows';

test('dashboard: names, filters, copy link, delete, lock mid-use and unlock', async ({
  page,
  context,
  leaks,
}) => {
  await context.grantPermissions(['clipboard-read', 'clipboard-write']);
  const email = uniqueEmail('dash');
  const password = randomPassword();
  const dropPassword = randomPassword();
  leaks.forbidText('account password', password);
  leaks.forbidText('drop password', dropPassword);
  const keyFile = textFile('board-deck ‮ v2.txt', 'DASH-MARKER-1');
  const pwFile = textFile('vault-passwords.txt', 'DASH-MARKER-2');
  const goneFile = textFile('already-burned.txt', 'DASH-MARKER-3');
  for (const f of [keyFile, pwFile, goneFile]) leaks.forbidText(`name ${f.name}`, f.name);
  leaks.forbidText('marker', 'DASH-MARKER');

  await registerAccount(page, email, password);
  await page.getByRole('link', { name: 'Send', exact: true }).first().click();
  const keyLink = await sendDrop(page, [keyFile], { maxDownloads: 5, expiryHours: 168 });
  leaks.forbidText('key link key', new URL(keyLink).hash.slice(1));
  await page.getByRole('button', { name: 'Send another' }).click();
  const pwLink = await sendDrop(page, [pwFile], { maxDownloads: 3, password: dropPassword });
  await page.getByRole('button', { name: 'Send another' }).click();
  const goneLink = await sendDrop(page, [goneFile], { maxDownloads: 1 });
  leaks.forbidText('gone link key', new URL(goneLink).hash.slice(1));

  // A signed-in sender gets the long expiries and the owner-wrapped key.
  await accountMenu(page, 'Dashboard');
  const list = page.getByRole('list', { name: 'Drops' });
  await expect(list.getByRole('listitem')).toHaveCount(3, { timeout: 20_000 });
  await expect(list.getByText(keyFile.name)).toBeVisible();
  await expect(list.getByText('vault-passwords.txt')).toBeVisible();
  await expect(list.getByText('already-burned.txt')).toBeVisible();

  // Burn the 1-download drop from a second page of the same context (anonymous visitor path is covered
  // elsewhere); then it moves from Active to Expired.
  const visitor = await context.newPage();
  await visitor.goto(goneLink);
  await visitor.getByRole('button', { name: 'Decrypt & download' }).click();
  const dl = visitor.waitForEvent('download');
  await visitor.getByRole('button', { name: 'Download now' }).click();
  await dl;
  await visitor.close();

  await page.getByRole('tab', { name: 'Expired' }).click();
  await expect(list.getByText('already-burned.txt')).toBeVisible({ timeout: 20_000 });
  await expect(list.getByRole('listitem')).toHaveCount(1);
  await page.getByRole('tab', { name: 'All' }).click();
  await expect(list.getByRole('listitem')).toHaveCount(3, { timeout: 20_000 });
  await page.getByRole('tab', { name: 'Active' }).click();
  await expect(list.getByRole('listitem')).toHaveCount(2, { timeout: 20_000 });

  // Copy link: key drops rebuild /d/id#key, password drops copy the keyless link.
  await page
    .getByRole('button', { name: new RegExp(`^Copy link for .* ${dropIdOf(keyLink)}$`) })
    .click();
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(keyLink);
  await page
    .getByRole('button', { name: new RegExp(`^Copy link for .* ${dropIdOf(pwLink)}$`) })
    .click();
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(pwLink);
  expect(pwLink).not.toContain('#');

  // The vault locks while the dashboard is open: rows switch to the locked state, nothing crashes or navigates.
  await accountMenu(page, 'Lock vault');
  await expect(page.getByText('Your vault is locked')).toBeVisible();
  await expect(page).toHaveURL(/\/dashboard$/);
  await expect(list.getByText(keyFile.name)).toHaveCount(0);
  await expect(page.getByText(/Locked/).first()).toBeVisible();
  // ... unlocking from the CTA brings the names back without a reload.
  await page.getByRole('link', { name: 'Unlock' }).first().click();
  await expect(page).toHaveURL(/\/unlock\?next=%2Fdashboard$/);
  await page.getByLabel('Password', { exact: true }).fill(password);
  await page.getByRole('button', { name: /Unlock/ }).click();
  await expect(page).toHaveURL(/\/dashboard$/, { timeout: 30_000 });
  await expect(list.getByText(keyFile.name)).toBeVisible({ timeout: 20_000 });

  // Delete a drop: confirm, the row disappears, the link is dead for everyone.
  await page.getByRole('button', { name: `Delete drop ${dropIdOf(pwLink)}` }).click();
  await expect(page.getByText('Delete this drop?')).toBeVisible();
  await page.getByRole('button', { name: 'Delete drop', exact: true }).click();
  await expect(list.getByText('vault-passwords.txt')).toHaveCount(0, { timeout: 20_000 });
  const probe = await context.newPage();
  await probe.goto(pwLink);
  await expect(
    probe.getByText('This drop was deleted').or(probe.getByText("This drop doesn't exist")),
  ).toBeVisible({
    timeout: 20_000,
  });
  await probe.close();

  // After a full logout + login the names are still there (stored encrypted, not in the browser).
  await accountMenu(page, 'Sign out');
  await logIn(page, email, password);
  await expect(page).toHaveURL(/\/dashboard$/, { timeout: 30_000 });
  await expect(list.getByText(keyFile.name)).toBeVisible({ timeout: 20_000 });
});
