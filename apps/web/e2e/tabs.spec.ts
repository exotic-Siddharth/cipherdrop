/**
 * Lock vault and sign-out apply to every open tab of the browser (critic-8): two pages of one context, lock in
 * one, the other drops its key and shows "Locked" rows; sign out in one, the other ends its session too.
 */
import { expect, test } from './support/fixtures';
import {
  accountMenu,
  randomPassword,
  registerAccount,
  sendDrop,
  textFile,
  uniqueEmail,
} from './support/flows';

test('lock vault and sign-out reach every open tab', async ({ page, context, leaks }) => {
  const email = uniqueEmail('tabs');
  const password = randomPassword();
  leaks.forbidText('account password', password);
  const file = textFile('two-tabs-report.txt', 'TABS-MARKER-1');
  leaks.forbidText('file name', file.name);
  leaks.forbidText('marker', 'TABS-MARKER');

  await registerAccount(page, email, password);
  await page.getByRole('link', { name: 'Send', exact: true }).first().click();
  const link = await sendDrop(page, [file], { maxDownloads: 5 });
  leaks.forbidKey('link key', new URL(link).hash.slice(1));
  await accountMenu(page, 'Dashboard');
  const list = page.getByRole('list', { name: 'Drops' });
  await expect(list.getByText(file.name)).toBeVisible({ timeout: 20_000 });

  // A second tab boots locked; the user unlocks it separately.
  const other = await context.newPage();
  await other.goto('/dashboard');
  await expect(other).toHaveURL(/\/unlock\?next=%2Fdashboard$/, { timeout: 20_000 });
  await other.getByLabel('Password', { exact: true }).fill(password);
  await other.getByRole('button', { name: /Unlock/ }).click();
  await expect(other).toHaveURL(/\/dashboard$/, { timeout: 30_000 });
  const otherList = other.getByRole('list', { name: 'Drops' });
  await expect(otherList.getByText(file.name)).toBeVisible({ timeout: 20_000 });

  // Lock in the first tab: the second forgets its key too, with no reload.
  await accountMenu(page, 'Lock vault');
  await expect(page.getByText('Your vault is locked')).toBeVisible();
  await expect(other.getByText('Your vault is locked')).toBeVisible({ timeout: 10_000 });
  await expect(otherList.getByText(file.name)).toHaveCount(0);
  await expect(other.getByText(/Locked/).first()).toBeVisible();

  // Sign out in the first tab: the second ends its session as well.
  await accountMenu(page, 'Sign out');
  await expect(page.getByRole('button', { name: /account menu$/ })).toHaveCount(0);
  await expect(other.getByRole('button', { name: /account menu$/ })).toHaveCount(0, {
    timeout: 10_000,
  });
  await expect(other).not.toHaveURL(/\/dashboard$/);
  await other.close();
});
