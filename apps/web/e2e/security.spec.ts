/**
 * Account-security flows against the real API (deferred from I1): backup codes, password change revoking the
 * other device, recovery-key rotation, sessions, account deletion. Review Focus 5 (session revoked elsewhere).
 */
import type { Page } from '@playwright/test';
import { expect, test } from './support/fixtures';
import {
  accountMenu,
  logIn,
  openLink,
  randomPassword,
  registerAccount,
  sendDrop,
  textFile,
  totpCode,
  uniqueEmail,
  waitForDashboard,
} from './support/flows';

async function enableTotp(page: Page): Promise<{ secret: string; backupCodes: string[] }> {
  await accountMenu(page, 'Settings');
  await page.getByRole('button', { name: 'Set up two-step verification' }).click();
  const secret = await page.getByLabel('Secret key').inputValue();
  await page.getByLabel('6-digit code').fill(totpCode(secret));
  await page.getByRole('button', { name: /Turn on|Verify|Enable/ }).click();
  await expect(page.getByText('Save these backup codes now')).toBeVisible({ timeout: 20_000 });
  const backupCodes = await page
    .getByRole('list', { name: 'Backup codes' })
    .getByRole('listitem')
    .allInnerTexts();
  await page.getByLabel('I saved my backup codes').check();
  await page.getByRole('button', { name: 'Done' }).click();
  return { secret, backupCodes };
}

async function loginWithBackupCode(page: Page, email: string, password: string, code: string) {
  await logIn(page, email, password);
  await page.getByRole('button', { name: 'Use a backup code instead' }).click();
  await page.getByLabel('Backup code').fill(code);
  await page.getByRole('button', { name: 'Verify and log in' }).click();
}

test('backup code logs in once, then is spent; regenerating backup codes needs a TOTP code', async ({
  page,
  newContext,
  leaks,
}) => {
  const email = uniqueEmail('backup');
  const password = randomPassword();
  leaks.forbidText('password', password);
  await registerAccount(page, email, password);
  const { secret, backupCodes } = await enableTotp(page);
  expect(backupCodes).toHaveLength(10);
  expect(backupCodes[0]).toMatch(/^[0-9a-z]{5}-[0-9a-z]{5}$/i);

  const device = await (await newContext()).newPage();
  await loginWithBackupCode(device, email, password, backupCodes[0]!);
  await waitForDashboard(device);
  await accountMenu(device, 'Sign out');

  // The same backup code is single-use.
  await loginWithBackupCode(device, email, password, backupCodes[0]!);
  await expect(device.getByRole('alert').first()).toBeVisible({ timeout: 20_000 });
  await expect(device).not.toHaveURL(/dashboard/);
  // A different one still works.
  await device.getByLabel('Backup code').fill(backupCodes[1]!);
  await device.getByRole('button', { name: 'Verify and log in' }).click();
  await waitForDashboard(device);

  // Regenerate on the first device: the old codes die.
  await page.getByRole('button', { name: 'Regenerate backup codes' }).click();
  await page.getByLabel('6-digit code').fill(totpCode(secret, true));
  await page.getByRole('button', { name: 'Regenerate', exact: true }).click();
  await expect(page.getByText('Save these backup codes now')).toBeVisible({ timeout: 20_000 });
  const fresh = await page
    .getByRole('list', { name: 'Backup codes' })
    .getByRole('listitem')
    .allInnerTexts();
  expect(fresh).toHaveLength(10);
  expect(fresh).not.toContain(backupCodes[2]);
  await page.getByLabel('I saved my backup codes').check();
  await page.getByRole('button', { name: 'Done' }).click();

  const other = await (await newContext()).newPage();
  await loginWithBackupCode(other, email, password, backupCodes[2]!);
  await expect(other.getByRole('alert').first()).toBeVisible({ timeout: 20_000 });
});

test('password change signs out the other device at once; files stay readable', async ({
  page,
  newContext,
  leaks,
}) => {
  const email = uniqueEmail('pwchange');
  const password = randomPassword();
  const newPassword = randomPassword();
  leaks.forbidText('password', password);
  leaks.forbidText('new password', newPassword);
  const file = textFile('keep-me-readable.txt', 'PWCHANGE-MARKER-5512');
  leaks.forbidText('file name', file.name);

  // Device A (the default page) and device B are signed in as the same user.
  await registerAccount(page, email, password);
  await page.getByRole('link', { name: 'Send', exact: true }).first().click();
  await sendDrop(page, [file], { maxDownloads: 5 });
  await accountMenu(page, 'Dashboard');
  await expect(page.getByText(file.name).first()).toBeVisible({ timeout: 20_000 });

  const deviceB = await (await newContext()).newPage();
  await logIn(deviceB, email, password);
  await waitForDashboard(deviceB);

  // B changes the password.
  await accountMenu(deviceB, 'Settings');
  await deviceB.getByLabel('Current password').fill(password);
  await deviceB.getByLabel('New password', { exact: true }).fill(newPassword);
  await deviceB.getByLabel('Confirm new password').fill(newPassword);
  await deviceB.getByRole('button', { name: 'Change password' }).click();
  await expect(deviceB.getByText('Password changed')).toBeVisible({ timeout: 30_000 });

  // A's next API call is rejected immediately (denylist), its refresh fails, and the SPA signs it out.
  await page.getByRole('tab', { name: 'All' }).click();
  await expect(page).toHaveURL(/\/login/, { timeout: 30_000 });
  await expect(
    page.getByText(/signed out|session (has )?expired|sign in again|log in again/i).first(),
  ).toBeVisible();

  // The new password works and the same file name decrypts (the account key was re-wrapped, not changed).
  await logIn(page, email, newPassword);
  await waitForDashboard(page);
  await expect(page.getByText(file.name).first()).toBeVisible({ timeout: 20_000 });
  // The old password is dead.
  const stale = await (await newContext()).newPage();
  await logIn(stale, email, password);
  await expect(stale.getByRole('alert').first()).toBeVisible({ timeout: 30_000 });
});

test('recovery key rotation: the new key recovers the account, the old one no longer does', async ({
  page,
  newContext,
  leaks,
}) => {
  const email = uniqueEmail('rotate');
  const password = randomPassword();
  const newPassword = randomPassword();
  leaks.forbidText('password', password);
  leaks.forbidText('new password', newPassword);
  const { recoveryKey: oldKey } = await registerAccount(page, email, password);
  leaks.forbidText('old recovery key', oldKey);
  leaks.forbidText('old recovery key (compact)', oldKey.replaceAll('-', ''));

  await accountMenu(page, 'Settings');
  await page.getByRole('button', { name: 'Replace recovery key' }).click();
  await page.getByLabel('Your password').fill(password);
  await page.getByRole('button', { name: 'Create new key' }).click();
  await expect(page.getByText('Save your new recovery key')).toBeVisible({ timeout: 30_000 });
  const rows = await page.getByTestId('recovery-key-row').allInnerTexts();
  const newKey = rows.map((r) => r.trim()).join('-');
  expect(newKey).not.toBe(oldKey);
  leaks.forbidText('new recovery key', newKey);
  leaks.forbidText('new recovery key (compact)', newKey.replaceAll('-', ''));
  await page.getByLabel('I saved my recovery key').check();
  await page.getByRole('button', { name: 'Done' }).click();
  // Rotation keeps this session signed in.
  await accountMenu(page, 'Dashboard');
  await waitForDashboard(page);

  const device = await (await newContext()).newPage();
  const recover = async (key: string) => {
    await device.goto('/recover');
    await device.getByLabel('Email').fill(email);
    await device.getByLabel('Recovery key').fill(key);
    await device.getByRole('button', { name: 'Continue' }).click();
  };
  await recover(oldKey);
  await expect(device.getByRole('alert').first()).toBeVisible({ timeout: 30_000 });
  await recover(newKey);
  await expect(device.getByText('Choose a new password')).toBeVisible({ timeout: 30_000 });
  await device.getByLabel('New password', { exact: true }).fill(newPassword);
  await device.getByLabel('Confirm new password').fill(newPassword);
  await device.getByRole('button', { name: 'Set new password' }).click();
  await expect(device.getByText('Save your new recovery key')).toBeVisible({ timeout: 30_000 });
});

test('sessions tab: two devices, sign out all others', async ({ page, newContext, leaks }) => {
  const email = uniqueEmail('sessions');
  const password = randomPassword();
  leaks.forbidText('password', password);
  await registerAccount(page, email, password);
  const other = await (await newContext()).newPage();
  await logIn(other, email, password);
  await waitForDashboard(other);

  await accountMenu(page, 'Settings');
  await page.getByRole('tab', { name: 'Sessions' }).click();
  await expect(page.getByText('This device')).toBeVisible({ timeout: 20_000 });
  await expect(page.getByRole('button', { name: /^Sign out Chrome/ })).toHaveCount(1);
  await page.getByRole('button', { name: 'Sign out all others' }).click();
  await page.getByRole('button', { name: 'Sign out all others' }).last().click();
  await expect(page.getByText('Signed out of all other devices')).toBeVisible({ timeout: 20_000 });
  await expect(page.getByRole('button', { name: /^Sign out Chrome/ })).toHaveCount(0);

  // The other device is signed out the next time it talks to the API.
  await other.getByRole('tab', { name: 'All' }).click();
  await expect(other).toHaveURL(/\/login/, { timeout: 30_000 });
});

test('delete account: typed confirmation + password, then drops and login are gone', async ({
  page,
  newContext,
  leaks,
}) => {
  const email = uniqueEmail('delete');
  const password = randomPassword();
  leaks.forbidText('password', password);
  const file = textFile('doomed.txt', 'DELETE-MARKER-3380');
  leaks.forbidText('file name', file.name);
  await registerAccount(page, email, password);
  await page.getByRole('link', { name: 'Send', exact: true }).first().click();
  const link = await sendDrop(page, [file], { maxDownloads: 5 });

  await accountMenu(page, 'Settings');
  await page.getByRole('tab', { name: 'Account' }).click();
  await page.getByRole('button', { name: /Delete my account/ }).click();
  const confirmButton = page.getByRole('button', { name: 'Delete everything' });
  await expect(confirmButton).toBeDisabled();
  await page.getByLabel(/Type DELETE to confirm/).fill('DELETE');
  await page.getByLabel('Your password').fill(password);
  await confirmButton.click();
  await expect(page).toHaveURL(/localhost:\d+\/$/, { timeout: 30_000 });
  await expect(page.getByText('Account deleted')).toBeVisible();

  const visitor = await (await newContext()).newPage();
  await openLink(visitor, link);
  await expect(visitor.getByText("This drop doesn't exist")).toBeVisible({ timeout: 20_000 });
  await logIn(visitor, email, password);
  await expect(visitor.getByRole('alert').first()).toBeVisible({ timeout: 30_000 });
});
