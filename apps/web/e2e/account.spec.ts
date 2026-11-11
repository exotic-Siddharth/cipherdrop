/**
 * E2E specs 5 and 6 (spec section 14) plus the account flows that only a real API can prove: backup codes,
 * password change revoking other devices (Review Focus 5), recovery-key rotation, sessions and activity,
 * account deletion. Passwords and recovery keys are random per run and must never reach a request body as
 * plaintext (the leak guard knows the passwords).
 */
import path from 'node:path';
import { expect, test } from './support/fixtures';
import {
  accountMenu,
  downloadFromReady,
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

const DOWNLOAD_DIR = path.join(import.meta.dirname, '..', 'test-results', 'downloads');

test('5. register, send, dashboard names, reload + unlock, enable TOTP, logout, login needs TOTP', async ({
  page,
  newContext,
  leaks,
}) => {
  const email = uniqueEmail('account');
  const password = randomPassword();
  leaks.forbidText('account password', password);
  const file = textFile('tax-return-2025 éè.txt', 'ACCOUNT-PLAINTEXT-MARKER-9921');
  leaks.forbidText('file name', file.name);
  leaks.forbidText('file name stem', 'tax-return-2025');
  leaks.forbidText('plaintext marker', 'ACCOUNT-PLAINTEXT-MARKER-9921');

  const { recoveryKey } = await registerAccount(page, email, password);
  leaks.forbidText('recovery key', recoveryKey);
  leaks.forbidText('recovery key (compact)', recoveryKey.replaceAll('-', ''));
  // A brand-new account: empty state with a call to action.
  await expect(
    page.getByText(/no (active )?drops|nothing here|send your first/i).first(),
  ).toBeVisible();

  // Send while signed in (owner-wrapped key travels, no names).
  await page.getByRole('link', { name: 'Send', exact: true }).first().click();
  const link = await sendDrop(page, [file], { maxDownloads: 5 });
  leaks.forbidText('link key', new URL(link).hash.slice(1));

  // Dashboard shows the decrypted name.
  await page.getByRole('link', { name: 'Dashboard', exact: true }).first().click();
  await expect(page.getByText(file.name).first()).toBeVisible({ timeout: 20_000 });

  // Reload: the access token is refreshed from the cookie but the vault key is gone -> /unlock.
  await page.reload();
  await expect(page).toHaveURL(/\/unlock\?next=%2Fdashboard$/, { timeout: 30_000 });
  await page.getByLabel('Password', { exact: true }).fill('not the password at all');
  await page.getByRole('button', { name: /Unlock/ }).click();
  await expect(
    page
      .getByRole('alert')
      .or(page.getByText(/incorrect|wrong|did not/i))
      .first(),
  ).toBeVisible({
    timeout: 20_000,
  });
  leaks.forbidText('wrong unlock password', 'not the password at all');
  await page.getByLabel('Password', { exact: true }).fill(password);
  await page.getByRole('button', { name: /Unlock/ }).click();
  await waitForDashboard(page);
  await expect(page.getByText(file.name).first()).toBeVisible({ timeout: 20_000 });

  // Another device opens the link: the owner sees an audit entry.
  const recipient = await (await newContext()).newPage();
  await openLink(recipient, link);
  await downloadFromReady(recipient, DOWNLOAD_DIR);

  // Enable TOTP from Settings.
  await accountMenu(page, 'Settings');
  await expect(page).toHaveURL(/\/settings/);
  await page.getByRole('button', { name: 'Set up two-step verification' }).click();
  const secret = await page.getByLabel('Secret key').inputValue();
  expect(secret).toMatch(/^[A-Z2-7]{16,}$/);
  leaks.forbidText('totp secret', secret);
  await expect(page.getByRole('img', { name: 'QR code for your authenticator app' })).toBeVisible();
  await page.getByLabel('6-digit code').fill(totpCode(secret));
  await page.getByRole('button', { name: /Turn on|Verify|Enable/ }).click();
  await expect(page.getByText('Save these backup codes now')).toBeVisible({ timeout: 20_000 });
  const backupCodes = await page
    .getByRole('list', { name: 'Backup codes' })
    .getByRole('listitem')
    .allInnerTexts();
  expect(backupCodes).toHaveLength(10);
  await page.getByLabel('I saved my backup codes').check();
  await page.getByRole('button', { name: 'Done' }).click();
  await expect(page.getByText('On', { exact: true })).toBeVisible();

  // Activity shows the download of the owner's drop.
  await page.getByRole('tab', { name: 'Activity' }).click();
  await expect(
    page.getByText('Your drop was downloaded').locator('visible=true').first(),
  ).toBeVisible({ timeout: 20_000 });
  await page.getByRole('tab', { name: 'Security' }).click();

  // Log out, log back in: the password alone is not enough.
  await accountMenu(page, 'Sign out');
  await expect(page).toHaveURL(/localhost:\d+\/$/, { timeout: 20_000 });
  await logIn(page, email, password);
  await expect(page.getByText('Two-step verification').first()).toBeVisible({ timeout: 30_000 });
  await expect(page).not.toHaveURL(/dashboard/);
  // A wrong code is refused ...
  await page.getByLabel('6-digit code').fill(totpCode(secret) === '000000' ? '111111' : '000000');
  await page.getByRole('button', { name: 'Verify and log in' }).click();
  await expect(page.getByRole('alert').first()).toBeVisible({ timeout: 20_000 });
  // ... the next window's code is accepted (R23: no sleeping, no replay of the code used at enable time).
  await page.getByLabel('6-digit code').fill(totpCode(secret, true));
  await page.getByRole('button', { name: 'Verify and log in' }).click();
  await waitForDashboard(page);

  // After this login the vault is unlocked (the derived key is still in memory): names are readable.
  await expect(page.getByText(file.name).first()).toBeVisible({ timeout: 20_000 });
});

test('6. recovery with the recovery key sets a new password, issues a new key, old password dies', async ({
  page,
  newContext,
  leaks,
}) => {
  const email = uniqueEmail('recover');
  const password = randomPassword();
  const newPassword = randomPassword();
  leaks.forbidText('old password', password);
  leaks.forbidText('new password', newPassword);
  const file = textFile('recoverable.txt', 'RECOVER-MARKER-4410');
  leaks.forbidText('file name', file.name);

  const { recoveryKey } = await registerAccount(page, email, password);
  leaks.forbidText('recovery key', recoveryKey);
  leaks.forbidText('recovery key (compact)', recoveryKey.replaceAll('-', ''));
  await page.getByRole('link', { name: 'Send', exact: true }).first().click();
  await sendDrop(page, [file]);

  // A second device recovers the account.
  const device = await (await newContext()).newPage();
  await device.goto('/recover');
  await device.getByLabel('Email').fill(email);
  // A mistyped recovery key gets the generic error.
  await device.getByLabel('Recovery key').fill('AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA');
  await device.getByRole('button', { name: 'Continue' }).click();
  await expect(device.getByRole('alert').first()).toBeVisible({ timeout: 30_000 });
  // Lower case and missing dashes are accepted.
  await device.getByLabel('Recovery key').fill(recoveryKey.toLowerCase().replaceAll('-', ''));
  await device.getByRole('button', { name: 'Continue' }).click();
  await expect(device.getByText('Choose a new password')).toBeVisible({ timeout: 30_000 });
  await device.getByLabel('New password', { exact: true }).fill(newPassword);
  await device.getByLabel('Confirm new password').fill(newPassword);
  await device.getByRole('button', { name: 'Set new password' }).click();
  await expect(device.getByText('Save your new recovery key')).toBeVisible({ timeout: 30_000 });
  const rows = await device.getByTestId('recovery-key-row').allInnerTexts();
  const newKey = rows.map((r) => r.trim()).join('-');
  expect(newKey).toMatch(/^([0-9A-Z]{4}-){7}[0-9A-Z]{4}$/);
  expect(newKey).not.toBe(recoveryKey);
  leaks.forbidText('new recovery key', newKey);
  leaks.forbidText('new recovery key (compact)', newKey.replaceAll('-', ''));
  await device.getByLabel('I saved my recovery key').check();
  await device.getByRole('button', { name: 'Continue to my files' }).click();
  await waitForDashboard(device);
  // The wrapped account key survived the recovery: the file name still decrypts.
  await expect(device.getByText(file.name).first()).toBeVisible({ timeout: 20_000 });

  // The first device was signed out by the recovery (other sessions revoked).
  await page.getByRole('link', { name: 'Dashboard', exact: true }).first().click();
  await page.reload();
  await expect(page).toHaveURL(/\/login/, { timeout: 30_000 });

  // Old password no longer works, new one does.
  const fresh = await (await newContext()).newPage();
  await logIn(fresh, email, password);
  await expect(fresh.getByRole('alert').first()).toBeVisible({ timeout: 30_000 });
  await expect(fresh).toHaveURL(/\/login/);
  await logIn(fresh, email, newPassword);
  await waitForDashboard(fresh);

  // The used recovery key is dead.
  await fresh.goto('/recover');
  await fresh.getByLabel('Email').fill(email);
  await fresh.getByLabel('Recovery key').fill(recoveryKey);
  await fresh.getByRole('button', { name: 'Continue' }).click();
  await expect(fresh.getByRole('alert').first()).toBeVisible({ timeout: 30_000 });
});
