/**
 * E2E specs 1-4 and the flaky-network spec (spec section 14, Review Focus 2): anonymous drops through the
 * production build (CSP on) against the real API. Every test also runs the leak guard (fixtures.ts): no request
 * may carry the file name, the plaintext bytes, the key after `#` or a password.
 */
import path from 'node:path';
import { expect, test } from './support/fixtures';
import {
  composeDrop,
  downloadFromReady,
  openLink,
  randomFile,
  randomPassword,
  sendDrop,
  sha256,
  textFile,
} from './support/flows';

const DOWNLOAD_DIR = path.join(import.meta.dirname, '..', 'test-results', 'downloads');

function keyOf(link: string): string {
  const key = new URL(link).hash.slice(1);
  expect(key).toHaveLength(43);
  return key;
}

test('1. anonymous send of a 5 MB random file, recipient in a new context gets identical bytes', async ({
  page,
  newContext,
  leaks,
}) => {
  const file = randomFile('quarterly-board-minutes ‮ final.bin', 5 * 1024 * 1024);
  leaks.forbidText('file name', file.name);
  leaks.forbidText('file name stem', 'quarterly-board-minutes');
  leaks.forbidBytes('plaintext bytes', file.buffer);

  await page.goto('/');
  await expect(
    page.getByText('Share files only the recipient can read. Not even us.'),
  ).toBeVisible();
  const link = await sendDrop(page, [file], { note: 'secret-note-for-the-recipient' });
  leaks.forbidText('note', 'secret-note-for-the-recipient');
  leaks.forbidText('link key', keyOf(link));

  // Success card content.
  await expect(page.getByText(/key after # never reaches our server/i)).toBeVisible();
  await expect(page.getByRole('button', { name: /Delete now/ })).toBeVisible();
  expect(link).toMatch(/\/d\/[A-Za-z0-9_-]{22}#[A-Za-z0-9_-]{43}$/);
  // The upload must have gone through the module worker under the CSP: 2 chunks of a 5 MB file.
  expect(leaks.count('PUT', '/chunks/')).toBe(2);

  // Anonymous drops are remembered on this device (no names, no keys).
  await page.getByRole('button', { name: 'Send another' }).click();
  await expect(page.getByText('Sent from this device')).toBeVisible();

  const recipient = await (await newContext()).newPage();
  await openLink(recipient, link);
  await expect(recipient.getByText(/secret-note-for-the-recipient/)).toBeVisible({
    timeout: 30_000,
  });
  await expect(recipient.getByText('quarterly-board-minutes', { exact: false })).toBeVisible();
  const saved = await downloadFromReady(recipient, DOWNLOAD_DIR);
  expect(sha256(saved.buffer)).toBe(sha256(file.buffer));
  // The RTL override is stripped from the saved name; the extension survives.
  expect(saved.filename).toMatch(/^quarterly-board-minutes.*final\.bin$/);
  expect(saved.filename).not.toContain('‮');
  await expect(recipient.getByText('Integrity verified').first()).toBeVisible();
});

test('2. password drop: wrong password shows an error, the right one downloads', async ({
  page,
  newContext,
  leaks,
}) => {
  const password = randomPassword();
  const file = textFile('payroll-2026.txt', 'PAYROLL-PLAINTEXT-MARKER-7731');
  leaks.forbidText('file name', file.name);
  leaks.forbidText('password', password);
  leaks.forbidText('plaintext marker', 'PAYROLL-PLAINTEXT-MARKER-7731');

  await page.goto('/');
  const link = await sendDrop(page, [file], { password });
  // A password drop's link carries no key at all: the key is wrapped under the password.
  expect(link).toMatch(/\/d\/[A-Za-z0-9_-]{22}$/);

  const recipient = await (await newContext()).newPage();
  await recipient.goto(link);
  await expect(recipient.getByText('This drop is password protected')).toBeVisible();
  const wrong = 'definitely not the password';
  leaks.forbidText('wrong password', wrong);
  await recipient.getByLabel('Password', { exact: true }).fill(wrong);
  await recipient.getByRole('button', { name: 'Unlock' }).click();
  await expect(
    recipient.getByText(/wrong password|incorrect|did not match|doesn't match/i),
  ).toBeVisible({
    timeout: 20_000,
  });
  // Still locked: the file list is not shown.
  await expect(recipient.getByText('payroll-2026.txt')).toHaveCount(0);

  await recipient.getByLabel('Password', { exact: true }).fill(password);
  await recipient.getByRole('button', { name: 'Unlock' }).click();
  await expect(recipient.getByText('payroll-2026.txt')).toBeVisible({ timeout: 20_000 });
  const saved = await downloadFromReady(recipient, DOWNLOAD_DIR);
  expect(saved.buffer.equals(file.buffer)).toBe(true);
  expect(saved.filename).toBe('payroll-2026.txt');
});

test('3. burn after reading: a second visitor sees "All downloads have been used"', async ({
  page,
  newContext,
  leaks,
}) => {
  const file = textFile('one-shot.txt', 'BURN-MARKER-1188');
  leaks.forbidText('file name', file.name);
  leaks.forbidText('plaintext marker', 'BURN-MARKER-1188');

  await page.goto('/');
  const link = await sendDrop(page, [file], { maxDownloads: 1 });
  leaks.forbidText('link key', keyOf(link));

  const first = await (await newContext()).newPage();
  await openLink(first, link);
  await expect(first.getByText(/1 of 1 downloads? left|1 download left/i)).toBeVisible({
    timeout: 30_000,
  });
  const saved = await downloadFromReady(first, DOWNLOAD_DIR);
  expect(saved.buffer.equals(file.buffer)).toBe(true);

  const second = await (await newContext()).newPage();
  await openLink(second, link);
  await expect(second.getByText('All downloads have been used')).toBeVisible({ timeout: 20_000 });
  await expect(second.getByRole('button', { name: 'Decrypt & download' })).toHaveCount(0);
});

test('4. tamper: one flipped ciphertext byte shows the integrity error and saves nothing', async ({
  page,
  newContext,
  leaks,
}) => {
  const file = randomFile('contract-v7.pdf', 300_000, 'application/pdf');
  leaks.forbidText('file name', file.name);
  await page.goto('/');
  const link = await sendDrop(page, [file]);
  leaks.forbidText('link key', keyOf(link));

  const context = await newContext();
  let tampered = 0;
  await context.route('**/api/drops/*/files/*/chunks/*', async (route) => {
    const response = await route.fetch();
    const body = Buffer.from(await response.body());
    body[Math.floor(body.length / 2)] ^= 0x01;
    tampered += 1;
    await route.fulfill({ response, body });
  });
  const recipient = await context.newPage();
  let saved = false;
  recipient.on('download', () => {
    saved = true;
  });
  await openLink(recipient, link);
  await recipient.getByRole('button', { name: 'Decrypt & download' }).click();
  const confirm = recipient.getByRole('button', { name: 'Download now' });
  if (await confirm.isVisible({ timeout: 1_500 }).catch(() => false)) await confirm.click();
  await expect(
    recipient.getByText('This file was modified in transit or storage. Download blocked.'),
  ).toBeVisible({ timeout: 30_000 });
  expect(tampered).toBeGreaterThan(0);
  expect(saved, 'a tampered file must never be saved').toBe(false);
  await expect(recipient.getByText('Integrity verified')).toHaveCount(0);
});

test('upload survives two injected 503s', async ({ page, newContext, leaks }) => {
  const file = randomFile('flaky-network.bin', 5 * 1024 * 1024);
  leaks.forbidText('file name', file.name);
  leaks.forbidBytes('plaintext bytes', file.buffer);

  let injected = 0;
  await page.context().route('**/api/drops/*/files/*/chunks/*', async (route) => {
    if (route.request().method() === 'PUT' && injected < 2) {
      injected += 1;
      await route.fulfill({
        status: 503,
        contentType: 'application/json',
        headers: { 'Retry-After': '0' },
        body: JSON.stringify({ error: { code: 'INTERNAL', message: 'injected outage' } }),
      });
      return;
    }
    await route.continue();
  });

  await page.goto('/');
  const link = await sendDrop(page, [file]);
  leaks.forbidText('link key', keyOf(link));
  expect(injected, 'the worker upload requests must be interceptable').toBe(2);
  // 2 chunks + 2 retried attempts reached the server side of the route (the 503s never did).
  expect(leaks.count('PUT', '/chunks/')).toBeGreaterThanOrEqual(4);

  const recipient = await (await newContext()).newPage();
  await openLink(recipient, link);
  const saved = await downloadFromReady(recipient, DOWNLOAD_DIR);
  expect(sha256(saved.buffer)).toBe(sha256(file.buffer));
});

test('compose view: limits, burn-after-reading option and empty submit', async ({ page }) => {
  await page.goto('/');
  const submit = page.getByRole('button', { name: 'Encrypt & upload' });
  await expect(submit).toBeDisabled();
  await composeDrop(page, [textFile('a.txt', 'A'), textFile('a.txt', 'BBBBBBBB')], {
    maxDownloads: 1,
  });
  await expect(page.getByText('a.txt')).toHaveCount(2);
  await expect(page.getByLabel('Download limit')).toHaveValue('1');
  await expect(submit).toBeEnabled();
});
