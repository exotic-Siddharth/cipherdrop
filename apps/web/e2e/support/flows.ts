/** Reusable browser flows for the e2e specs. Everything goes through the real UI and the real API. */
import crypto from 'node:crypto';
import fs from 'node:fs';
import { expect, type Page } from '@playwright/test';
import * as OTPAuth from 'otpauth';

export const sha256 = (bytes: Buffer): string =>
  crypto.createHash('sha256').update(bytes).digest('hex');

let counter = 0;
export function uniqueEmail(tag: string): string {
  counter += 1;
  return `${tag}-${Date.now().toString(36)}-${counter}@e2e.cipherdrop.test`;
}

/** Passwords are random per run so a fixed string can never be the thing a test "finds" in a request. */
export function randomPassword(): string {
  return `e2e ${crypto.randomBytes(6).toString('hex')} horse battery staple`;
}

export interface TestFile {
  name: string;
  mimeType: string;
  buffer: Buffer;
}

export function randomFile(
  name: string,
  bytes: number,
  mimeType = 'application/octet-stream',
): TestFile {
  return { name, mimeType, buffer: crypto.randomBytes(bytes) };
}

/** A text file whose content is unmistakable (so a plaintext leak cannot be a coincidence). */
export function textFile(name: string, marker: string): TestFile {
  const body = `${marker} :: ${'The quick brown fox jumps over the lazy dog. '.repeat(40)}`;
  return { name, mimeType: 'text/plain', buffer: Buffer.from(body, 'utf8') };
}

export async function registerAccount(
  page: Page,
  email: string,
  password: string,
): Promise<{ recoveryKey: string }> {
  await page.goto('/register');
  await page.getByLabel('Email').fill(email);
  await page.getByLabel('Password', { exact: true }).fill(password);
  await page.getByLabel('Confirm password').fill(password);
  await page.getByRole('button', { name: 'Create account' }).click();
  const group = page.getByRole('group', { name: 'Your recovery key' });
  await expect(group).toBeVisible({ timeout: 30_000 });
  const rows = await group.getByTestId('recovery-key-row').allInnerTexts();
  const recoveryKey = rows.map((r) => r.trim()).join('-');
  expect(recoveryKey).toMatch(/^([0-9A-Z]{4}-){7}[0-9A-Z]{4}$/);
  const cont = page.getByRole('button', { name: 'Continue' });
  await expect(cont).toBeDisabled();
  await page.getByLabel('I saved my recovery key').check();
  await cont.click();
  await expect(page).toHaveURL(/\/dashboard$/);
  return { recoveryKey };
}

export async function logIn(page: Page, email: string, password: string): Promise<void> {
  await page.goto('/login');
  await page.getByLabel('Email').fill(email);
  await page.getByLabel('Password', { exact: true }).fill(password);
  await page.getByRole('button', { name: 'Log in', exact: true }).click();
}

export async function waitForDashboard(page: Page): Promise<void> {
  await expect(page).toHaveURL(/\/dashboard$/, { timeout: 30_000 });
}

export interface SendOptions {
  password?: string;
  /** Download limit; 1 selects "burn after reading". */
  maxDownloads?: number;
  expiryHours?: number;
  note?: string;
}

/** Fill the Send form with the files and options, without clicking Encrypt & upload. */
export async function composeDrop(
  page: Page,
  files: TestFile[],
  opts: SendOptions = {},
): Promise<void> {
  await page.getByTestId('file-input').setInputFiles(files);
  if (opts.expiryHours !== undefined) {
    await page.getByLabel('Expires after').selectOption(String(opts.expiryHours));
  }
  if (opts.maxDownloads !== undefined) {
    await page.getByLabel('Download limit').selectOption(String(opts.maxDownloads));
  }
  if (opts.note) await page.getByLabel('Note for the recipient').fill(opts.note);
  if (opts.password) {
    await page.getByRole('switch', { name: /Protect with a password/ }).click();
    await page.getByLabel('Password', { exact: true }).fill(opts.password);
  }
}

/** Compose, click Encrypt & upload, wait for the success card and return the share link. */
export async function sendDrop(
  page: Page,
  files: TestFile[],
  opts: SendOptions = {},
): Promise<string> {
  await composeDrop(page, files, opts);
  await page.getByRole('button', { name: 'Encrypt & upload' }).click();
  await expect(page.getByText('Your encrypted link is ready')).toBeVisible({ timeout: 90_000 });
  return page.getByLabel('Share link').inputValue();
}

export async function openLink(page: Page, link: string, password?: string): Promise<void> {
  await page.goto(link);
  if (password !== undefined) {
    await page.getByLabel('Password', { exact: true }).fill(password);
    await page.getByRole('button', { name: 'Unlock' }).click();
  }
}

export interface Downloaded {
  buffer: Buffer;
  filename: string;
}

/** Click Decrypt & download (confirming the "last download" dialog when it shows) and read the saved file. */
export async function downloadFromReady(page: Page, outDir: string): Promise<Downloaded> {
  const button = page.getByRole('button', { name: 'Decrypt & download' });
  await expect(button).toBeVisible({ timeout: 30_000 });
  const downloadPromise = page.waitForEvent('download', { timeout: 120_000 });
  await button.click();
  const confirm = page.getByRole('button', { name: 'Download now' });
  if (await confirm.isVisible({ timeout: 1_500 }).catch(() => false)) await confirm.click();
  const download = await downloadPromise;
  const file = `${outDir}/${Date.now()}-${crypto.randomBytes(3).toString('hex')}.bin`;
  await download.saveAs(file);
  const buffer = fs.readFileSync(file);
  fs.rmSync(file);
  return { buffer, filename: download.suggestedFilename() };
}

/** The current 6-digit code, or the NEXT window's code (R23: avoids the replay guard without sleeping). */
export function totpCode(secretBase32: string, nextWindow = false): string {
  const totp = new OTPAuth.TOTP({
    algorithm: 'SHA1',
    digits: 6,
    period: 30,
    secret: OTPAuth.Secret.fromBase32(secretBase32.replace(/\s+/g, '')),
  });
  return totp.generate({ timestamp: Date.now() + (nextWindow ? 30_000 : 0) });
}

export async function expectNoHorizontalScroll(page: Page): Promise<void> {
  const overflow = await page.evaluate(
    () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
  );
  expect(overflow, 'page has horizontal overflow').toBeLessThanOrEqual(1);
}

/** Open the account menu in the navbar and pick an item (desktop viewport). */
export async function accountMenu(
  page: Page,
  item: 'Dashboard' | 'Settings' | 'Admin console' | 'Lock vault' | 'Sign out',
): Promise<void> {
  await page.getByRole('button', { name: /account menu$/ }).click();
  await page.getByRole('menuitem', { name: item }).click();
}
