/**
 * Flaky-network behaviour against the real API (Review Focus 2, R11): a permanent upload failure shows a
 * retryable error, a reload resumes through upload-status and sends only the missing chunks, and a 409 on
 * complete is repaired by re-sending the named chunks.
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { expect, test } from './support/fixtures';
import { downloadFromReady, openLink, sendDrop, sha256 } from './support/flows';

const OUT_DIR = path.join(import.meta.dirname, '..', 'test-results', 'resume');
const DOWNLOAD_DIR = path.join(import.meta.dirname, '..', 'test-results', 'downloads');

function chunkIndexOf(url: string): number {
  const match = /\/chunks\/(\d+)$/.exec(new URL(url).pathname);
  return match ? Number(match[1]) : -1;
}

test('reload resumes an interrupted upload and sends only the missing chunks', async ({
  page,
  newContext,
  leaks,
}) => {
  test.setTimeout(120_000);
  fs.mkdirSync(OUT_DIR, { recursive: true });
  // 13 MB = 4 chunks of 4 MiB. A real file on disk keeps size + lastModified stable for the re-selection.
  const bytes = crypto.randomBytes(13 * 1024 * 1024);
  const filePath = path.join(OUT_DIR, 'resume-me.bin');
  fs.writeFileSync(filePath, bytes);
  leaks.forbidText('file name', 'resume-me.bin');
  leaks.forbidBytes('plaintext bytes', bytes);

  // The network "dies" after chunks 0 and 1: every later chunk PUT is aborted.
  const outage = async (route: import('@playwright/test').Route) => {
    if (route.request().method() === 'PUT' && chunkIndexOf(route.request().url()) >= 2) {
      await route.abort('connectionreset');
      return;
    }
    await route.continue();
  };
  await page.context().route('**/api/drops/*/files/*/chunks/*', outage);

  await page.goto('/');
  await page.getByTestId('file-input').setInputFiles(filePath);
  await page.getByRole('button', { name: 'Encrypt & upload' }).click();
  await expect(page.getByText('The upload did not finish')).toBeVisible({ timeout: 90_000 });
  await expect(page.getByRole('button', { name: 'Try again' })).toBeVisible();
  await expect(page.getByText(/Chunks that already arrived are kept/)).toBeVisible();

  // Network is back; the tab is reloaded (sessionStorage keeps the resume record, without file names).
  await page.context().unroute('**/api/drops/*/files/*/chunks/*', outage);
  const record = await page.evaluate(() => sessionStorage.getItem('cd-upload-resume'));
  expect(record).not.toBeNull();
  expect(record).not.toContain('resume-me');
  await page.reload();
  await expect(page.getByText('An upload in this tab was interrupted')).toBeVisible({
    timeout: 20_000,
  });

  // Re-selecting the same file matches the record.
  const putsBefore = leaks.count('PUT', '/chunks/');
  await page.getByTestId('file-input').setInputFiles(filePath);
  await expect(page.getByText('Ready to resume your upload')).toBeVisible({ timeout: 20_000 });
  await page.getByRole('button', { name: 'Resume upload' }).click();
  await expect(page.getByText('Your encrypted link is ready')).toBeVisible({ timeout: 90_000 });
  const link = await page.getByLabel('Share link').inputValue();
  leaks.forbidText('link key', new URL(link).hash.slice(1));
  // Chunks 2 and 3 only: 0 and 1 were already stored (verified by hash, not re-sent).
  expect(leaks.count('PUT', '/chunks/') - putsBefore).toBe(2);
  expect(await page.evaluate(() => sessionStorage.getItem('cd-upload-resume'))).toBeNull();

  const recipient = await (await newContext()).newPage();
  await openLink(recipient, link);
  const saved = await downloadFromReady(recipient, DOWNLOAD_DIR);
  expect(sha256(saved.buffer)).toBe(sha256(bytes));
  fs.rmSync(filePath);
});

test('409 on complete: the client re-sends the named chunks and completes', async ({
  page,
  newContext,
  leaks,
}) => {
  const bytes = crypto.randomBytes(5 * 1024 * 1024);
  leaks.forbidText('file name', 'repair-me.bin');
  leaks.forbidBytes('plaintext bytes', bytes);

  let fileId = '';
  page.on('request', (req) => {
    if (req.method() === 'POST' && new URL(req.url()).pathname === '/api/drops') {
      const body = req.postDataJSON() as { files: { id: string }[] };
      fileId = body.files[0]!.id;
    }
  });
  let answered409 = 0;
  await page.context().route('**/api/drops/*/complete', async (route) => {
    if (answered409 === 0) {
      answered409 += 1;
      await route.fulfill({
        status: 409,
        contentType: 'application/json',
        body: JSON.stringify({
          error: {
            code: 'CONFLICT',
            message: 'Some chunks are missing',
            details: { missing: [{ fileId, indexes: [0] }] },
          },
        }),
      });
      return;
    }
    await route.continue();
  });

  await page.goto('/');
  const link = await sendDrop(page, [
    { name: 'repair-me.bin', mimeType: 'application/octet-stream', buffer: bytes },
  ]);
  expect(answered409).toBe(1);
  // 2 chunks + the repaired chunk 0.
  expect(leaks.count('PUT', '/chunks/')).toBe(3);
  leaks.forbidText('link key', new URL(link).hash.slice(1));

  const recipient = await (await newContext()).newPage();
  await openLink(recipient, link);
  const saved = await downloadFromReady(recipient, DOWNLOAD_DIR);
  expect(sha256(saved.buffer)).toBe(sha256(bytes));
});

test('a permanently failing upload shows a retryable error and Try again succeeds once the network is back', async ({
  page,
  newContext,
  leaks,
}) => {
  test.setTimeout(120_000);
  const bytes = crypto.randomBytes(2 * 1024 * 1024);
  leaks.forbidText('file name', 'retry-me.bin');
  leaks.forbidBytes('plaintext bytes', bytes);
  const down = async (route: import('@playwright/test').Route) => {
    if (route.request().method() === 'PUT') {
      await route.fulfill({
        status: 503,
        contentType: 'application/json',
        body: '{"error":{"code":"INTERNAL","message":"down"}}',
      });
      return;
    }
    await route.continue();
  };
  await page.context().route('**/api/drops/*/files/*/chunks/*', down);
  await page.goto('/');
  await page.getByTestId('file-input').setInputFiles({
    name: 'retry-me.bin',
    mimeType: 'application/octet-stream',
    buffer: bytes,
  });
  await page.getByRole('button', { name: 'Encrypt & upload' }).click();
  await expect(page.getByText('The upload did not finish')).toBeVisible({ timeout: 90_000 });
  await page.context().unroute('**/api/drops/*/files/*/chunks/*', down);
  await page.getByRole('button', { name: 'Try again' }).click();
  await expect(page.getByText('Your encrypted link is ready')).toBeVisible({ timeout: 90_000 });
  const link = await page.getByLabel('Share link').inputValue();
  leaks.forbidText('link key', new URL(link).hash.slice(1));
  const recipient = await (await newContext()).newPage();
  await openLink(recipient, link);
  const saved = await downloadFromReady(recipient, DOWNLOAD_DIR);
  expect(sha256(saved.buffer)).toBe(sha256(bytes));
});
