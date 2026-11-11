/**
 * Receive-page states against the real API: unknown id, expired, deleted by the owner (Delete now), missing,
 * truncated and wrong keys, and links mangled by chat apps (Review Focus 3).
 */
import { expect, test } from './support/fixtures';
import { dropIdOf, expireDrop } from './support/db';
import { downloadFromReady, openLink, sendDrop, textFile } from './support/flows';
import crypto from 'node:crypto';
import path from 'node:path';

const DOWNLOAD_DIR = path.join(import.meta.dirname, '..', 'test-results', 'downloads');

test('unknown drop id shows "doesn\'t exist"', async ({ page }) => {
  await openLink(page, '/d/AAAAAAAAAAAAAAAAAAAAAA#' + 'A'.repeat(43));
  await expect(page.getByText("This drop doesn't exist")).toBeVisible({ timeout: 20_000 });
});

test('expired drop shows the expired state (no key needed to know)', async ({
  page,
  newContext,
}) => {
  const file = textFile('stale.txt', 'STATES-MARKER-1');
  await page.goto('/');
  const link = await sendDrop(page, [file], { expiryHours: 1, maxDownloads: 5 });
  await expireDrop(dropIdOf(link));
  const visitor = await (await newContext()).newPage();
  await openLink(visitor, link);
  await expect(visitor.getByText('This drop has expired')).toBeVisible({ timeout: 20_000 });
  await expect(visitor.getByRole('button', { name: 'Decrypt & download' })).toHaveCount(0);
});

test('"Delete now" on the success card kills the link', async ({ page, newContext }) => {
  const file = textFile('oops-wrong-file.txt', 'STATES-MARKER-2');
  await page.goto('/');
  const link = await sendDrop(page, [file], { maxDownloads: 5 });
  await page.getByRole('button', { name: /Delete now/ }).click();
  await page
    .getByRole('button', { name: /Delete (drop|now)/ })
    .last()
    .click();
  const visitor = await (await newContext()).newPage();
  await expect(async () => {
    await openLink(visitor, link);
    await expect(
      visitor.getByText('This drop was deleted').or(visitor.getByText("This drop doesn't exist")),
    ).toBeVisible({ timeout: 3_000 });
  }).toPass({ timeout: 20_000 });
});

test('missing, truncated and wrong keys; mangled links still open', async ({
  page,
  newContext,
}) => {
  const file = textFile('keyed.txt', 'STATES-MARKER-3');
  await page.goto('/');
  const link = await sendDrop(page, [file], { maxDownloads: 10 });
  const id = dropIdOf(link);
  const key = new URL(link).hash.slice(1);

  // A fresh page per link: a hash-only change on the same document would not re-run the page's key logic.
  const visit = async (url: string) => {
    const p = await (await newContext()).newPage();
    await openLink(p, url);
    return p;
  };

  // No key at all.
  await expect((await visit(`/d/${id}`)).getByText('This link is incomplete')).toBeVisible({
    timeout: 20_000,
  });
  // Truncated key (a chat app cut the link).
  await expect(
    (await visit(`/d/${id}#${key.slice(0, 30)}`)).getByText('This link is incomplete'),
  ).toBeVisible({
    timeout: 20_000,
  });
  // A well-formed but wrong key.
  await expect(
    (await visit(`/d/${id}#${crypto.randomBytes(32).toString('base64url')}`)).getByText(
      "This link's key doesn't open this drop",
    ),
  ).toBeVisible({ timeout: 20_000 });

  // Trailing punctuation or URL-encoding from a chat message: the link still opens.
  for (const mangled of [`${link}.`, `${link})`, `${link},`, `${link}%20`]) {
    await expect((await visit(mangled)).getByText('keyed.txt')).toBeVisible({ timeout: 20_000 });
  }
  const last = await visit(link);
  const saved = await downloadFromReady(last, DOWNLOAD_DIR);
  expect(saved.buffer.equals(file.buffer)).toBe(true);
});
