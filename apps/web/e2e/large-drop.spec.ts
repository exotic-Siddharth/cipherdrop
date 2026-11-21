/**
 * C-03 in a real browser engine (until now only jsdom covered it, ReceivePage.test.tsx): a file over 256 MiB can only
 * be saved by streaming it to disk through the File System Access API, which only Chromium-based desktop browsers
 * have. Elsewhere the receive page must refuse the drop up front, from the decrypted manifest, without calling /open,
 * so a burn-after-reading link keeps its one download for a browser that can save it.
 *
 * Firefox and WebKit (npm run e2e:cross) run the page as it is: they have no showSaveFilePicker. Chromium has it, so
 * there the test removes it before the app loads, which is the path a phone's Chrome takes. The drop is sent from
 * Node with a manifest that declares 300 MiB (support/senders.ts): the refusal is decided before any chunk is read.
 */
import { LIMITS } from '@cipherdrop/shared';
import { expect, test } from './support/fixtures';
import { disconnectDb, downloadCount, dropStatus } from './support/db';
import { openLink } from './support/flows';
import { sendFromNode } from './support/senders';

const MiB = 1024 * 1024;

test.afterAll(disconnectDb);

test('a drop with a file over 256 MiB is refused before /open where the browser cannot stream to disk (C-03) @cross', async ({
  page,
  request,
  baseURL,
  leaks,
  browserName,
}) => {
  const name = 'site-backup-2026-11.tar';
  const drop = await sendFromNode(
    request,
    baseURL!,
    [
      {
        name,
        type: 'application/x-tar',
        content: Buffer.from('CROSS-ENGINE-LARGE-DROP-MARKER'),
        declaredSize: 300 * MiB,
      },
    ],
    { maxDownloads: 1 },
  );
  expect(300 * MiB).toBeGreaterThan(LIMITS.BLOB_SAVE_MAX_BYTES);
  leaks.forbidKey('link key', drop.key);
  leaks.forbidText('file name', name);

  if (browserName === 'chromium') {
    await page.addInitScript(() => {
      delete (window as { showSaveFilePicker?: unknown }).showSaveFilePicker;
    });
  }
  await openLink(page, drop.link);
  expect(
    await page.evaluate(() => 'showSaveFilePicker' in window),
    'this engine (or the stub) has no File System Access API',
  ).toBe(false);

  const files = page.getByRole('list', { name: 'Files in this drop' });
  await expect(files.getByText(name)).toBeVisible({ timeout: 30_000 });
  await expect(files.getByText(/can't save it straight to disk/)).toBeVisible();
  await expect(page.getByText("This browser can't save every file in this drop")).toBeVisible();
  await expect(page.getByText(/1 of 1 downloads? left/)).toBeVisible();

  const download = page.getByRole('button', { name: 'Decrypt & download' });
  await expect(download).toBeDisabled();

  // The page has loaded, decrypted the manifest and refused: nothing on the way asked for a grant or a chunk (every
  // request is recorded when it is sent), and the server's count and status are unchanged.
  expect(leaks.count('POST', '/open'), 'no download grant was requested').toBe(0);
  expect(leaks.count('GET', '/chunks/'), 'no chunk was fetched').toBe(0);
  expect(await downloadCount(drop.dropId)).toBe(0);
  expect(await dropStatus(drop.dropId)).toBe('READY');
});
