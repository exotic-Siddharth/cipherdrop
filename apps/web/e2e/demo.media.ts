/**
 * Media run, part 2 (playwright.media.config.ts; `npm run media -w @cipherdrop/web`): records the docs/DEMO.md flow
 * with Playwright's video recorder (recordVideo), one browser context per scene, and joins the scenes into
 * docs/screenshots/demo.gif with ffmpeg: 960 px wide, under 6 MB. Without ffmpeg on the PATH the run keeps the WebM
 * scenes in test-results/media-video and says so.
 *
 * The scenes follow DEMO.md: send with burn after reading, the key after #, a fresh browser decrypts, the reload
 * finds the drop burned, one flipped byte blocks the save, a password link, the zero-knowledge account (dashboard,
 * locked vault after a reload, activity log) and the honest limitations. The recorder draws the pointer; the
 * captions are a plain element added to the page with DOM calls (textContent and CSSOM, so no HTML string reaches a
 * Trusted Types sink and the leak guard's CSP check stays as strict as in `npm run e2e`). The chunk uploads are
 * slowed down on purpose (a route delays each PUT) so the progress and the ciphertext strip stay on screen: the
 * MB/s shown in the clip is not a measurement.
 */
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import type { BrowserContext, Page, Route } from '@playwright/test';
import { accountMenu, composeDrop, waitForDashboard } from './support/flows';
import {
  SEED_DROP_PASSWORD,
  SHOTS_DIR,
  VIDEO_DIR,
  demoFiles,
  expect,
  prepareOutput,
  seedE2eDatabase,
  seedPasswordLink,
  seedPasswords,
  test,
} from './support/media';
import { sendFromNode } from './support/senders';

/** The recorded viewport, and the GIF made from it. */
const VIDEO = { width: 1152, height: 720 } as const;
const GIF_WIDTH = 960;
const GIF_FPS = 8;
const GIF_COLORS = 96;
const GIF_MAX_BYTES = 6 * 1024 * 1024;

const NOTE = 'Photos from the site visit, as promised.';
const TAMPERED = 'This file was modified in transit or storage. Download blocked.';

test.beforeAll(() => {
  prepareOutput();
  seedE2eDatabase();
});

/** The caption bar along the bottom of the frame (CSSOM properties, applied with Object.assign). */
const CAPTION_STYLE = {
  position: 'fixed',
  left: '50%',
  bottom: '22px',
  transform: 'translateX(-50%)',
  width: 'max-content',
  maxWidth: '900px',
  padding: '12px 22px',
  borderRadius: '12px',
  background: 'rgba(11, 16, 20, 0.92)',
  color: '#fff',
  textAlign: 'center',
  font: "600 21px/1.4 'Inter Variable', system-ui, sans-serif",
  boxShadow: '0 8px 28px rgba(0, 0, 0, 0.35)',
  zIndex: '2147483647',
  pointerEvents: 'none',
} as const;

/** Shows a caption, holds the frame long enough to read it, then takes the caption away again. */
async function say(page: Page, text: string, holdMs = 3_000): Promise<void> {
  await page.evaluate(
    ({ text, style }) => {
      const el = document.createElement('div');
      el.dataset.mediaCaption = '';
      el.textContent = text;
      Object.assign(el.style, style);
      document.body.append(el);
    },
    { text, style: CAPTION_STYLE },
  );
  await page.waitForTimeout(holdMs);
  await page.evaluate(() => document.querySelector('[data-media-caption]')?.remove());
}

/** Flip one byte in the middle of every chunk the recipient downloads (e2e drops.spec.ts test 4). */
async function tamperChunks(route: Route): Promise<void> {
  const response = await route.fetch();
  const body = Buffer.from(await response.body());
  body[Math.floor(body.length / 2)] ^= 0x01;
  await route.fulfill({ response, body });
}

test('the DEMO.md flow, recorded and turned into docs/screenshots/demo.gif', async ({
  open,
  leaks,
  request,
  baseURL,
}, testInfo) => {
  test.setTimeout(5 * 60_000);
  fs.rmSync(VIDEO_DIR, { recursive: true, force: true });
  fs.mkdirSync(VIDEO_DIR, { recursive: true });
  const { demo } = seedPasswords();
  const [photo, pdf] = demoFiles();
  for (const file of [photo!, pdf!]) leaks.forbidText('file name', file.name);
  leaks.forbidText('note', NOTE);
  leaks.forbidText('demo password', demo);
  leaks.forbidText('drop password', SEED_DROP_PASSWORD);
  leaks.forbidBytes('document bytes', pdf!.buffer);

  /** Each scene's video, and how many seconds of it to skip: the blank page and the first load. */
  const scenes: { file: string; skip: number }[] = [];
  /** One recorded browser per scene. A scene calls `start()` once its first view is ready to watch. */
  const scene = async (
    run: (page: Page, context: BrowserContext, start: () => void) => Promise<void>,
  ) => {
    const context = await open({
      device: { viewport: VIDEO, deviceScaleFactor: 1 },
      recordVideo: {
        dir: VIDEO_DIR,
        size: VIDEO,
        showActions: {
          cursor: 'pointer',
          duration: 900,
          style: {
            title: 'display: none',
            highlight: 'outline: 3px solid rgba(20, 184, 166, 0.9); border-radius: 8px',
          },
        },
      },
    });
    const opened = performance.now();
    let startsAt = opened;
    const page = await context.newPage();
    await run(page, context, () => (startsAt = performance.now()));
    await context.close();
    scenes.push({
      file: await page.video()!.path(),
      skip: Math.max(0, (startsAt - opened) / 1000 - 0.3),
    });
  };

  let link = '';
  await scene(async (page, context, start) => {
    await page.goto('/');
    await expect(page.getByRole('button', { name: 'Browse files' })).toBeVisible();
    start();
    await say(page, 'CipherDrop encrypts files in the browser with AES-256-GCM before upload.');
    await composeDrop(page, [photo!, pdf!], { maxDownloads: 1, note: NOTE });
    await say(page, 'Burn after reading: one download, then the link is dead.', 2_500);
    await context.route('**/api/drops/*/files/*/chunks/*', async (route) => {
      if (route.request().method() === 'PUT') await new Promise((r) => setTimeout(r, 600));
      await route.continue();
    });
    await page.getByRole('button', { name: 'Encrypt & upload' }).click();
    await say(page, 'The strip shows the real ciphertext leaving this device, chunk by chunk.');
    await expect(page.getByText('Your encrypted link is ready')).toBeVisible({ timeout: 90_000 });
    link = await page.getByLabel('Share link').inputValue();
    leaks.forbidKey('link key', new URL(link).hash.slice(1));
    await page.getByLabel('Share link').hover();
    await say(
      page,
      'The key sits after the # in the link. Browsers never send that part to a server.',
      3_500,
    );
  });

  await scene(async (page, _context, start) => {
    await page.goto(link);
    await expect(page.getByRole('button', { name: 'Decrypt & download' })).toBeVisible();
    start();
    await say(
      page,
      'A fresh browser opens the link: names and note are decrypted here, with its key.',
      3_500,
    );
    await page.getByRole('button', { name: 'Decrypt & download' }).click();
    await page.getByRole('button', { name: 'Download now' }).click();
    await expect(page.getByText('Integrity verified')).toHaveCount(3);
    await page.mouse.wheel(0, 300);
    await say(
      page,
      'Every chunk is authenticated as it arrives: "Integrity verified", byte for byte.',
      3_500,
    );
    await page.reload();
    await expect(page.getByText('All downloads have been used')).toBeVisible();
    await say(page, 'Reload: burned. The server used up the only download in one atomic update.');
  });

  const target = await sendFromNode(
    request,
    baseURL!,
    [{ name: photo!.name, type: photo!.mimeType, content: photo!.buffer }],
    { maxDownloads: 5, note: NOTE },
  );
  leaks.forbidKey('second link key', target.key);
  await scene(async (page, context, start) => {
    await context.route('**/api/drops/*/files/*/chunks/*', tamperChunks);
    await page.goto(target.link);
    await expect(page.getByRole('button', { name: 'Decrypt & download' })).toBeVisible();
    start();
    await say(
      page,
      'Now one byte of the ciphertext is flipped on its way to the browser...',
      2_500,
    );
    await page.getByRole('button', { name: 'Decrypt & download' }).click();
    await expect(page.getByText(TAMPERED)).toBeVisible();
    await say(page, '...the authentication check fails, and nothing is saved.');
  });

  await scene(async (page, _context, start) => {
    await page.goto(seedPasswordLink(baseURL!));
    await expect(page.getByText('This drop is password protected')).toBeVisible();
    start();
    await say(
      page,
      'A password link carries no key. Argon2id stretches the password in a Web Worker.',
    );
    const wrong = 'not the password';
    leaks.forbidText('wrong password', wrong);
    await page.getByLabel('Password', { exact: true }).fill(wrong);
    await page.getByRole('button', { name: 'Unlock' }).click();
    await expect(
      page.getByText(/wrong password|incorrect|did not match|doesn't match/i),
    ).toBeVisible();
    await say(page, 'A wrong password reveals nothing...', 2_000);
    await page.getByLabel('Password', { exact: true }).fill(SEED_DROP_PASSWORD);
    await page.getByRole('button', { name: 'Unlock' }).click();
    await expect(page.getByText('diagram.png').first()).toBeVisible();
    await say(page, '...the right one unwraps the drop key, in the browser.', 2_500);
  });

  await scene(async (page, _context, start) => {
    await page.goto('/login');
    await expect(page.getByRole('button', { name: 'Use demo account' })).toBeVisible();
    start();
    await page.getByRole('button', { name: 'Use demo account' }).click();
    await say(page, 'Accounts are zero-knowledge too: the password never leaves the browser.');
    await page.getByRole('button', { name: 'Log in', exact: true }).click();
    await waitForDashboard(page);
    await expect(page.getByText('welcome.txt')).toBeVisible();
    await say(page, 'It unwraps an account key, which decrypts the file names on any device.');
    await page.reload();
    await expect(page.getByRole('button', { name: /Unlock/ })).toBeVisible();
    await say(page, 'After a reload the key is gone from memory, so the vault is locked.');
    await page.getByLabel('Password', { exact: true }).fill(demo);
    await page.getByRole('button', { name: /Unlock/ }).click();
    await waitForDashboard(page);
    await accountMenu(page, 'Settings');
    await page.getByRole('tab', { name: 'Activity' }).click();
    await expect(page.getByRole('tabpanel')).toBeVisible();
    await say(page, 'The activity log keeps IP prefixes and the browser, never full addresses.');
    await page.getByRole('link', { name: 'How it works', exact: true }).first().click();
    await page.locator('#limits').scrollIntoViewIfNeeded();
    await say(
      page,
      'And the limits are written down, next to what the server can and cannot see.',
      3_500,
    );
  });

  // Join the scenes, each without its loading frames; GIF_FPS frames a second at most, frames that did not change
  // dropped (mpdecimate, with the frame delays kept), one palette for the clip, and each frame stores only the
  // rectangle that changed.
  const gif = path.join(SHOTS_DIR, 'demo.gif');
  const filter =
    scenes
      .map((s, i) => `[${i}:v]trim=start=${s.skip.toFixed(2)},setpts=PTS-STARTPTS[s${i}];`)
      .join('') +
    `${scenes.map((_, i) => `[s${i}]`).join('')}concat=n=${scenes.length}:v=1:a=0,` +
    `fps=${GIF_FPS},scale=${GIF_WIDTH}:-2:flags=lanczos,mpdecimate,split[a][b];` +
    `[a]palettegen=max_colors=${GIF_COLORS}:stats_mode=diff[p];` +
    `[b][p]paletteuse=dither=none:diff_mode=rectangle`;
  const args = ['-y', '-loglevel', 'error', ...scenes.flatMap((s) => ['-i', s.file])];
  try {
    execFileSync(
      'ffmpeg',
      [...args, '-filter_complex', filter, '-fps_mode', 'vfr', '-loop', '0', gif],
      { stdio: 'pipe' },
    );
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== 'ENOENT') throw err;
    const note = `ffmpeg is not on the PATH: ${gif} was not rebuilt; the scenes are in ${VIDEO_DIR}`;
    testInfo.annotations.push({ type: 'media', description: note });
    console.warn(note);
    return;
  }
  expect(fs.statSync(gif).size, 'demo.gif stays small enough for the README').toBeLessThan(
    GIF_MAX_BYTES,
  );
});
