/**
 * Helpers of the media run (playwright.media.config.ts): browser contexts with a frozen clock, screenshots in both
 * themes, the seed, and the demo picture. Nothing here is used by `npm run e2e`.
 */
import { execFileSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { crc32, deflateSync } from 'node:zlib';
import type { BrowserContext, BrowserContextOptions, Page } from '@playwright/test';
import { E2E_API_PORT, E2E_WEB_PORT } from '../../playwright.config';
import { test as base, expect } from './fixtures';
import type { TestFile } from './flows';

const webDir = path.resolve(import.meta.dirname, '..', '..');
const repoRoot = path.resolve(webDir, '..', '..');
const apiRoot = path.join(repoRoot, 'apps', 'api');

/** Where the screenshots go (committed) and where the raw recordings go (gitignored). */
export const SHOTS_DIR = path.join(repoRoot, 'docs', 'screenshots');
export const VIDEO_DIR = path.join(webDir, 'test-results', 'media-video');

/** Screenshots meant for people: a desktop and a phone viewport, both at deviceScaleFactor 2. */
export const DESKTOP = { viewport: { width: 1440, height: 900 }, deviceScaleFactor: 2 } as const;
export const PHONE = {
  viewport: { width: 390, height: 844 },
  deviceScaleFactor: 2,
  isMobile: true,
  hasTouch: true,
} as const;

export type Theme = 'light' | 'dark';
export const BOTH: readonly Theme[] = ['light', 'dark'];
export const LIGHT: readonly Theme[] = ['light'];

/** The seed's accounts, with the passwords playwright.media.config.ts picked for this run. */
export const DEMO_EMAIL = 'demo@cipherdrop.local';
export const ADMIN_EMAIL = 'admin@cipherdrop.local';
export function seedPasswords(): { demo: string; admin: string } {
  const demo = process.env.MEDIA_DEMO_PASSWORD;
  const admin = process.env.MEDIA_ADMIN_PASSWORD;
  if (!demo || !admin) throw new Error('run the media specs with -c playwright.media.config.ts');
  return { demo, admin };
}

/** The seeded password drop (diagram.png): seed.ts derives its id from its label, and its password is fixed. */
export const SEED_DROP_PASSWORD = 'correct horse battery staple';
export const seedPasswordLink = (baseURL: string): string =>
  `${baseURL}/d/${crypto
    .createHash('sha256')
    .update('cipherdrop-seed/diagram')
    .digest()
    .subarray(0, 16)
    .toString('base64url')}`;

/**
 * Runs apps/api/prisma/seed.ts against the e2e database and blob directory the e2e API uses
 * (playwright.config.ts). Idempotent, like the seed. Its output (passwords, links) is not printed.
 */
export function seedE2eDatabase(): void {
  const { demo, admin } = seedPasswords();
  execFileSync(process.execPath, ['--import', 'tsx', 'prisma/seed.ts'], {
    cwd: apiRoot,
    stdio: 'pipe',
    env: {
      ...process.env,
      NODE_ENV: 'development',
      DATABASE_URL:
        'postgresql://cipherdrop:cipherdrop@localhost:55433/cipherdrop_e2e?schema=public',
      REDIS_URL: 'redis://localhost:56380/9',
      KEY_PREFIX: 'cd-e2e',
      STORAGE_DRIVER: 'local',
      STORAGE_DIR: './data/e2e-blobs',
      API_PORT: String(E2E_API_PORT),
      WEB_ORIGIN: `http://localhost:${E2E_WEB_PORT}`,
      SEED_DEMO_PASSWORD: demo,
      SEED_ADMIN_PASSWORD: admin,
    },
  });
}

export interface ContextOptions extends Pick<BrowserContextOptions, 'recordVideo'> {
  device?:
    typeof DESKTOP | typeof PHONE | Pick<BrowserContextOptions, 'viewport' | 'deviceScaleFactor'>;
}

/**
 * The e2e fixtures plus `open()`: a new browser context watched by the leak guard, with its clock frozen at the
 * current time. Date stands still (no countdown moves between two screenshots, "expires in 60 minutes" stays 60)
 * while timers keep running. The time is the real one, not a fixed date: the server stamps drops with its own
 * clock, and a browser ahead of it would treat fresh access tokens as expired. Contexts still open at the end are
 * closed before the leak guard's verdict, like the e2e newContext() fixture.
 */
export const test = base.extend<{ open: (options?: ContextOptions) => Promise<BrowserContext> }>({
  open: async ({ browser, leaks, guard: _guard }, provide) => {
    const opened: BrowserContext[] = [];
    await provide(async ({ device = DESKTOP, recordVideo } = {}) => {
      const context = await browser.newContext({ ...device, recordVideo, acceptDownloads: true });
      await context.clock.setFixedTime(new Date());
      leaks.watch(context);
      opened.push(context);
      return context;
    });
    for (const context of opened) await context.close();
  },
});
export { expect };

/** Switch the theme the way a second tab would: write the preference and fire the storage event the app syncs on. */
export async function setTheme(page: Page, theme: Theme): Promise<void> {
  await page.evaluate((t) => {
    window.localStorage.setItem('cd-theme', t);
    window.dispatchEvent(new StorageEvent('storage', { key: 'cd-theme', newValue: t }));
  }, theme);
  const html = page.locator('html');
  if (theme === 'dark') await expect(html).toHaveClass(/(^|\s)dark(\s|$)/);
  else await expect(html).not.toHaveClass(/(^|\s)dark(\s|$)/);
}

/**
 * Screenshots of the top of the current page in each theme, as docs/screenshots/<name>-<theme>.png, viewport only.
 * Focus and hover are cleared first, toasts are left to close (the pointer rests on the left edge, away from them:
 * hovering would pause them) and CSS animations are stopped, so a picture never catches a transition. Returns the
 * PNGs.
 */
export async function shoot(
  page: Page,
  name: string,
  themes: readonly Theme[] = BOTH,
): Promise<Record<Theme, Buffer | undefined>> {
  const out: Record<Theme, Buffer | undefined> = { light: undefined, dark: undefined };
  const size = page.viewportSize();
  if (size) await page.mouse.move(1, Math.round(size.height / 2));
  await expect(page.locator('[data-sonner-toast]')).toHaveCount(0);
  await page.evaluate(async () => {
    (document.activeElement as HTMLElement | null)?.blur();
    window.scrollTo(0, 0);
    await document.fonts.ready;
  });
  for (const theme of themes) {
    await setTheme(page, theme);
    out[theme] = await page.screenshot({
      path: path.join(SHOTS_DIR, `${name}-${theme}.png`),
      animations: 'disabled',
    });
  }
  return out;
}

/** Wait until every <img> on the page has decoded (the receive page's image preview). */
export async function imagesLoaded(page: Page): Promise<void> {
  await expect
    .poll(() =>
      page.evaluate(() =>
        [...document.images].every((img) => img.complete && img.naturalWidth > 0),
      ),
    )
    .toBe(true);
}

/**
 * The demo picture: a landscape (sky, sun, two mountains) as an RGB PNG, drawn here so the media run needs no binary
 * fixture. The sky only changes from top to bottom, so it stays clean bands in the GIF's limited palette, and rows
 * use PNG's Sub filter, which keeps the file small.
 */
export function landscapePng(width = 640, height = 400): TestFile {
  const mix = (a: number[], b: number[], t: number) => a.map((v, i) => v + (b[i]! - v) * t);
  const skyTop = [92, 98, 210];
  const skyBottom = [108, 201, 219];
  const sun = [249, 225, 167];
  const back = [21, 94, 91];
  const front = [17, 68, 79];
  // Inside the triangle with apex (ax, ay) and base along the bottom from x0 to x1.
  const inMountain = (x: number, y: number, ax: number, ay: number, x0: number, x1: number) =>
    y >= ay &&
    x >= ax - ((ax - x0) * (y - ay)) / (height - ay) &&
    x <= ax + ((x1 - ax) * (y - ay)) / (height - ay);
  const rows: Buffer[] = [];
  for (let y = 0; y < height; y++) {
    const row = Buffer.alloc(1 + width * 3);
    row[0] = 1; // Sub filter
    let prev = [0, 0, 0];
    for (let x = 0; x < width; x++) {
      let c = mix(skyTop, skyBottom, y / height);
      if ((x - width * 0.75) ** 2 + (y - height * 0.34) ** 2 <= (width * 0.125) ** 2) c = sun;
      if (inMountain(x, y, width * 0.33, height * 0.5, -width * 0.05, width * 0.72)) c = back;
      if (inMountain(x, y, width * 0.69, height * 0.4, width * 0.31, width * 1.05)) c = front;
      const px = c.map((v) => Math.round(v));
      for (let i = 0; i < 3; i++) row[1 + x * 3 + i] = (px[i]! - prev[i]! + 256) & 0xff;
      prev = px;
    }
    rows.push(row);
  }
  const chunk = (type: string, data: Buffer) => {
    const body = Buffer.concat([Buffer.from(type, 'latin1'), data]);
    const len = Buffer.alloc(4);
    len.writeUInt32BE(data.length);
    const crc = Buffer.alloc(4);
    crc.writeUInt32BE(crc32(body));
    return Buffer.concat([len, body, crc]);
  };
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr.set([8, 2, 0, 0, 0], 8); // 8-bit RGB
  const buffer = Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', ihdr),
    chunk('IDAT', deflateSync(Buffer.concat(rows), { level: 9 })),
    chunk('IEND', Buffer.alloc(0)),
  ]);
  return { name: 'site-photo-march.png', mimeType: 'image/png', buffer };
}

/** The three files of the send and receive screenshots: a picture, a 24 MB document and a short text. */
export function demoFiles(): TestFile[] {
  return [
    landscapePng(),
    {
      name: 'Q3 financial summary (final).pdf',
      mimeType: 'application/pdf',
      buffer: crypto.randomBytes(24 * 1024 * 1024),
    },
    {
      name: 'meeting-notes.txt',
      mimeType: 'text/plain',
      buffer: Buffer.from('Agenda: site visit, budget, next steps.\n', 'utf8'),
    },
  ];
}

export const DEMO_NOTE = 'Here are the files from Tuesday. The photo is the one we talked about.';

/** Make sure the output directories exist. */
export function prepareOutput(): void {
  fs.mkdirSync(SHOTS_DIR, { recursive: true });
  fs.mkdirSync(VIDEO_DIR, { recursive: true });
}
