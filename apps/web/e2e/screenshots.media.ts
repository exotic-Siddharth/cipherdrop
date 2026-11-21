/**
 * Media run, part 1 (playwright.media.config.ts; `npm run media -w @cipherdrop/web`): regenerates every PNG in
 * docs/screenshots at deviceScaleFactor 2, in light and dark where both exist. Desktop is 1440x900, the phone 390x844.
 *
 * - send-*, receive-* and receive-tamper-blocked-*: one anonymous drop sent through the UI (3 files, 24 MB, 1 hour,
 *   5 downloads). send-progress-* holds the upload part-way with a route that parks the chunk PUTs after the fifth,
 *   so its MB/s and ETA describe a stalled upload, not a measurement. The tamper shots flip one byte of every chunk
 *   response in flight, as e2e test 4 does, and the page blocks the save.
 * - receive-burned, receive-password, register-recovery-key, totp-setup and login-2fa: light only. The burned drop
 *   comes from the Node sender (e2e/support/senders.ts); the password prompt is the seeded diagram.png drop.
 * - dashboard-*, settings-*, admin-*: the seeded demo and admin accounts (apps/api/prisma/seed.ts); the admin turns
 *   on two-step verification first, as the console requires.
 * - hero.png: the sender's dark upload view and the recipient's light receive view side by side, 1280x640 (the size
 *   GitHub's social preview asks for).
 *
 * The leak guard of every e2e test runs here too: no file name, note, password or link key in any request.
 */
import path from 'node:path';
import type { Page, Route } from '@playwright/test';
import {
  accountMenu,
  composeDrop,
  downloadFromReady,
  logIn,
  openLink,
  randomPassword,
  totpCode,
  waitForDashboard,
} from './support/flows';
import {
  ADMIN_EMAIL,
  DEMO_EMAIL,
  DEMO_NOTE,
  DESKTOP,
  LIGHT,
  PHONE,
  SEED_DROP_PASSWORD,
  SHOTS_DIR,
  demoFiles,
  expect,
  imagesLoaded,
  prepareOutput,
  seedE2eDatabase,
  seedPasswordLink,
  seedPasswords,
  shoot,
  test,
} from './support/media';
import { sendFromNode } from './support/senders';

const DOWNLOAD_DIR = path.join(import.meta.dirname, '..', 'test-results', 'downloads');
const TAMPERED = 'This file was modified in transit or storage. Download blocked.';

test.describe.configure({ mode: 'serial' });

/** The two halves of hero.png, captured on the way. */
const hero: { sending?: Buffer; received?: Buffer } = {};

test.beforeAll(() => {
  prepareOutput();
  seedE2eDatabase();
});

/** Flip one byte in the middle of every chunk the recipient downloads (e2e drops.spec.ts test 4). */
async function tamperChunks(route: Route): Promise<void> {
  const response = await route.fetch();
  const body = Buffer.from(await response.body());
  body[Math.floor(body.length / 2)] ^= 0x01;
  await route.fulfill({ response, body });
}

/** Decrypt & download on a receive page, then wait until all 3 files and the drop show "Integrity verified". */
async function receive(page: Page, link: string): Promise<void> {
  await openLink(page, link);
  await downloadFromReady(page, DOWNLOAD_DIR);
  await expect(page.getByText('Integrity verified')).toHaveCount(4);
  await imagesLoaded(page);
  await page.evaluate(() => window.scrollTo(0, 0));
}

test('send, upload, link, receive and tamper, on desktop and phone', async ({ open, leaks }) => {
  const files = demoFiles();
  for (const file of files) leaks.forbidText('file name', file.name);
  leaks.forbidText('note', DEMO_NOTE);
  leaks.forbidBytes('document bytes', files[1]!.buffer);
  const options = { expiryHours: 1, maxDownloads: 5, note: DEMO_NOTE };

  const phone = await (await open({ device: PHONE })).newPage();
  await phone.goto('/');
  await composeDrop(phone, files, options);
  await shoot(phone, 'send-mobile');

  const senderContext = await open();
  const sender = await senderContext.newPage();
  await sender.goto('/');
  await composeDrop(sender, files, options);
  await shoot(sender, 'send');

  // Let the first five chunk PUTs through (the picture and 4 of the document's 6 chunks), park the rest.
  let passed = 0;
  let parked = 0;
  let release = () => {};
  const released = new Promise<void>((resolve) => (release = resolve));
  await senderContext.route('**/api/drops/*/files/*/chunks/*', async (route) => {
    if (route.request().method() === 'PUT' && passed >= 5) {
      parked += 1;
      await released;
    } else if (route.request().method() === 'PUT') {
      passed += 1;
    }
    await route.continue();
  });
  await sender.getByRole('button', { name: 'Encrypt & upload' }).click();
  await expect.poll(() => parked).toBeGreaterThan(0);
  await expect(sender.getByText('Uploaded 67%')).toBeVisible();
  hero.sending = (await shoot(sender, 'send-progress')).dark;
  release();

  await expect(sender.getByText('Your encrypted link is ready')).toBeVisible({ timeout: 90_000 });
  const link = await sender.getByLabel('Share link').inputValue();
  leaks.forbidKey('link key', new URL(link).hash.slice(1));
  await shoot(sender, 'send-success');

  // Recipients in fresh browsers: 5 downloads, 4 of them used here.
  const recipient = await (await open()).newPage();
  await receive(recipient, link);
  hero.received = (await shoot(recipient, 'receive')).light;

  const phoneRecipient = await (await open({ device: PHONE })).newPage();
  await receive(phoneRecipient, link);
  await shoot(phoneRecipient, 'receive-mobile');

  for (const [device, name, themes] of [
    [DESKTOP, 'receive-tamper-blocked', undefined],
    [PHONE, 'receive-tamper-blocked-mobile', LIGHT],
  ] as const) {
    const context = await open({ device });
    await context.route('**/api/drops/*/files/*/chunks/*', tamperChunks);
    const page = await context.newPage();
    let saved = false;
    page.on('download', () => (saved = true));
    await openLink(page, link);
    await page.getByRole('button', { name: 'Decrypt & download' }).click();
    await expect(page.getByText(TAMPERED)).toBeVisible();
    await expect(page.getByText('Integrity verified')).toHaveCount(0);
    expect(saved, 'a tampered file is never saved').toBe(false);
    await page.evaluate(() => window.scrollTo(0, 0));
    await shoot(page, name, themes);
  }
});

test('burn after reading and the password prompt', async ({ open, leaks, request, baseURL }) => {
  const note = { name: 'door-code.txt', type: 'text/plain', content: Buffer.from('4471#\n') };
  leaks.forbidText('file name', note.name);
  const burn = await sendFromNode(request, baseURL!, [note], {
    maxDownloads: 1,
    note: 'Read once, then it is gone.',
  });
  leaks.forbidKey('link key', burn.key);

  const first = await (await open()).newPage();
  await openLink(first, burn.link);
  await downloadFromReady(first, DOWNLOAD_DIR);
  const second = await (await open()).newPage();
  await openLink(second, burn.link);
  await expect(second.getByText('All downloads have been used')).toBeVisible();
  await shoot(second, 'receive-burned', LIGHT);

  leaks.forbidText('drop password', SEED_DROP_PASSWORD);
  const locked = await (await open()).newPage();
  await locked.goto(seedPasswordLink(baseURL!));
  await expect(locked.getByText('This drop is password protected')).toBeVisible();
  await locked.getByLabel('Password', { exact: true }).fill(SEED_DROP_PASSWORD);
  await shoot(locked, 'receive-password', LIGHT);
});

test('register: the recovery key step', async ({ open, leaks }) => {
  const password = randomPassword();
  leaks.forbidText('password', password);
  const page = await (await open()).newPage();
  await page.goto('/register');
  await page.getByLabel('Email').fill('alex@cipherdrop.local');
  await page.getByLabel('Password', { exact: true }).fill(password);
  await page.getByLabel('Confirm password').fill(password);
  await page.getByRole('button', { name: 'Create account' }).click();
  const card = page.getByRole('group', { name: 'Your recovery key' });
  await expect(card).toBeVisible();
  const recoveryKey = (await card.getByTestId('recovery-key-row').allInnerTexts()).join('');
  leaks.forbidText('recovery key', recoveryKey);
  await shoot(page, 'register-recovery-key', LIGHT);
});

test('demo account: dashboard and settings, desktop and phone', async ({ open, leaks }) => {
  const { demo } = seedPasswords();
  leaks.forbidText('demo password', demo);

  const page = await (await open()).newPage();
  await logIn(page, DEMO_EMAIL, demo);
  await waitForDashboard(page);
  await expect(page.getByText('welcome.txt')).toBeVisible();
  await shoot(page, 'dashboard');
  await accountMenu(page, 'Settings');
  await expect(page.getByRole('button', { name: 'Set up two-step verification' })).toBeVisible();
  await shoot(page, 'settings');

  const phone = await (await open({ device: PHONE })).newPage();
  await logIn(phone, DEMO_EMAIL, demo);
  await waitForDashboard(phone);
  await expect(phone.getByText('welcome.txt')).toBeVisible();
  await shoot(phone, 'dashboard-mobile');
});

test('admin: two-step setup, the console, and the sign-in code prompt', async ({ open, leaks }) => {
  const { admin } = seedPasswords();
  leaks.forbidText('admin password', admin);

  const page = await (await open()).newPage();
  await logIn(page, ADMIN_EMAIL, admin);
  await waitForDashboard(page);
  await accountMenu(page, 'Settings');
  await page.getByRole('button', { name: 'Set up two-step verification' }).click();
  const secret = await page.getByLabel('Secret key').inputValue();
  leaks.forbidText('totp secret', secret);
  await expect(page.getByRole('img', { name: 'QR code for your authenticator app' })).toBeVisible();
  await page.getByLabel('Your password').fill(admin);
  await shoot(page, 'totp-setup', LIGHT);
  await page.getByLabel('6-digit code').fill(totpCode(secret));
  await page.getByRole('button', { name: /Turn on|Verify|Enable/ }).click();
  await expect(page.getByText('Save these backup codes now')).toBeVisible();
  await page.getByLabel('I saved my backup codes').check();
  await page.getByRole('button', { name: 'Done' }).click();

  await accountMenu(page, 'Admin console');
  await expect(page.getByRole('list', { name: 'Statistics' })).toBeVisible();
  await expect(page.getByText('Seeded example report').first()).toBeAttached();
  await shoot(page, 'admin');

  // A new sign-in now asks for the code. The prompt is the picture; the sign-in is not finished.
  const signIn = await (await open()).newPage();
  await logIn(signIn, ADMIN_EMAIL, admin);
  await expect(signIn.getByLabel('6-digit code')).toBeVisible();
  await shoot(signIn, 'login-2fa', LIGHT);
});

test('how it works', async ({ open }) => {
  const page = await (await open()).newPage();
  await page.goto('/how-it-works');
  await expect(page.getByRole('heading', { name: 'How it works', level: 1 })).toBeVisible();
  await shoot(page, 'how-it-works');
});

test('hero: sender and recipient side by side', async ({ open }) => {
  expect(hero.sending && hero.received, 'the send and receive shots ran first').toBeTruthy();
  const page = await (
    await open({ device: { viewport: { width: 1280, height: 640 }, deviceScaleFactor: 2 } })
  ).newPage();
  const src = (png: Buffer) => `data:image/png;base64,${png.toString('base64')}`;
  const frame =
    'position:absolute;width:700px;border-radius:12px;box-shadow:0 18px 48px rgba(0,0,0,.45);' +
    'outline:1px solid rgba(255,255,255,.18)';
  await page.setContent(
    `<body style="margin:0;width:1280px;height:640px;overflow:hidden;` +
      `background:linear-gradient(135deg,#0b1014 0%,#134e4a 100%)">` +
      `<img alt="" style="${frame};left:40px;top:32px" src="${src(hero.sending!)}">` +
      `<img alt="" style="${frame};right:40px;bottom:32px" src="${src(hero.received!)}">` +
      `</body>`,
  );
  await imagesLoaded(page);
  await page.screenshot({ path: path.join(SHOTS_DIR, 'hero.png') });
});
