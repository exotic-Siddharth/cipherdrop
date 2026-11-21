/**
 * Responsive layout (docs/DESIGN.md section 11.1, "Responsive from 360 px"): no page scrolls sideways, at the
 * project's own viewport (a phone in the mobile projects of npm run e2e:cross) and at 360 px wide. The receive page
 * gets a long unbroken file name, the usual way a layout breaks out of a narrow screen.
 */
import { expect, test } from './support/fixtures';
import { disconnectDb } from './support/db';
import {
  expectNoHorizontalScroll,
  randomPassword,
  registerAccount,
  uniqueEmail,
} from './support/flows';
import { sendFromNode } from './support/senders';

const NARROWEST = { width: 360, height: 740 };

test.afterAll(disconnectDb);

test('send, receive, how-it-works, sign-in and dashboard pages never scroll sideways @cross', async ({
  page,
  request,
  baseURL,
  leaks,
}) => {
  const name = `quarterly-board-minutes-final-v12-approved-by-legal-${'x'.repeat(40)}.pdf`;
  const drop = await sendFromNode(
    request,
    baseURL!,
    [{ name, type: 'application/pdf', content: Buffer.from('LAYOUT-MARKER') }],
    {
      maxDownloads: 5,
      note: 'A note that is long enough to wrap onto several lines on a phone.',
    },
  );
  leaks.forbidKey('link key', drop.key);
  leaks.forbidText('file name', name);

  const atBothWidths = async (check: () => Promise<void>) => {
    const own = page.viewportSize();
    await check();
    await expectNoHorizontalScroll(page);
    await page.setViewportSize(NARROWEST);
    await check();
    await expectNoHorizontalScroll(page);
    if (own) await page.setViewportSize(own);
  };

  await page.goto('/');
  await atBothWidths(() =>
    expect(page.getByRole('button', { name: 'Encrypt & upload' })).toBeVisible(),
  );

  await page.goto(drop.link);
  await atBothWidths(() =>
    expect(page.getByRole('button', { name: 'Decrypt & download' })).toBeVisible({
      timeout: 30_000,
    }),
  );

  await page.goto('/how-it-works');
  await atBothWidths(() => expect(page.getByRole('heading', { level: 1 })).toBeVisible());

  await page.goto('/login');
  await atBothWidths(() =>
    expect(page.getByRole('button', { name: 'Log in', exact: true })).toBeVisible(),
  );

  await page.goto('/register');
  await atBothWidths(() =>
    expect(page.getByRole('button', { name: 'Create account' })).toBeVisible(),
  );

  const password = randomPassword();
  leaks.forbidText('account password', password);
  const { recoveryKey } = await registerAccount(page, uniqueEmail('layout'), password);
  leaks.forbidText('recovery key', recoveryKey);
  leaks.forbidText('recovery key (compact)', recoveryKey.replaceAll('-', ''));
  await atBothWidths(() =>
    expect(
      page.getByText(/no (active )?drops|nothing here|send your first/i).first(),
    ).toBeVisible(),
  );
});
