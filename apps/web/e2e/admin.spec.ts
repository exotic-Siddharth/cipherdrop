/**
 * Report -> moderation flow against the real API (R13): a recipient reports a drop (with and without the
 * key), the admin reviews it through the non-consuming grant, disables it, dismisses another report and edits a
 * user. Also checks that a plain user is refused on /admin.
 */
import { expect, test } from './support/fixtures';
import {
  disconnectDb,
  downloadCount,
  dropIdOf,
  promoteToAdmin,
  userQuotaBytes,
  userRole,
} from './support/db';
import {
  accountMenu,
  openLink,
  randomPassword,
  registerAccount,
  sendDrop,
  textFile,
  uniqueEmail,
} from './support/flows';

test.afterAll(async () => {
  await disconnectDb();
});

test('report with key -> admin review (no download consumed) -> disable; dismiss; edit a user', async ({
  page,
  newContext,
  leaks,
}) => {
  const adminEmail = uniqueEmail('admin');
  const userEmail = uniqueEmail('plainuser');
  const password = randomPassword();
  leaks.forbidText('password', password);
  const reviewed = textFile('suspicious-invoice.txt', 'ADMIN-MARKER-1');
  const dismissed = textFile('harmless-cat.txt', 'ADMIN-MARKER-2');
  leaks.forbidText('name 1', reviewed.name);
  leaks.forbidText('name 2', dismissed.name);

  // Two anonymous drops. The reviewed one is reported with its key; the other without.
  const sender = await (await newContext()).newPage();
  await sender.goto('/');
  const link1 = await sendDrop(sender, [reviewed], { maxDownloads: 5 });
  await sender.getByRole('button', { name: 'Send another' }).click();
  const link2 = await sendDrop(sender, [dismissed], { maxDownloads: 5 });
  const id1 = dropIdOf(link1);
  const id2 = dropIdOf(link2);

  const reporter = await (await newContext()).newPage();
  const report = async (link: string, reason: string, includeKey: boolean) => {
    await openLink(reporter, link);
    await reporter.reload();
    await expect(reporter.getByRole('button', { name: 'Decrypt & download' })).toBeVisible({
      timeout: 30_000,
    });
    await reporter.getByRole('button', { name: 'Report abuse' }).click();
    await reporter.getByLabel('Reason').selectOption(reason);
    await reporter.getByLabel('Details').fill('reported by e2e');
    if (includeKey)
      await reporter.getByLabel('Include the decryption key so moderators can review').check();
    await reporter.getByRole('button', { name: 'Send report' }).click();
    await expect(reporter.getByText(/report (was )?(sent|received)|thank/i).first()).toBeVisible({
      timeout: 20_000,
    });
  };
  // The key is in the link for the reporter, and it travels ONLY when the box is ticked.
  await report(link1, 'MALWARE', true);
  const reportCalls = leaks.requests.filter(
    (r) => r.method === 'POST' && r.url.includes('/report'),
  );
  expect(reportCalls).toHaveLength(1);
  expect(reportCalls[0]!.body?.toString('utf8')).toContain(new URL(link1).hash.slice(1));
  await report(link2, 'OTHER', false);
  const reportCalls2 = leaks.requests.filter(
    (r) => r.method === 'POST' && r.url.includes('/report'),
  );
  expect(reportCalls2).toHaveLength(2);
  expect(reportCalls2[1]!.body?.toString('utf8')).not.toContain(new URL(link2).hash.slice(1));
  // From here on the key of drop 1 is allowed to appear in the admin requests (the reporter chose to share it).
  const key1 = new URL(link1).hash.slice(1);

  // A plain user and an admin.
  await registerAccount(page, adminEmail, password);
  await promoteToAdmin(adminEmail);
  const userPage = await (await newContext()).newPage();
  await registerAccount(userPage, userEmail, password);

  // A non-admin is refused on /admin.
  await userPage.goto('/admin');
  await expect(userPage.getByText('Admins only')).toBeVisible({ timeout: 20_000 });

  // The admin's role comes from a fresh token: reload refreshes the session.
  await page.goto('/admin');
  await expect(
    page
      .getByRole('heading', { name: 'Admin console' })
      .or(page.getByRole('heading', { name: /Admin/ }))
      .first(),
  ).toBeVisible({
    timeout: 30_000,
  });
  await expect(page.getByRole('list', { name: 'Statistics' })).toBeVisible();
  await expect(page.getByText('Open reports').first()).toBeVisible();
  await expect(page.getByText('Needs review')).toBeVisible();
  // The 14-day uploads chart renders (not an empty or error state).
  await expect(page.getByRole('group', { name: /^Uploads per day/ })).toBeVisible({
    timeout: 20_000,
  });

  const reportsCard = page.getByRole('region', { name: 'Abuse reports' });
  await expect(reportsCard.getByText(id1)).toBeVisible({ timeout: 20_000 });
  await expect(reportsCard.getByText(id2)).toBeVisible();
  const row = (id: string) => reportsCard.getByRole('listitem').filter({ hasText: id });
  await expect(row(id1).getByText('Has key')).toBeVisible();
  await expect(row(id2).getByText('Has key')).toHaveCount(0);

  // Review: the grant does not consume a download, and the manifest decrypts with the reporter's key.
  const before = await downloadCount(id1);
  await page.getByRole('link', { name: `Review drop ${id1}` }).click();
  await expect(page).toHaveURL(new RegExp(`/d/${id1}\\?review=1#`));
  await expect(page.getByText('Review mode')).toBeVisible({ timeout: 30_000 });
  await expect(page.getByText(reviewed.name)).toBeVisible({ timeout: 20_000 });
  expect(await downloadCount(id1)).toBe(before);
  expect(leaks.count('POST', '/admin/drops/')).toBe(1);
  void key1;

  // Disable it from the queue.
  await page.goto('/admin');
  await expect(row(id1)).toBeVisible({ timeout: 20_000 });
  await page.getByRole('button', { name: `Disable drop ${id1}` }).click();
  await page.getByRole('button', { name: 'Disable drop', exact: true }).click();
  await expect(page.getByText('Drop disabled and report resolved')).toBeVisible({
    timeout: 20_000,
  });
  const visitor = await (await newContext()).newPage();
  await openLink(visitor, link1);
  await expect(visitor.getByText('This drop was disabled')).toBeVisible({ timeout: 20_000 });

  // Dismiss the other report: the drop stays online.
  await row(id2)
    .getByRole('button', { name: /^Dismiss report/ })
    .click();
  await page.getByRole('button', { name: 'Dismiss report', exact: true }).click();
  await expect(page.getByText('Report dismissed')).toBeVisible({ timeout: 20_000 });
  const stillOnline = await (await newContext()).newPage();
  await openLink(stillOnline, link2);
  await expect(stillOnline.getByText(dismissed.name)).toBeVisible({ timeout: 20_000 });
  // Both reports left the Open queue.
  await expect(row(id1)).toHaveCount(0, { timeout: 20_000 });
  await expect(row(id2)).toHaveCount(0);

  // Users: search, edit the quota and promote.
  await page.getByLabel('Search users').fill(userEmail.slice(0, 18));
  await expect(page.getByRole('button', { name: `Edit ${userEmail}` })).toBeVisible({
    timeout: 20_000,
  });
  await page.getByRole('button', { name: `Edit ${userEmail}` }).click();
  await page.getByLabel('Storage quota').fill('1');
  await page.getByLabel('Role').selectOption('ADMIN');
  await page.getByRole('button', { name: 'Save changes' }).click();
  await expect(page.getByText('User updated')).toBeVisible({ timeout: 20_000 });
  expect(await userRole(userEmail)).toBe('ADMIN');
  expect(await userQuotaBytes(userEmail)).toBe(1024n ** 3n);
  await expect(page.getByText(/of 1 GB used/).first()).toBeVisible();

  // The admin menu entry exists for admins.
  await accountMenu(page, 'Dashboard');
});
