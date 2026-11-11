/**
 * Smoke check against a RUNNING API (`npm run smoke`, after `npm run db:seed`): the demo user's path through
 * the zero-knowledge flow, exactly as the SPA performs it:
 *
 *   prelogin -> derive authKey/encKey from the password -> login -> GET /auth/vault -> unwrap the account key
 *   -> GET /me/drops?status=all -> unwrap each ownerWrappedKey -> decrypt each manifest -> print the file names.
 *
 * Exit code 1 when a step fails or fewer than 3 seeded drops decrypt. Env: SMOKE_API_URL (default
 * http://localhost:<API_PORT>), SEED_DEMO_PASSWORD (from apps/api/.env). Every response is validated with the
 * shared zod contracts, so a contract drift fails here too.
 */
import {
  AAD,
  b64urlEncode,
  decryptManifest,
  deriveAccountKeys,
  importAesKey,
  unwrapKey,
} from '@cipherdrop/crypto';
import {
  LoginResponseSchema,
  OwnerDropPageSchema,
  PreloginResponseSchema,
  VaultSchema,
} from '@cipherdrop/shared';
import { env } from '../src/config/env';

const API = (process.env.SMOKE_API_URL ?? `http://localhost:${env.API_PORT}`).replace(/\/$/, '');
const EMAIL = 'demo@cipherdrop.local';

async function call(path: string, init: RequestInit & { token?: string } = {}): Promise<unknown> {
  const { token, ...rest } = init;
  const res = await fetch(`${API}/api${path}`, {
    ...rest,
    headers: {
      ...(rest.body ? { 'content-type': 'application/json' } : {}),
      ...(token ? { authorization: `Bearer ${token}` } : {}),
    },
  });
  const body: unknown = res.status === 204 ? null : await res.json().catch(() => null);
  if (!res.ok) {
    throw new Error(`${rest.method ?? 'GET'} ${path} -> ${res.status} ${JSON.stringify(body)}`);
  }
  return body;
}

async function main(): Promise<void> {
  const password = env.SEED_DEMO_PASSWORD;
  if (!password) throw new Error('SEED_DEMO_PASSWORD is not set (apps/api/.env)');

  let t = performance.now();
  const lap = (label: string) => {
    const now = performance.now();
    console.log(`  ${label.padEnd(34)} ${(now - t).toFixed(0).padStart(5)} ms`);
    t = now;
  };

  console.log(`Smoke check against ${API} as ${EMAIL}`);
  const { kdf } = PreloginResponseSchema.parse(
    await call('/auth/prelogin', { method: 'POST', body: JSON.stringify({ email: EMAIL }) }),
  );
  lap('prelogin');
  const { authKey, encKey } = await deriveAccountKeys(password, kdf);
  lap(`derive (Argon2id ${kdf.memoryKiB / 1024} MiB x${kdf.iterations})`);
  const login = LoginResponseSchema.parse(
    await call('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email: EMAIL, authKey: b64urlEncode(authKey) }),
    }),
  );
  if (login.mfaRequired) throw new Error('the demo account unexpectedly requires MFA');
  lap('login');

  const vault = VaultSchema.parse(await call('/auth/vault', { token: login.accessToken }));
  const accountKey = await unwrapKey(encKey, vault.wrappedAccountKey, AAD.WRAP_ACCOUNT);
  const vaultKey = await importAesKey(accountKey);
  accountKey.fill(0);
  lap('vault unwrap');

  const page = OwnerDropPageSchema.parse(
    await call('/me/drops?status=all&pageSize=50', { token: login.accessToken }),
  );
  lap('GET /me/drops');

  console.log(`\n${page.total} drop(s) for ${EMAIL}:`);
  let decrypted = 0;
  for (const drop of page.items) {
    let names = '(no owner wrap: cannot decrypt)';
    if (drop.ownerWrappedKey) {
      const dk = await unwrapKey(vaultKey, drop.ownerWrappedKey, AAD.WRAP_OWNER);
      const manifest = await decryptManifest(dk, drop.encryptedManifest);
      names = manifest.files.map((f) => `${f.name} (${f.size} B)`).join(', ');
      decrypted++;
    }
    const pw = drop.passwordProtected ? ', password' : '';
    console.log(
      `  [${drop.status}] ${drop.id}  ${names}  | ${drop.downloadCount}/${drop.maxDownloads} downloads${pw}`,
    );
  }
  lap('decrypt manifests');

  if (decrypted < 3) {
    throw new Error(`expected at least 3 decryptable seeded drops, got ${decrypted}`);
  }
  console.log(
    `\nOK: ${decrypted} drop manifest(s) decrypted client-side; the server never saw a name.`,
  );
}

main().catch((err: unknown) => {
  console.error('SMOKE FAILED:', err instanceof Error ? err.message : err);
  process.exitCode = 1;
});
