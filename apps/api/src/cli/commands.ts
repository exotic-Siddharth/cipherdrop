/**
 * Operator commands (ops-9): day-one and incident-day moderation without hand-written SQL. Run with
 * `npm run cli -w @cipherdrop/api -- <command>` in development, or in the production stack with
 * `docker compose --env-file .env.production -f docker-compose.prod.yml exec api node apps/api/dist/cli.js <command>`.
 *
 * Every command goes through the same service code as the admin console and is audited with metadata.operator
 * (there is no acting account), so the admin Audit tab shows it as "Operator".
 */
import type { AppContext } from '../context';
import { isAppError } from '../lib/errors';
import { disableDrop, listAudit, patchUser, revokeSessions } from '../modules/admin/service';

export const CLI_HELP = `CipherDrop operator commands

Usage (production):  docker compose --env-file .env.production -f docker-compose.prod.yml exec api node apps/api/dist/cli.js <command>
Usage (development): npm run cli -w @cipherdrop/api -- <command>

Commands:
  admin:promote <email>                 Make an EXISTING account an admin (it must have two-step verification)
  admin:demote <email>                  Remove the admin role
  user:suspend <email> --reason <text>  Suspend an account and sign out all of its sessions
  user:unsuspend <email>                Lift a suspension
  drop:disable <dropId> --reason <text> Take a drop down (blobs deleted, open reports resolved)
  sessions:revoke <email>               Sign out every session of one account
  sessions:revoke --all                 Sign out every session of every account (incident response)
  audit:tail [--limit <n>]              Print the latest admin and operator actions
  help                                  Show this text

Every command is recorded in the audit log as an operator action.`;

type Out = (line: string) => void;

class UsageError extends Error {}

/** `--name value` options and positional arguments. */
function parseArgs(args: string[]): { positional: string[]; options: Map<string, string | true> } {
  const positional: string[] = [];
  const options = new Map<string, string | true>();
  for (let i = 0; i < args.length; i++) {
    const a = args[i]!;
    if (a.startsWith('--')) {
      const next = args[i + 1];
      if (next !== undefined && !next.startsWith('--')) {
        options.set(a.slice(2), next);
        i++;
      } else {
        options.set(a.slice(2), true);
      }
    } else {
      positional.push(a);
    }
  }
  return { positional, options };
}

function one(positional: string[], what: string): string {
  if (positional.length !== 1) throw new UsageError(`Expected exactly one ${what}`);
  return positional[0]!;
}

function reasonOf(options: Map<string, string | true>): string {
  const reason = options.get('reason');
  if (typeof reason !== 'string' || !reason.trim())
    throw new UsageError('--reason <text> is required');
  if (reason.length > 500) throw new UsageError('--reason is at most 500 characters');
  return reason.trim();
}

async function userIdByEmail(ctx: AppContext, email: string): Promise<string> {
  const user = await ctx.prisma.user.findUnique({
    where: { email: email.trim().toLowerCase() },
    select: { id: true },
  });
  if (!user) throw new UsageError(`No account with the email ${email}`);
  return user.id;
}

/** Run one command; returns the process exit code (0 ok, 1 refused, 2 usage). Never prints secrets. */
export async function runCli(ctx: AppContext, argv: string[], out: Out): Promise<number> {
  const [command, ...rest] = argv;
  const { positional, options } = parseArgs(rest);
  try {
    switch (command) {
      case 'admin:promote':
      case 'admin:demote': {
        const email = one(positional, 'email');
        const role = command === 'admin:promote' ? 'ADMIN' : 'USER';
        const user = await patchUser(ctx, await userIdByEmail(ctx, email), { role }, 'operator');
        out(`${user.email} is now ${user.role === 'ADMIN' ? 'an admin' : 'a regular user'}`);
        return 0;
      }
      case 'user:suspend': {
        const email = one(positional, 'email');
        const reason = reasonOf(options);
        await patchUser(
          ctx,
          await userIdByEmail(ctx, email),
          { suspended: true, suspendedReason: reason },
          'operator',
        );
        out(`${email} is suspended and signed out everywhere`);
        return 0;
      }
      case 'user:unsuspend': {
        const email = one(positional, 'email');
        await patchUser(ctx, await userIdByEmail(ctx, email), { suspended: false }, 'operator');
        out(`${email} can sign in again`);
        return 0;
      }
      case 'drop:disable': {
        const dropId = one(positional, 'drop id');
        await disableDrop(ctx, dropId, 'operator', {
          reason: reasonOf(options),
          requireChange: true,
        });
        out(`Drop ${dropId} is disabled and its files are deleted`);
        return 0;
      }
      case 'sessions:revoke': {
        const all = options.get('all') === true;
        if (all === positional.length > 0) throw new UsageError('Give one email, or --all');
        const userId = all ? null : await userIdByEmail(ctx, one(positional, 'email'));
        const count = await revokeSessions(ctx, userId, 'operator');
        out(`Signed out ${count} session${count === 1 ? '' : 's'}`);
        return 0;
      }
      case 'audit:tail': {
        const limitOpt = options.get('limit');
        const limit = typeof limitOpt === 'string' ? Number(limitOpt) : 20;
        if (!Number.isInteger(limit) || limit < 1 || limit > 100) {
          throw new UsageError('--limit is a whole number from 1 to 100');
        }
        const page = await listAudit(ctx, { page: 1, pageSize: limit });
        for (const e of [...page.items].reverse()) {
          const who = e.byOperator ? 'operator' : (e.actor?.email ?? '-');
          const subject = e.subject ? (e.subject.email ?? e.subject.id) : '-';
          const reason =
            typeof e.metadata?.reason === 'string' ? ` reason="${e.metadata.reason}"` : '';
          out(
            `${e.createdAt} ${e.action} by=${who} account=${subject} drop=${e.dropId ?? '-'}${reason}`,
          );
        }
        out(`(${page.items.length} of ${page.total} events)`);
        return 0;
      }
      case undefined:
      case 'help':
      case '--help':
      case '-h':
        out(CLI_HELP);
        return command === undefined ? 2 : 0;
      default:
        throw new UsageError(`Unknown command: ${command}`);
    }
  } catch (err) {
    if (err instanceof UsageError) {
      out(`Error: ${err.message}. Run "help" for the commands.`);
      return 2;
    }
    if (isAppError(err)) {
      out(`Refused: ${err.message}`);
      return 1;
    }
    throw err;
  }
}
