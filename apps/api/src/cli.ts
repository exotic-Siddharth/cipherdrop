/**
 * Operator CLI entry (dist/cli.js, ops-9). See cli/commands.ts for the commands; `help` lists them.
 */
import { createContext } from './context';
import { runCli } from './cli/commands';

const ctx = createContext();
let code = 1;
try {
  code = await runCli(ctx, process.argv.slice(2), (line) => process.stdout.write(`${line}\n`));
} catch (err) {
  const e = err as { name?: string; code?: string };
  // Names the error class and code only: a Prisma message can carry the statement.
  process.stderr.write(`Failed: ${e.name ?? 'Error'}${e.code ? ` (${e.code})` : ''}\n`);
} finally {
  await ctx.prisma.$disconnect();
  ctx.redis.disconnect();
}
process.exit(code);
