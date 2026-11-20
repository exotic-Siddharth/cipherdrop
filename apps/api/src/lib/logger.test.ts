/** The logger's err serializer: Prisma errors keep only safe fields, whatever their message carries. */
import { Prisma } from '@prisma/client';
import { pino } from 'pino';
import { describe, expect, it } from 'vitest';
import { createLogger, serializeError } from './logger';

const SECRET = 'NHQLjAoPm44F9kDrwhV7u3CPHHucOoBzVFOBmVwdGmw';
const CLIENT = { clientVersion: '6.19.3' };

/** A message rendered the way Prisma renders a rejected call: with its arguments. */
const rendered = `\nInvalid \`prisma.report.create()\` invocation:\n\n{\n  data: {\n    providedKey: "${SECRET}"\n  }\n}\n\nInvalid value for argument \`reason\`.`;

function captured(): { lines: string[]; log: ReturnType<typeof createLogger> } {
  const lines: string[] = [];
  return {
    lines,
    log: createLogger({ level: 'trace', destination: { write: (s) => lines.push(s) } }),
  };
}

describe('serializeError', () => {
  it('reduces a Prisma validation error to its class and stack frames', () => {
    const out = serializeError(new Prisma.PrismaClientValidationError(rendered, CLIENT));
    expect(JSON.stringify(out)).not.toContain(SECRET);
    expect(out).toMatchObject({ type: 'PrismaClientValidationError' });
    expect((out as { stack: string }).stack).toMatch(/^\s+at /);
    expect(out).not.toHaveProperty('message');
  });

  it('keeps the code and the schema names of a known request error, not the database message', () => {
    const err = new Prisma.PrismaClientKnownRequestError(`Raw query failed: "${SECRET}"`, {
      ...CLIENT,
      code: 'P2010',
      meta: { modelName: 'Report', target: ['providedKey'], message: `invalid input "${SECRET}"` },
    });
    const out = serializeError(err);
    expect(JSON.stringify(out)).not.toContain(SECRET);
    expect(out).toMatchObject({
      type: 'PrismaClientKnownRequestError',
      prismaCode: 'P2010',
      meta: { modelName: 'Report', target: ['providedKey'] },
    });
    const init = new Prisma.PrismaClientInitializationError('cannot reach db', '6.19.3', 'P1001');
    expect(serializeError(init)).toMatchObject({ prismaCode: 'P1001' });
  });

  it('reduces a Prisma error that is the cause of another one (pino would fold its message in)', () => {
    const cause = new Prisma.PrismaClientValidationError(rendered, CLIENT);
    const err = new Error('report failed', { cause });
    expect(JSON.stringify(pino.stdSerializers.err(err))).toContain(SECRET);
    const out = serializeError(err);
    expect(JSON.stringify(out)).not.toContain(SECRET);
    expect(out).toMatchObject({
      type: 'Error',
      message: 'report failed',
      cause: { type: 'PrismaClientValidationError' },
    });
  });

  it('leaves every other error to pino', () => {
    const err = Object.assign(new Error('EIO: i/o error, write'), { syscall: 'write' });
    expect(serializeError(err)).toEqual(pino.stdSerializers.err(err));
    expect(serializeError({ message: 'not an error' })).toEqual(
      pino.stdSerializers.err({ message: 'not an error' } as Error),
    );
  });

  it('is the err serializer of createLogger(), and the Prisma code survives redaction', () => {
    const { lines, log } = captured();
    const err = new Prisma.PrismaClientKnownRequestError(`"${SECRET}"`, {
      ...CLIENT,
      code: 'P2002',
    });
    log.error({ err }, 'request failed');
    log.error(new Prisma.PrismaClientValidationError(rendered, CLIENT));
    const output = lines.join('');
    expect(output).not.toContain(SECRET);
    expect(output).toContain('"prismaCode":"P2002"');
    expect(output).toContain('"type":"PrismaClientValidationError"');
  });
});
