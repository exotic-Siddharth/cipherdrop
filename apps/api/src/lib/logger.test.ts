/**
 * The logger's err serializer: Prisma errors keep only safe fields, whatever their message carries, on every
 * path pino has for an error (the serializer, the message pino copies into `msg`, pino-http's child logger).
 */
import { Prisma } from '@prisma/client';
import express from 'express';
import { pino } from 'pino';
import request from 'supertest';
import { describe, expect, it, vi } from 'vitest';
import { createHttpLogger, createLogger, serializeError } from './logger';

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
  });

  it('keeps the message of an initialization error: it says why the API could not start', () => {
    const reason = "Can't reach database server at `db:5432`";
    const init = new Prisma.PrismaClientInitializationError(reason, '6.19.3', 'P1001');
    expect(serializeError(init)).toMatchObject({
      type: 'PrismaClientInitializationError',
      message: reason,
      prismaCode: 'P1001',
    });
    // Without an error code (a missing engine or environment variable) the message is all there is.
    const noCode = new Prisma.PrismaClientInitializationError(
      'Missing URL environment variable',
      '6.19.3',
    );
    expect(serializeError(noCode)).toMatchObject({ message: 'Missing URL environment variable' });
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

  it('reduces Prisma errors inside an AggregateError or a property, and survives a cycle', () => {
    const prismaErr = new Prisma.PrismaClientValidationError(rendered, CLIENT);
    const batch = new AggregateError([prismaErr, new Error('disk full')], 'batch failed');
    expect(JSON.stringify(pino.stdSerializers.err(batch))).toContain(SECRET);
    const out = serializeError(batch);
    expect(JSON.stringify(out)).not.toContain(SECRET);
    expect(out).toMatchObject({
      type: 'AggregateError',
      message: 'batch failed',
      aggregateErrors: [{ type: 'PrismaClientValidationError' }, { message: 'disk full' }],
    });

    const holder = Object.assign(new Error('report failed'), { original: prismaErr, step: 2 });
    expect(JSON.stringify(pino.stdSerializers.err(holder))).toContain(SECRET);
    const held = serializeError(holder);
    expect(JSON.stringify(held)).not.toContain(SECRET);
    expect(held).toMatchObject({ step: 2, original: { type: 'PrismaClientValidationError' } });

    const loop = new AggregateError([prismaErr], 'loop');
    Object.assign(loop, { again: loop });
    expect(JSON.stringify(serializeError(loop))).not.toContain(SECRET);
  });

  it('reduces a Prisma error that pino already serialized', () => {
    const std = pino.stdSerializers.err(new Prisma.PrismaClientValidationError(rendered, CLIENT));
    expect(JSON.stringify(std)).toContain(SECRET);
    // pino-http hands over pino's own serialization (the error is still behind it, as `raw`) ...
    expect(JSON.stringify(serializeError(std))).not.toContain(SECRET);
    expect(serializeError(std)).toMatchObject({ type: 'PrismaClientValidationError' });
    // ... and a copy without `raw` still says what it is in `type`.
    const copy = JSON.parse(JSON.stringify(std)) as unknown;
    expect(JSON.stringify(serializeError(copy))).not.toContain(SECRET);
    // Anything else pino serialized stays as pino made it.
    const other = pino.stdSerializers.err(new Error('EIO'));
    expect(serializeError(other)).toBe(other);
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

  it('keeps the message out of `msg` for log.error(err) and log.error({ err }) without a message', () => {
    const { lines, log } = captured();
    const err = new Prisma.PrismaClientValidationError(rendered, CLIENT);
    log.error(err);
    log.error({ err });
    log.error({ err: pino.stdSerializers.err(err) });
    log.warn({ err, reqId: 'r1' });
    expect(lines.join('')).not.toContain(SECRET);
    const msgs = lines.map((l) => (JSON.parse(l) as { msg?: string }).msg);
    expect(msgs).toEqual(Array(4).fill('PrismaClientValidationError'));
    // Other errors keep pino's behaviour: their message becomes `msg`.
    log.error({ err: new Error('disk full') });
    expect(JSON.parse(lines.at(-1)!)).toMatchObject({ msg: 'disk full' });
  });

  it('is also the err serializer of the pino-http logger (req.log, httpLogger.logger, res.err)', async () => {
    const { lines, log } = captured();
    const err = new Prisma.PrismaClientValidationError(rendered, CLIENT);
    const httpLogger = createHttpLogger(log);
    httpLogger.logger.error({ err }, 'direct');
    const app = express();
    app.use(httpLogger);
    app.get('/x', (req, res) => {
      req.log.error({ err }, 'handler failed');
      req.log.error({ err });
      // pino-http logs res.err with the access log line when the response finishes.
      (res as typeof res & { err?: Error }).err = err;
      res.status(500).end();
    });
    await request(app).get('/x').expect(500);
    await vi.waitFor(() => expect(lines.join('')).toContain('request errored'));
    const output = lines.join('');
    expect(output).not.toContain(SECRET);
    expect(output.match(/"type":"PrismaClientValidationError"/g)).toHaveLength(4);
  });
});
