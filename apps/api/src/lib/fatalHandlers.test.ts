/**
 * C-10: an unhandled rejection or uncaught exception must leave a structured fatal log and a non-zero exit
 * (Node's default is a raw stack trace), not be swallowed.
 */
import { EventEmitter } from 'node:events';
import { describe, expect, it, vi } from 'vitest';
import { installFatalHandlers } from './fatalHandlers';

describe('installFatalHandlers', () => {
  const setup = () => {
    const proc = new EventEmitter();
    const logger = { fatal: vi.fn() };
    const exit = vi.fn();
    installFatalHandlers(proc, logger, exit);
    return { proc, logger, exit };
  };

  it('logs an unhandled rejection with logger.fatal and exits 1', () => {
    const { proc, logger, exit } = setup();
    const err = new Error('redis down');
    proc.emit('unhandledRejection', err, Promise.resolve());
    expect(logger.fatal).toHaveBeenCalledTimes(1);
    expect(logger.fatal.mock.calls[0]?.[0]).toMatchObject({ err });
    expect(exit).toHaveBeenCalledWith(1);
  });

  it('logs an uncaught exception with logger.fatal and exits 1', () => {
    const { proc, logger, exit } = setup();
    proc.emit('uncaughtException', new Error('boom'));
    expect(logger.fatal).toHaveBeenCalledTimes(1);
    expect(exit).toHaveBeenCalledWith(1);
  });

  it('wraps a non-Error rejection reason', () => {
    const { proc, logger } = setup();
    proc.emit('unhandledRejection', 'just a string', Promise.resolve());
    expect(logger.fatal.mock.calls[0]?.[0]).toMatchObject({ err: { message: 'just a string' } });
  });
});
