import { useEffect, useId, useMemo, useRef, useState } from 'react';
import { cn } from '../lib/cn';
import { useDebouncedValue } from '../lib/hooks';
import {
  loadPasswordStrength,
  type PasswordStrengthEstimator,
  type StrengthScore,
} from '../lib/passwordStrength';

export interface PasswordStrengthProps {
  password: string;
  /** Words that make a password weak for this user (email, name); always also penalises "cipherdrop". */
  userInputs?: readonly string[];
  /** Called with 0-4, or null while empty/loading. Use it to gate a submit (e.g. require >= 3). */
  onScoreChange?: (score: StrengthScore | null) => void;
  /** id of the meter block, for the password input's aria-describedby. */
  id?: string;
  className?: string;
}

const BAR_TONES: Record<StrengthScore, string> = {
  0: 'bg-danger',
  1: 'bg-danger',
  2: 'bg-warning',
  3: 'bg-success',
  4: 'bg-success',
};

const TEXT_TONES: Record<StrengthScore, string> = {
  0: 'text-danger-ink',
  1: 'text-danger-ink',
  2: 'text-warning-ink',
  3: 'text-success-ink',
  4: 'text-success-ink',
};

const SEPARATOR = '\u0000';

/**
 * Password strength meter (spec 11.2, R8). zxcvbn-ts v3 and its dictionaries load lazily on first mount; the
 * estimate runs locally and the password never leaves the page.
 */
export function PasswordStrength({
  password,
  userInputs,
  onScoreChange,
  id,
  className,
}: PasswordStrengthProps) {
  const autoId = useId();
  const baseId = id ?? autoId;
  const [estimator, setEstimator] = useState<PasswordStrengthEstimator | null>(null);
  const [loadFailed, setLoadFailed] = useState(false);

  useEffect(() => {
    let alive = true;
    loadPasswordStrength()
      .then((estimate) => {
        if (alive) setEstimator(() => estimate);
      })
      .catch(() => {
        if (alive) setLoadFailed(true);
      });
    return () => {
      alive = false;
    };
  }, []);

  const debounced = useDebouncedValue(password, 120);
  const effective = password ? debounced : '';
  const inputsKey = (userInputs ?? []).join(SEPARATOR);
  const inputs = useMemo(() => (inputsKey ? inputsKey.split(SEPARATOR) : []), [inputsKey]);
  const result = useMemo(
    () => (estimator && effective ? estimator(effective, inputs) : null),
    [estimator, effective, inputs],
  );
  const score = result?.score ?? null;

  const callback = useRef(onScoreChange);
  useEffect(() => {
    callback.current = onScoreChange;
  });
  useEffect(() => {
    callback.current?.(score);
  }, [score]);

  const filled = result ? Math.max(1, result.score) : 0;

  return (
    <div id={baseId} className={cn('flex flex-col gap-1.5', className)}>
      <div
        role="meter"
        aria-label="Password strength"
        aria-valuemin={0}
        aria-valuemax={4}
        aria-valuenow={score ?? 0}
        aria-valuetext={result ? result.label : 'No password entered'}
        className="grid grid-cols-4 gap-1.5"
      >
        {[0, 1, 2, 3].map((i) => (
          <span
            key={i}
            className={cn(
              'h-1.5 rounded-full transition-colors duration-200',
              result && i < filled ? BAR_TONES[result.score] : 'bg-border',
            )}
          />
        ))}
      </div>
      <div aria-live="polite" className="min-h-5 text-xs leading-relaxed">
        {!password ? (
          <span className="text-muted-strong">
            Tip: a few random words make a strong password that is easy to remember.
          </span>
        ) : loadFailed ? (
          <span className="text-muted-strong">The strength check could not load.</span>
        ) : !result ? (
          <span className="text-muted-strong">Checking strength…</span>
        ) : (
          <span>
            <span className={cn('font-semibold', TEXT_TONES[result.score])}>{result.label}</span>
            {result.warning ? <span className="text-muted-strong"> · {result.warning}</span> : null}
          </span>
        )}
      </div>
      {result && result.score < 3 && result.suggestions[0] ? (
        <p className="text-xs leading-relaxed text-muted-strong">{result.suggestions[0]}</p>
      ) : null}
      {result ? (
        <p className="text-xs text-muted-strong">
          Estimated time to guess it after a data breach:{' '}
          <span className="font-medium text-foreground">{result.crackTime}</span>
        </p>
      ) : null}
    </div>
  );
}
