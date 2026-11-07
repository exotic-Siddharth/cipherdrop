/**
 * Password strength estimation with @zxcvbn-ts v3 (spec 4, R8), loaded lazily: the dictionaries are a large
 * chunk that only pages with a password field ever download. Runs entirely in the browser; the password never
 * leaves this function.
 *
 * Only @zxcvbn-ts/core + language-common are installed (no language-en), so the English feedback text below
 * is our own, keyed by core's v3 translation keys.
 */
import type { TranslationKeys, ZxcvbnResult } from '@zxcvbn-ts/core';

export type StrengthScore = 0 | 1 | 2 | 3 | 4;

export const STRENGTH_LABELS: Readonly<Record<StrengthScore, string>> = Object.freeze({
  0: 'Very weak',
  1: 'Weak',
  2: 'Fair',
  3: 'Strong',
  4: 'Very strong',
});

export interface PasswordStrength {
  score: StrengthScore;
  label: string;
  warning: string | null;
  suggestions: string[];
  /**
   * Estimated time to guess it offline at 10k guesses/s: the "database breach + slow hash" scenario that
   * matters here, because CipherDrop stretches passwords with Argon2id.
   */
  crackTime: string;
}

export type PasswordStrengthEstimator = (
  password: string,
  userInputs?: readonly string[],
) => PasswordStrength;

/** Words every CipherDrop password is penalised for containing. */
const APP_WORDS = ['cipherdrop', 'cipher', 'drop'];

const EN_TRANSLATIONS: TranslationKeys = {
  warnings: {
    straightRow: 'Straight rows of keys on your keyboard are easy to guess.',
    keyPattern: 'Short keyboard patterns are easy to guess.',
    simpleRepeat: 'Repeated characters like "aaa" are easy to guess.',
    extendedRepeat: 'Repeated patterns like "abcabcabc" are easy to guess.',
    sequences: 'Common sequences like "abc" or "123" are easy to guess.',
    recentYears: 'Recent years are easy to guess.',
    dates: 'Dates are easy to guess.',
    topTen: 'This is one of the most used passwords.',
    topHundred: 'This is a very frequently used password.',
    common: 'This is a commonly used password.',
    similarToCommon: 'This is similar to a commonly used password.',
    wordByItself: 'A single word is easy to guess.',
    namesByThemselves: 'Single names or surnames are easy to guess.',
    commonNames: 'Common names and surnames are easy to guess.',
    userInputs: 'Avoid words related to you or to this site, such as your email address.',
    pwned: 'This password appeared in a data breach.',
  },
  suggestions: {
    l33t: "Avoid predictable substitutions like '@' for 'a'.",
    reverseWords: 'Avoid common words spelled backwards.',
    allUppercase: 'Capitalise some letters, not all of them.',
    capitalization: 'Capitalise more than the first letter.',
    dates: 'Avoid dates and years that are associated with you.',
    recentYears: 'Avoid recent years.',
    associatedYears: 'Avoid years that are associated with you.',
    sequences: 'Avoid common character sequences.',
    repeated: 'Avoid repeated words and characters.',
    longerKeyboardPattern: 'Use longer keyboard patterns and change direction several times.',
    anotherWord: 'Add another word or two. Uncommon words are better.',
    useWords: 'Use several words, but avoid common phrases.',
    noNeed: 'You can make a strong password without symbols, numbers or uppercase letters.',
    pwned: 'If you use this password anywhere else, change it there.',
  },
  timeEstimation: {
    ltSecond: 'less than a second',
    second: '{base} second',
    seconds: '{base} seconds',
    minute: '{base} minute',
    minutes: '{base} minutes',
    hour: '{base} hour',
    hours: '{base} hours',
    day: '{base} day',
    days: '{base} days',
    month: '{base} month',
    months: '{base} months',
    year: '{base} year',
    years: '{base} years',
    centuries: 'centuries',
  },
};

function toStrength(result: ZxcvbnResult): PasswordStrength {
  const score = result.score as StrengthScore;
  return {
    score,
    label: STRENGTH_LABELS[score],
    warning: result.feedback.warning || null,
    suggestions: result.feedback.suggestions,
    crackTime: String(result.crackTimesDisplay.offlineSlowHashing1e4PerSecond),
  };
}

let loading: Promise<PasswordStrengthEstimator> | null = null;

/** Load (once) and configure zxcvbn; resolves with a synchronous estimator. */
export function loadPasswordStrength(): Promise<PasswordStrengthEstimator> {
  if (!loading) {
    loading = (async () => {
      const [core, common] = await Promise.all([
        import('@zxcvbn-ts/core'),
        import('@zxcvbn-ts/language-common'),
      ]);
      core.zxcvbnOptions.setOptions({
        dictionary: { ...common.dictionary },
        graphs: common.adjacencyGraphs,
        translations: EN_TRANSLATIONS,
        useLevenshteinDistance: true,
      });
      return (password: string, userInputs: readonly string[] = []) =>
        toStrength(core.zxcvbn(password, [...userInputs, ...APP_WORDS]));
    })();
    // A failed chunk load (offline, new deploy) may be retried later.
    loading.catch(() => {
      loading = null;
    });
  }
  return loading;
}

/** One-shot estimate (W1 can use it to gate a submit). */
export async function estimatePasswordStrength(
  password: string,
  userInputs?: readonly string[],
): Promise<PasswordStrength> {
  const estimate = await loadPasswordStrength();
  return estimate(password, userInputs);
}
