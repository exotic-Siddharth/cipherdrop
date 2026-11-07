import { render, screen, waitFor } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { PasswordStrength } from './PasswordStrength';

describe('PasswordStrength (lazy zxcvbn-ts v3, R8)', () => {
  it('rates a common password as very weak with feedback', async () => {
    const onScoreChange = vi.fn();
    render(<PasswordStrength password="password" onScoreChange={onScoreChange} />);
    expect(await screen.findByText('Very weak', {}, { timeout: 10_000 })).toBeInTheDocument();
    expect(screen.getByText(/most used passwords|commonly used/i)).toBeInTheDocument();
    expect(onScoreChange).toHaveBeenLastCalledWith(0);
    expect(screen.getByRole('meter', { name: /password strength/i })).toHaveAttribute(
      'aria-valuenow',
      '0',
    );
  });

  it('rates a long random passphrase as very strong and penalises user inputs', async () => {
    const onScoreChange = vi.fn();
    const { rerender } = render(
      <PasswordStrength
        password="quartz-velvet-orbit-1837-lantern"
        onScoreChange={onScoreChange}
      />,
    );
    expect(await screen.findByText('Very strong', {}, { timeout: 10_000 })).toBeInTheDocument();
    expect(onScoreChange).toHaveBeenLastCalledWith(4);

    rerender(<PasswordStrength password="" onScoreChange={onScoreChange} />);
    await waitFor(() => expect(onScoreChange).toHaveBeenLastCalledWith(null));
    expect(screen.queryByText('Very strong')).not.toBeInTheDocument();

    rerender(
      <PasswordStrength
        password="ada.lovelace"
        userInputs={['ada.lovelace@example.com', 'ada.lovelace']}
        onScoreChange={onScoreChange}
      />,
    );
    await waitFor(() => expect(onScoreChange.mock.lastCall?.[0]).toBeLessThanOrEqual(1));
  });
});
