import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { CopyButton, CopyField } from './CopyField';

describe('CopyField', () => {
  it('shows the value read-only and copies it with visible and announced feedback', async () => {
    const user = userEvent.setup();
    const onCopied = vi.fn();
    const link =
      'https://cipherdrop.example/d/AAAAAAAAAAAAAAAAAAAAAA#0123456789abcdefghijklmnopqrstuvwxyzABCDEFG';
    render(<CopyField label="Share link" value={link} onCopied={onCopied} />);

    const input = screen.getByLabelText('Share link');
    expect(input).toHaveValue(link);
    expect(input).toHaveAttribute('readonly');

    await user.click(screen.getByRole('button', { name: 'Copy' }));

    expect(await navigator.clipboard.readText()).toBe(link);
    expect(screen.getByRole('button', { name: 'Copied' })).toBeInTheDocument();
    expect(screen.getByText('Copied to clipboard')).toBeInTheDocument();
    expect(onCopied).toHaveBeenCalledTimes(1);
  });
});

describe('CopyButton', () => {
  it('icon-only variant keeps an accessible name', async () => {
    const user = userEvent.setup();
    render(<CopyButton value="ABCD-EFGH" label="Copy recovery key" iconOnly />);
    await user.click(screen.getByRole('button', { name: 'Copy recovery key' }));
    expect(await navigator.clipboard.readText()).toBe('ABCD-EFGH');
    expect(screen.getByRole('button', { name: 'Copied' })).toBeInTheDocument();
  });
});
