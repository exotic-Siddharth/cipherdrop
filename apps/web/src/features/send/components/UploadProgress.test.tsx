import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { UploadProgress } from './UploadProgress';

describe('UploadProgress', () => {
  it('only the phase text is a live region; byte counts, speed and ETA are not announced (C-22)', () => {
    render(
      <UploadProgress
        phase="uploading"
        files={[
          {
            id: 'f1',
            name: 'a.bin',
            size: 4_000_000,
            type: 'application/octet-stream',
            encrypted: 2_000_000,
            uploaded: 1_000_000,
            done: false,
          },
        ]}
        speed={1_000_000}
        hex={null}
        retryNotice={null}
        onCancel={() => undefined}
        cancelling={false}
      />,
    );
    const phase = screen.getByText('Encrypting and uploading...');
    expect(phase.closest('[aria-live]')).not.toBeNull();
    const numbers = screen.getByText(/of 3\.8 MB/);
    expect(numbers.closest('[aria-live]')).toBeNull();
  });
});
