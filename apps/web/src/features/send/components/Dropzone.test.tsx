import { fireEvent, render, screen } from '@testing-library/react';
import { toast } from 'sonner';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { Dropzone } from './Dropzone';

vi.mock('sonner', () => ({ toast: { error: vi.fn() } }));

function item(file: File, isDirectory: boolean) {
  return {
    kind: 'file',
    webkitGetAsEntry: () => ({ isDirectory }),
    getAsFile: () => file,
  };
}

function drop(items: ReturnType<typeof item>[]) {
  const zone = screen.getByTestId('file-input').parentElement!;
  fireEvent.drop(zone, {
    dataTransfer: { types: ['Files'], files: items.map((i) => i.getAsFile()), items },
  });
}

afterEach(() => vi.clearAllMocks());

describe('Dropzone', () => {
  it('takes dropped files and skips dropped folders with a clear message (C-41)', () => {
    const onFiles = vi.fn();
    render(<Dropzone onFiles={onFiles} />);
    const doc = new File(['hello'], 'doc.txt');
    drop([item(new File([], 'photos'), true), item(doc, false)]);
    expect(onFiles).toHaveBeenCalledTimes(1);
    expect(onFiles.mock.calls[0]![0]).toEqual([doc]);
    expect(toast.error).toHaveBeenCalledWith('Folders are not supported', expect.anything());
  });

  it('a folder alone adds nothing and still explains why (C-41)', () => {
    const onFiles = vi.fn();
    render(<Dropzone onFiles={onFiles} />);
    drop([item(new File([], 'photos'), true)]);
    expect(onFiles).not.toHaveBeenCalled();
    expect(toast.error).toHaveBeenCalledTimes(1);
  });
});
