import { render, screen } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { FilePreview } from './FilePreview';

const HOSTILE = '<img src=x onerror="alert(1)"><script>alert(document.domain)</script><b>bold</b>';

describe('FilePreview (crypto-3)', () => {
  let created: Blob[];
  beforeEach(() => {
    created = [];
    URL.createObjectURL = vi.fn((b: Blob | MediaSource) => {
      created.push(b as Blob);
      return 'blob:preview';
    });
    URL.revokeObjectURL = vi.fn();
  });

  it('decodes a raster image from a URL typed with the allowlisted type, not the Blob type', async () => {
    const saved = new Blob([new Uint8Array([137, 80, 78, 71])], {
      type: 'application/octet-stream',
    });
    render(<FilePreview blob={saved} type="image/png" name="cat.png" />);
    const img = await screen.findByRole('img', { name: 'Preview of cat.png' });
    expect(img).toHaveAttribute('src', 'blob:preview');
    expect(created).toHaveLength(1);
    expect(created[0]!.type).toBe('image/png');
    expect(created[0]!.size).toBe(saved.size);
  });

  it('never previews SVG: no image, no object URL', () => {
    const svg = new Blob([
      '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>',
    ]);
    const { container } = render(<FilePreview blob={svg} type="image/svg+xml" name="x.svg" />);
    expect(container).toBeEmptyDOMElement();
    expect(URL.createObjectURL).not.toHaveBeenCalled();
  });

  it('shows HTML as its source text, never as markup', async () => {
    // jsdom's Blob has no text() (R20); a browser's has.
    const html = Object.assign(new Blob([HOSTILE], { type: 'application/octet-stream' }), {
      text: async () => HOSTILE,
    });
    const { container } = render(<FilePreview blob={html} type="text/html" name="page.html" />);
    const pre = await screen.findByLabelText('Preview of page.html');
    expect(pre.tagName).toBe('PRE');
    expect(pre.textContent).toBe(HOSTILE);
    expect(container.querySelector('img, script, b')).toBeNull();
    expect(URL.createObjectURL).not.toHaveBeenCalled();
  });
});
