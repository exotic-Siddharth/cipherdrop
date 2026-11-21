import { describe, expect, it } from 'vitest';
import { previewKind } from './previewKind';

describe('previewKind', () => {
  it('previews raster images with the allowlisted type', () => {
    expect(previewKind('image/png', 10)).toEqual({ kind: 'image', type: 'image/png' });
    expect(previewKind('IMAGE/JPEG', 10)).toEqual({ kind: 'image', type: 'image/jpeg' });
  });

  it.each(['image/svg+xml', 'application/xhtml+xml', 'application/pdf', 'image/x-icon'])(
    'never previews %s',
    (type) => {
      expect(previewKind(type, 10)).toBeNull();
    },
  );

  it('shows text types, HTML and XML included, as text only, up to 1 MiB', () => {
    for (const type of ['text/plain', 'text/html', 'text/xml', 'application/json']) {
      expect(previewKind(type, 1024 * 1024), type).toEqual({ kind: 'text' });
    }
    expect(previewKind('text/plain', 1024 * 1024 + 1)).toBeNull();
  });
});
