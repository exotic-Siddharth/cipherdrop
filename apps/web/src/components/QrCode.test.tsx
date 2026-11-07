import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { QrCode } from './QrCode';

describe('QrCode (local qrcode -> SVG, R8)', () => {
  it('renders an accessible inline SVG built locally (no network, no innerHTML)', () => {
    const value = 'https://cipherdrop.example/d/AAAAAAAAAAAAAAAAAAAAAA#key';
    render(<QrCode value={value} label="QR code for the share link" size={160} />);
    const img = screen.getByRole('img', { name: 'QR code for the share link' });
    expect(img.tagName.toLowerCase()).toBe('svg');
    expect(img).toHaveAttribute('width', '160');
    const path = img.querySelector('path');
    // Horizontal runs of dark modules, offset by the 4-module quiet zone.
    expect(path?.getAttribute('d')).toMatch(/^M4 4h(\d+)v1h-\1z/);
    // Only drawing primitives: no text node, image or link with the link inside the SVG.
    expect(img.querySelector('text, image, a, foreignObject')).toBeNull();
    expect(img.innerHTML).not.toContain('cipherdrop.example');
  });

  it('changes the modules when the value changes', () => {
    const { rerender } = render(<QrCode value="first" label="QR" />);
    const first = screen.getByRole('img').querySelector('path')?.getAttribute('d');
    rerender(<QrCode value="second" label="QR" />);
    const second = screen.getByRole('img').querySelector('path')?.getAttribute('d');
    expect(first).toBeTruthy();
    expect(second).not.toBe(first);
  });
});
