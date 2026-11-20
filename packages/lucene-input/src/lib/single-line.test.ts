import { describe, expect, it } from 'vitest';
import { preventNewlineKeymap, sanitizeSingleLineValue } from './single-line';

describe('single-line query behavior', () => {
  it('normalizes line breaks to spaces', () => {
    expect(sanitizeSingleLineValue('author:john\ntitle:hello\r\nstatus:open')).toBe(
      'author:john title:hello status:open'
    );
  });

  it('binds Enter and Shift-Enter to a no-op command', () => {
    expect(preventNewlineKeymap.map((binding) => binding.key)).toEqual(['Enter', 'Shift-Enter']);
  });
});
