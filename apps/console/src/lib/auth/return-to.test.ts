import { describe, expect, it } from 'vitest'

import { sanitizeReturnTo } from './return-to'

const ORIGIN = 'https://console.example'

describe('sanitizeReturnTo', () => {
  it('accepts same-origin paths and relative paths', () => {
    expect(sanitizeReturnTo('/account/profile?tab=1#top', ORIGIN)).toBe(
      '/account/profile?tab=1#top',
    )
    expect(sanitizeReturnTo('account/sessions', ORIGIN)).toBe(
      '/account/sessions',
    )
    expect(sanitizeReturnTo(`${ORIGIN}/account/security?x=1`, ORIGIN)).toBe(
      '/account/security?x=1',
    )
  })

  it('falls back for missing or unsafe values', () => {
    for (const value of [
      undefined,
      null,
      42,
      '',
      '//evil.example/path',
      '//console.example/path',
      'https://evil.example/path',
      'http://console.example.evil.example/path',
      'javascript:alert(1)',
      'data:text/html,hi',
      '/\\evil.example',
      '/%5cevil.example',
      '/%5Cevil.example',
      'https://user:pass@console.example/path',
      '/path\nheader: value',
    ]) {
      expect(sanitizeReturnTo(value, ORIGIN)).toBe('/')
    }
  })
})
