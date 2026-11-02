// @vitest-environment node
import { describe, expect, it } from 'vitest'

import {
  resolveLocalizedValue,
} from './localized-metadata'

describe('localized resource metadata', () => {
  it('resolves exact and parent locales, leaving unmatched values to the default', () => {
    const entries = [
      { locale: 'fr-FR', value: 'Lecture' },
      { locale: 'zh', value: '读取' },
      { locale: 'zh-CN', value: '读取用户' },
      { locale: 'en-US', value: 'Read' },
    ]
    expect(resolveLocalizedValue(entries, 'zh-CN')).toBe('读取用户')
    expect(resolveLocalizedValue(entries, 'zh-Hans-CN')).toBe('读取')
    expect(resolveLocalizedValue(entries, 'de-DE')).toBeUndefined()
    expect(resolveLocalizedValue([{ locale: 'fr-FR', value: 'Lecture' }], 'de-DE'))
      .toBeUndefined()
    expect(
      resolveLocalizedValue([{ locale: 'en-US', value: '   ' }], 'en-US'),
    ).toBeUndefined()
  })

})
