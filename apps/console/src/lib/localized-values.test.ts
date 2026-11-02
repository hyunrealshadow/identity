// @vitest-environment node
import { describe, expect, it } from 'vitest'
import {
  canonicalTranslationLocale,
  createLocalizedDraft,
  hasLocalizedValue,
  localizedEntries,
  localizedMetadata,
  localizedValuesEqual,
  restoreLocalizedDraft,
} from './localized-values'

describe('localized field values', () => {
  it('canonicalizes regional/script/numeric tags and rejects malformed tags', () => {
    expect(canonicalTranslationLocale(' zh_hant_tw ')).toBe('zh-Hant-TW')
    expect(canonicalTranslationLocale('ES-419')).toBe('es-419')
    expect(canonicalTranslationLocale('EN-us')).toBe('en-US')
    for (const value of ['', 'en--US', 'x', 'en-@', 'a'.repeat(36)]) {
      expect(canonicalTranslationLocale(value)).toBeUndefined()
    }
  })

  it('round-trips all languages, including third languages and regional values', () => {
    const source = {
      name: 'Default readers',
      description: 'Default description',
      names: [
        { locale: 'en-US', value: 'Readers' },
        { locale: 'fr-CA', value: 'Lecteurs' },
        { locale: 'zh-Hant-TW', value: '讀者' },
      ],
      descriptions: [{ locale: 'de-DE', value: 'Lesen' }],
    }
    expect(localizedMetadata(createLocalizedDraft(source))).toEqual(source)
  })

  it('omits cleared translations and ignores order/whitespace for dirty checks', () => {
    expect(localizedEntries({ 'fr-FR': ' Lire ', 'en-US': '' })).toEqual([
      { locale: 'fr-FR', value: 'Lire' },
    ])
    expect(
      localizedValuesEqual(
        { 'fr-FR': 'Lire', 'en-US': '' },
        { 'fr-FR': ' Lire ' },
      ),
    ).toBe(true)
    expect(hasLocalizedValue({ 'ja-JP': '閲覧者' })).toBe(true)
  })

  it('restores only edited translations over a fresh server read and preserves deletion', () => {
    const draft = createLocalizedDraft({
      names: [
        { locale: 'en-US', value: 'Readers' },
        { locale: 'fr-FR', value: 'Lecteurs' },
        { locale: 'ja-JP', value: 'Old' },
      ],
    })
    draft.names['fr-FR'] = 'Lecteurs modifiés'
    delete draft.names['en-US']
    const restored = restoreLocalizedDraft(draft, {
      names: [
        { locale: 'en-US', value: 'Readers updated remotely' },
        { locale: 'fr-FR', value: 'Lecteurs' },
        { locale: 'ja-JP', value: '新しい' },
        { locale: 'de-DE', value: 'Leser' },
      ],
    })
    expect(restored.names).toEqual({
      'fr-FR': 'Lecteurs modifiés',
      'ja-JP': '新しい',
      'de-DE': 'Leser',
    })
    expect(restored.baseline.names['en-US']).toBe('Readers updated remotely')
  })

  it('restores edited defaults independently and keeps untouched defaults fresh', () => {
    const draft = createLocalizedDraft({
      name: 'Old',
      description: 'Old description',
    })
    draft.name = 'Edited default'
    draft.names['fr-FR'] = 'Traduction'
    const restored = restoreLocalizedDraft(draft, {
      name: 'Remote',
      description: 'Fresh description',
    })
    expect(localizedMetadata(restored)).toEqual({
      name: 'Edited default',
      description: 'Fresh description',
      names: [{ locale: 'fr-FR', value: 'Traduction' }],
      descriptions: [],
    })
    restored.names = {}
    expect(localizedMetadata(restored).name).toBe('Edited default')
  })

  it('keeps an empty added language in the draft without sending an empty translation', () => {
    const draft = createLocalizedDraft()
    draft.names['fr-FR'] = ''
    expect(restoreLocalizedDraft(draft).names).toEqual({ 'fr-FR': '' })
    expect(localizedMetadata(draft).names).toEqual([])
  })

  it('does not apply stale fixed-language or malformed stored drafts', () => {
    const source = { names: [{ locale: 'fr-FR', value: 'Lecteurs' }] }
    expect(
      restoreLocalizedDraft({ names: { enUS: 'Unexpected' } }, source).names,
    ).toEqual({ 'fr-FR': 'Lecteurs' })
    const draft = createLocalizedDraft(source)
    expect(
      restoreLocalizedDraft({ ...draft, names: { 'fr-FR': false } }, source)
        .names,
    ).toEqual(draft.names)
  })
})
