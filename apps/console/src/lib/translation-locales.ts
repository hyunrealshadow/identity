/** Selectable languages and commonly used regional/script variants. */
export const translationLocales = [
  ...new Set([
    ...`
  aa ab ae af ak am an ar as av ay az ba be bg bh bi bm bn bo
  br bs ca ce ch co cr cs cu cv cy da de dv dz ee el en eo es
  et eu fa ff fi fj fo fr fy ga gd gl gn gu gv ha he hi ho hr
  ht hu hy hz ia id ie ig ii ik io is it iu ja jv ka kg ki kj
  kk kl km kn ko kr ks ku kv kw ky la lb lg li ln lo lt lu lv
  mg mh mi mk ml mn mr ms mt my na nb nd ne ng nl nn no nr nv
  ny oc oj om or os pa pi pl ps pt qu rm rn ro ru rw sa sc sd
  se sg si sk sl sm sn so sq sr ss st su sv sw ta te tg th ti
  tk tl tn to tr ts tt tw ty ug uk ur uz ve vi vo wa wo xh yi
  yo za zh zu
  `
      .trim()
      .split(/\s+/),
    'ar-SA',
    'de-AT',
    'de-CH',
    'de-DE',
    'en-AU',
    'en-CA',
    'en-GB',
    'en-US',
    'es-ES',
    'es-MX',
    'fr-CA',
    'fr-FR',
    'it-IT',
    'ja-JP',
    'ko-KR',
    'pt-BR',
    'pt-PT',
    'sr-Cyrl',
    'sr-Latn',
    'zh-CN',
    'zh-HK',
    'zh-TW',
    'zh-Hans',
    'zh-Hant',
    'zh-Hans-CN',
    'zh-Hant-HK',
    'zh-Hant-TW',
  ]),
]

export interface TranslationLocaleOption {
  tag: string
  label: string
  search: string
}

const formatters = new Map<string, Intl.DisplayNames>()
const catalogs = new Map<string, readonly TranslationLocaleOption[]>()
const nativeNames = new Map<string, string>()

function languageName(tag: string, uiLocale: string): string {
  try {
    let formatter = formatters.get(uiLocale)
    if (!formatter) {
      formatter = new Intl.DisplayNames([uiLocale], { type: 'language' })
      formatters.set(uiLocale, formatter)
    }
    return formatter.of(tag) ?? tag
  } catch {
    return tag
  }
}

export function translationLocaleLabel(tag: string, uiLocale: string): string {
  const localized = languageName(tag, uiLocale)
  const name = localized === tag ? languageName(tag, 'en-US') : localized
  return name === tag ? tag : `${name} (${tag})`
}

/** Shared display/search data does not depend on the text being edited. */
export function translationLocaleOptions(
  uiLocale: string,
): readonly TranslationLocaleOption[] {
  const cached = catalogs.get(uiLocale)
  if (cached) return cached
  const options = translationLocales
    .map((tag) => {
      let native = nativeNames.get(tag)
      if (native === undefined) {
        native = languageName(tag, tag)
        nativeNames.set(tag, native)
      }
      const label = translationLocaleLabel(tag, uiLocale)
      return {
        tag,
        label,
        search: [label, native, languageName(tag, 'en-US')].join(' '),
      }
    })
    .sort((left, right) => left.label.localeCompare(right.label, uiLocale))
  catalogs.set(uiLocale, options)
  return options
}
