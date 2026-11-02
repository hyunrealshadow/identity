export interface LocalizedValue {
  locale: string
  value: string
}

const FALLBACK_LOCALE = 'en-US'

function sameLocale(left: string, right: string): boolean {
  return left.trim().toLowerCase() === right.trim().toLowerCase()
}

function parentTags(value: string): string[] {
  const tags: string[] = []
  let tag = value.trim()
  while (tag) {
    tags.push(tag)
    const separator = tag.lastIndexOf('-')
    tag = separator < 0 ? '' : tag.slice(0, separator)
  }
  return tags
}

/**
 * Resolve display text without inventing a translation:
 * exact locale, then parent locale; callers fall back to the independent default.
 * Callers add their own base name/key/code fallback after this returns undefined.
 */
export function resolveLocalizedValue(
  entries: ReadonlyArray<LocalizedValue> | null | undefined,
  locale: string,
): string | undefined {
  if (!entries?.length) return undefined
  const available = entries.filter((entry) => entry.value.trim())
  if (available.length === 0) return undefined

  for (const tag of parentTags(locale)) {
    const match = available.find((entry) => sameLocale(entry.locale, tag))
    if (match) return match.value
  }
  return undefined
}

export function canonicalResourceLocale(value: string | null | undefined): string {
  try {
    return value?.trim() ? Intl.getCanonicalLocales(value.trim())[0] : FALLBACK_LOCALE
  } catch {
    return FALLBACK_LOCALE
  }
}
