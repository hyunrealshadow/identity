export type LocalizedValues = Record<string, string>

export interface LocalizedEntry {
  locale: string
  value: string
}

export interface LocalizedSource {
  name?: string | null
  description?: string | null
  names?: ReadonlyArray<LocalizedEntry> | null
  descriptions?: ReadonlyArray<LocalizedEntry> | null
}

export interface LocalizedDraft {
  name: string
  description: string
  names: LocalizedValues
  descriptions: LocalizedValues
  baseline: {
    name: string
    description: string
    names: LocalizedValues
    descriptions: LocalizedValues
  }
}

export const MAX_TRANSLATIONS = 20

/** Keep the same conservative language-tag canonicalization as the API. */
export function canonicalTranslationLocale(input: string): string | undefined {
  const value = input.trim().replaceAll('_', '-')
  if (!value || value.length > 35) return undefined
  const parts = value.split('-')
  const language = parts.shift() ?? ''
  if (!/^[a-z]{2,8}$/i.test(language)) return undefined
  const result = [language.toLowerCase()]
  let index = 0
  if (/^[a-z]{4}$/i.test(parts[index] ?? '')) {
    const script = parts[index++]!
    result.push(script[0]!.toUpperCase() + script.slice(1).toLowerCase())
  }
  if (/^(?:[a-z]{2}|\d{3})$/i.test(parts[index] ?? '')) {
    result.push(parts[index++]!.toUpperCase())
  }
  for (const variant of parts.slice(index)) {
    if (!/^[a-z0-9]{1,8}$/i.test(variant)) return undefined
    result.push(variant.toLowerCase())
  }
  return result.join('-')
}

export function localizedValuesFromEntries(
  entries?: ReadonlyArray<LocalizedEntry> | null,
): LocalizedValues {
  return Object.fromEntries(
    (entries ?? []).map(({ locale, value }) => [
      canonicalTranslationLocale(locale) ?? locale,
      value,
    ]),
  )
}

/** Full replacement payload: omitted/blank translations are deliberately removed. */
export function localizedEntries(values: LocalizedValues): LocalizedEntry[] {
  return Object.entries(values)
    .filter(([, value]) => value.trim() !== '')
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([locale, value]) => ({ locale, value: value.trim() }))
}

export function localizedValuesEqual(
  left: LocalizedValues,
  right: LocalizedValues,
): boolean {
  return (
    JSON.stringify(localizedEntries(left)) ===
    JSON.stringify(localizedEntries(right))
  )
}

export function hasLocalizedValue(values: LocalizedValues): boolean {
  return Object.values(values).some((value) => value.trim() !== '')
}

export function createLocalizedDraft(
  source: LocalizedSource = {},
): LocalizedDraft {
  const names = localizedValuesFromEntries(source.names)
  const descriptions = localizedValuesFromEntries(source.descriptions)
  const name = source.name ?? ''
  const description = source.description ?? ''
  return {
    name,
    description,
    names,
    descriptions,
    baseline: {
      name,
      description,
      names: { ...names },
      descriptions: { ...descriptions },
    },
  }
}

function record(value: unknown): Record<string, unknown> | undefined {
  if (!value || typeof value !== 'object' || Array.isArray(value))
    return undefined
  return value as Record<string, unknown>
}

function storedValues(value: unknown): LocalizedValues | undefined {
  const object = record(value)
  if (!object) return undefined
  const entries = Object.entries(object)
  if (
    entries.some(
      ([key, text]) =>
        typeof text !== 'string' || canonicalTranslationLocale(key) !== key,
    )
  ) {
    return undefined
  }
  return Object.fromEntries(entries) as LocalizedValues
}

function restoreEditedValues(
  edited: LocalizedValues,
  baseline: LocalizedValues,
  fresh: LocalizedValues,
): LocalizedValues {
  const result = { ...fresh }
  for (const language of new Set([
    ...Object.keys(baseline),
    ...Object.keys(edited),
  ])) {
    const previous = baseline[language]?.trim() ?? ''
    const next = edited[language]?.trim() ?? ''
    if (previous === next) {
      // Retain an explicitly added empty editor row without overwriting fresh text.
      if (
        !(language in baseline) &&
        language in edited &&
        !(language in fresh)
      ) {
        result[language] = edited[language]!
      }
      continue
    }
    if (next) result[language] = edited[language]!
    else delete result[language]
  }
  return result
}

/** Reapply only the user's edits/deletions over a new read after authentication. */
export function restoreLocalizedDraft(
  stored: unknown,
  fresh: LocalizedSource = {},
): LocalizedDraft {
  const fallback = createLocalizedDraft(fresh)
  const object = record(stored)
  const baseline = record(object?.baseline)
  const oldNames = storedValues(baseline?.names)
  const oldDescriptions = storedValues(baseline?.descriptions)
  if (!object || !oldNames || !oldDescriptions) return fallback
  const names = storedValues(object.names)
  const descriptions = storedValues(object.descriptions)
  return {
    ...fallback,
    name:
      typeof object.name === 'string' &&
      typeof baseline?.name === 'string' &&
      object.name.trim() !== baseline.name.trim()
        ? object.name
        : fallback.name,
    description:
      typeof object.description === 'string' &&
      typeof baseline?.description === 'string' &&
      object.description.trim() !== baseline.description.trim()
        ? object.description
        : fallback.description,
    names: names
      ? restoreEditedValues(names, oldNames, fallback.names)
      : fallback.names,
    descriptions: descriptions
      ? restoreEditedValues(
          descriptions,
          oldDescriptions,
          fallback.descriptions,
        )
      : fallback.descriptions,
  }
}

export function hasLocalizedDraftChanges(
  source: LocalizedSource,
  draft: Pick<
    LocalizedDraft,
    'name' | 'description' | 'names' | 'descriptions'
  >,
): boolean {
  const original = createLocalizedDraft(source)
  return (
    original.name.trim() !== draft.name.trim() ||
    original.description.trim() !== draft.description.trim() ||
    !localizedValuesEqual(original.names, draft.names) ||
    !localizedValuesEqual(original.descriptions, draft.descriptions)
  )
}

export function localizedMetadata(
  draft: Pick<
    LocalizedDraft,
    'name' | 'description' | 'names' | 'descriptions'
  >,
): {
  name: string
  description: string
  names: LocalizedEntry[]
  descriptions: LocalizedEntry[]
} {
  return {
    name: draft.name.trim(),
    description: draft.description.trim(),
    names: localizedEntries(draft.names),
    descriptions: localizedEntries(draft.descriptions),
  }
}
