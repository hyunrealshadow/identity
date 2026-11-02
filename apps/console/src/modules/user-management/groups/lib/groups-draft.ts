import type { LocalizedTextInput } from '#/gql/graphql'
import {
  createLocalizedDraft,
  localizedMetadata,
  localizedValuesEqual,
  localizedValuesFromEntries,
  restoreLocalizedDraft,
  type LocalizedDraft,
  type LocalizedSource,
  type LocalizedValues,
} from '#/lib/localized-values'

export type GroupTextDraft = LocalizedDraft
export type GroupSource = LocalizedSource

export function emptyGroupDraft(): GroupTextDraft {
  return createLocalizedDraft()
}

/** Seed every server locale, regional variants included. */
export function groupEditDraftFromGroup(group: GroupSource): GroupTextDraft {
  return createLocalizedDraft(group)
}

/**
 * Re-apply only the operator's edited and removed keys over a fresh server
 * read. Untouched translations stay current and explicit deletions stay gone.
 */
export function restoreGroupTextDraft(
  stored: unknown,
  fresh?: GroupSource,
): GroupTextDraft {
  return restoreLocalizedDraft(stored, fresh)
}

/** Full current map: every visible language, with deliberate deletions removed. */
export function groupLocalizedMetadata(
  draft: Pick<
    GroupTextDraft,
    'name' | 'description' | 'names' | 'descriptions'
  >,
): {
  name: string
  description: string
  names: LocalizedTextInput[]
  descriptions: LocalizedTextInput[]
} {
  return localizedMetadata(draft)
}

/** The independent default name is required; translations are optional. */
export function hasGroupName(
  draft: Pick<GroupTextDraft, 'name' | 'names'>,
): boolean {
  return draft.name.trim() !== ''
}

function sourceValues(entries: LocalizedSource['names']): LocalizedValues {
  return localizedValuesFromEntries(entries)
}

export function namesChanged(
  original: GroupSource,
  draft: Pick<GroupTextDraft, 'name' | 'names'>,
): boolean {
  return (
    (original.name ?? '').trim() !== draft.name.trim() ||
    !localizedValuesEqual(sourceValues(original.names), draft.names)
  )
}

export function descriptionsChanged(
  original: GroupSource,
  draft: Pick<GroupTextDraft, 'description' | 'descriptions'>,
): boolean {
  return (
    (original.description ?? '').trim() !== draft.description.trim() ||
    !localizedValuesEqual(
      sourceValues(original.descriptions),
      draft.descriptions,
    )
  )
}
