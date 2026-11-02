import {
  createLocalizedDraft,
  hasLocalizedDraftChanges,
  restoreLocalizedDraft,
  type LocalizedDraft,
  type LocalizedSource,
} from '#/lib/localized-values'

export type PermissionLocalizedSource = LocalizedSource

export type PermissionCreateDraft = LocalizedDraft & {
  resourceId: string
  code: string
}

export type PermissionUpdateDraft = LocalizedDraft

export function emptyPermissionCreateDraft(): PermissionCreateDraft {
  return {
    ...createLocalizedDraft(),
    resourceId: '',
    code: '',
  }
}

/** Seed the edit draft from every server translation, never a guess. */
export function permissionUpdateDraftFromSource(
  source: PermissionLocalizedSource,
): PermissionUpdateDraft {
  return createLocalizedDraft(source)
}

export function hasPermissionMetadataChanges(
  source: LocalizedSource,
  draft: Pick<
    LocalizedDraft,
    'name' | 'description' | 'names' | 'descriptions'
  >,
): boolean {
  return hasLocalizedDraftChanges(source, draft)
}

function text(value: unknown, fallback: string): string {
  return typeof value === 'string' ? value : fallback
}

/**
 * Restore non-sensitive nonmetadata values after a step-up round trip while
 * the shared localized draft helper replays only the user's actual edits over
 * the current translations.
 */
export function restorePermissionCreateDraft(
  stored: Partial<PermissionCreateDraft> | null | undefined,
  fallback: PermissionCreateDraft,
): PermissionCreateDraft {
  const metadata = restoreLocalizedDraft(stored)
  return {
    ...metadata,
    resourceId: text(stored?.resourceId, fallback.resourceId),
    code: text(stored?.code, fallback.code),
  }
}

export function restorePermissionUpdateDraft(
  stored: unknown,
  source: PermissionLocalizedSource,
): PermissionUpdateDraft {
  return restoreLocalizedDraft(stored, source)
}
