// @vitest-environment node
import { describe, expect, it } from 'vitest'

import { createLocalizedDraft } from '#/lib/localized-values'
import {
  emptyPermissionCreateDraft,
  hasPermissionMetadataChanges,
  permissionUpdateDraftFromSource,
  restorePermissionCreateDraft,
  restorePermissionUpdateDraft,
} from '#/modules/client-management/resources/permissions/lib/permissions-draft'

describe('permission localized metadata drafts', () => {
  it('detects third-language edits and removals', () => {
    const source = {
      names: [
        { locale: 'en-US', value: 'Read users' },
        { locale: 'fr-FR', value: 'Lire' },
      ],
      descriptions: [{ locale: 'de-DE', value: 'Benutzer lesen' }],
    }
    const draft = permissionUpdateDraftFromSource(source)
    expect(hasPermissionMetadataChanges(source, draft)).toBe(false)

    draft.names['fr-FR'] = 'Lire les utilisateurs'
    expect(hasPermissionMetadataChanges(source, draft)).toBe(true)

    const removed = permissionUpdateDraftFromSource(source)
    delete removed.descriptions['de-DE']
    expect(hasPermissionMetadataChanges(source, removed)).toBe(true)
  })

  it('restores non-sensitive create values without inventing metadata', () => {
    const fallback = emptyPermissionCreateDraft()
    const stored = {
      ...emptyPermissionCreateDraft(),
      names: { 'zh-CN': '读取用户' },
      resourceId: 'resource-1',
      code: 'users.read',
    }

    const restored = restorePermissionCreateDraft(stored, fallback)
    expect(restored.resourceId).toBe('resource-1')
    expect(restored.code).toBe('users.read')
    expect(restored.names).toEqual({ 'zh-CN': '读取用户' })
    expect(restored.descriptions).toEqual({})
  })

  it('replays only edited keys over fresh server translations on update restore', () => {
    const source = {
      names: [{ locale: 'en-US', value: 'Read users' }],
      descriptions: [],
    }
    const stored = createLocalizedDraft(source)
    stored.names['fr-FR'] = 'Lire'
    delete stored.names['en-US']

    const fresh = {
      names: [
        { locale: 'en-US', value: 'Read users updated' },
        { locale: 'ja-JP', value: 'ユーザーを読む' },
      ],
      descriptions: [{ locale: 'de-DE', value: 'Benutzer lesen' }],
    }

    const restored = restorePermissionUpdateDraft(stored, fresh)
    expect(restored.names).toEqual({
      'ja-JP': 'ユーザーを読む',
      'fr-FR': 'Lire',
    })
    expect(restored.descriptions).toEqual({
      'de-DE': 'Benutzer lesen',
    })
  })
})
