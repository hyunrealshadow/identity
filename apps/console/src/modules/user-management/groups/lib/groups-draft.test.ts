// @vitest-environment node
import { describe, expect, it } from 'vitest'

import {
  descriptionsChanged,
  groupEditDraftFromGroup,
  hasGroupName,
  namesChanged,
  restoreGroupTextDraft,
  type GroupSource,
} from '#/modules/user-management/groups/lib/groups-draft'

const group: GroupSource = {
  name: 'Engineering default',
  description: 'Default team',
  names: [
    { locale: 'en-US', value: 'Engineering' },
    { locale: 'fr-CA', value: 'Ingénierie' },
  ],
  descriptions: [
    { locale: 'zh-CN', value: '团队' },
    { locale: 'de-DE', value: 'Team' },
  ],
}

describe('group drafts', () => {
  it('seeds every server locale into the localized maps', () => {
    const draft = groupEditDraftFromGroup(group)

    expect(draft.names).toEqual({
      'en-US': 'Engineering',
      'fr-CA': 'Ingénierie',
    })
    expect(draft.descriptions).toEqual({
      'zh-CN': '团队',
      'de-DE': 'Team',
    })
    expect(draft.baseline).toEqual({
      name: draft.name,
      description: draft.description,
      names: draft.names,
      descriptions: draft.descriptions,
    })
  })

  it('keeps a third-language edit and deletion while merging fresh remote translations', () => {
    const original = groupEditDraftFromGroup(group)
    const restored = restoreGroupTextDraft(
      {
        ...original,
        names: { 'en-US': 'Engineering', 'fr-CA': 'Génie' },
        descriptions: { 'zh-CN': '团队' },
      },
      {
        names: [
          ...(group.names ?? []),
          { locale: 'ja-JP', value: 'エンジニアリング' },
        ],
        descriptions: [
          ...(group.descriptions ?? []),
          { locale: 'ja-JP', value: 'チーム' },
        ],
      },
    )

    expect(restored.names['fr-CA']).toBe('Génie')
    expect(restored.names['ja-JP']).toBe('エンジニアリング')
    expect(restored.descriptions['de-DE']).toBeUndefined()
    expect(restored.descriptions['ja-JP']).toBe('チーム')
  })

  it('falls back to the fresh server source for invalid stored values', () => {
    const restored = restoreGroupTextDraft({ names: 'legacy' }, group)

    expect(restored.names).toEqual(groupEditDraftFromGroup(group).names)
    expect(restored.descriptions).toEqual(
      groupEditDraftFromGroup(group).descriptions,
    )
  })

  it('compares maps semantically and requires an independent default name', () => {
    const draft = groupEditDraftFromGroup(group)
    expect(namesChanged(group, draft)).toBe(false)
    expect(descriptionsChanged(group, draft)).toBe(false)

    const thirdLanguage = {
      ...draft,
      names: { ...draft.names, 'fr-CA': 'Génie' },
    }
    expect(namesChanged(group, thirdLanguage)).toBe(true)

    const deletion = { ...draft, descriptions: { 'zh-CN': '团队' } }
    expect(descriptionsChanged(group, deletion)).toBe(true)

    expect(hasGroupName(draft)).toBe(true)
    expect(hasGroupName({ name: 'Default', names: {} })).toBe(true)
    expect(hasGroupName({ name: '   ', names: { 'en-US': 'Name' } })).toBe(
      false,
    )
  })
})
