// @vitest-environment node
import { describe, expect, it } from 'vitest'

import {
  createDraftFromEmpty,
  createDraftSnapshot,
  createDraftSnapshotHasContent,
  editDraftFromUser,
  editDraftSnapshot,
  editDraftSnapshotHasContent,
  restoreCreateDraft,
  restoreEditDraft,
  updateInputFromDraft,
  type ProjectedUser,
} from '#/modules/user-management/users/lib/user-form'

function user(overrides: Partial<ProjectedUser> = {}): ProjectedUser {
  return {
    id: 'User:1',
    username: 'ada',
    email: 'ada@example.test',
    emailVerified: true,
    enabled: true,
    locked: false,
    lockedUntil: null,
    failedAttempts: 0,
    version: '9f0c2b1a-3d4e-4f50-8a9b-1c2d3e4f5a6b',
    givenName: null,
    familyName: null,
    middleName: null,
    nickname: 'ada',
    profile: null,
    picture: null,
    website: null,
    birthdate: null,
    locale: null,
    theme: null,
    createdAt: '2026-01-01T00:00:00Z',
    updatedAt: null,
    ...overrides,
  }
}

describe('sparse user updates', () => {
  it('submits only changed identifier and profile fields', () => {
    const current = user()
    const draft = editDraftFromUser(current)
    draft.username = 'ada.lovelace'
    draft.profile.givenName = 'Ada'

    const input = updateInputFromDraft(current, draft)

    expect(input).toEqual({
      id: 'User:1',
      expectedVersion: '9f0c2b1a-3d4e-4f50-8a9b-1c2d3e4f5a6b',
      username: 'ada.lovelace',
      profile: { givenName: 'Ada' },
    })
    expect(input?.email).toBeUndefined()
    expect(input?.profile?.nickname).toBeUndefined()
  })

  it('clears a nullable profile field with an explicit null', () => {
    const current = user({ nickname: 'ada' })
    const draft = editDraftFromUser(current)
    draft.profile.nickname = ''

    const input = updateInputFromDraft(current, draft)

    expect(input?.profile).toEqual({ nickname: null })
  })

  it('refuses to build an update without a current version', () => {
    const current = user({ version: undefined })
    const draft = editDraftFromUser(current)

    expect(updateInputFromDraft(current, draft)).toBeNull()
  })
})

describe('safe edit draft snapshots', () => {
  it('stores only changed fields and ignores unknown values', () => {
    const current = user()
    const draft = editDraftFromUser(current)
    draft.email = 'ada.lovelace@example.test'
    draft.profile.givenName = 'Augusta'

    const snapshot = editDraftSnapshot(current, draft)

    expect(snapshot).toEqual({
      email: 'ada.lovelace@example.test',
      profile: { givenName: 'Augusta' },
    })
    expect(editDraftSnapshotHasContent(snapshot)).toBe(true)
    expect(
      editDraftSnapshotHasContent(
        {
          unexpected: 'value',
        } as unknown as Parameters<typeof editDraftSnapshotHasContent>[0],
      ),
    ).toBe(false)
  })

  it('never serializes optimistic-lock or mutation identifiers', () => {
    const current = user()
    const draft = editDraftFromUser(current)
    draft.username = 'ada.lovelace'

    const snapshot = editDraftSnapshot(current, draft)

    expect(Object.keys(snapshot)).not.toContain('expectedVersion')
    expect(Object.keys(snapshot)).not.toContain('clientMutationId')
    expect(JSON.stringify(snapshot)).not.toContain(current.version)
  })

  it('restores over a fresh user and ignores stale CAS values', () => {
    const current = user({
      version: '11111111-1111-4111-8111-111111111111',
    })
    const restored = restoreEditDraft(current, {
      username: 'ada.lovelace',
      expectedVersion: 'old-stale-version',
      clientMutationId: 'old-client-mutation',
    })

    expect(restored?.username).toBe('ada.lovelace')

    const input = updateInputFromDraft(current, restored!)
    expect(input?.expectedVersion).toBe(current.version)
    expect(input?.expectedVersion).not.toBe('old-stale-version')
    expect(input).not.toHaveProperty('clientMutationId')
  })

  it('preserves hidden server fields changed after the draft was saved', () => {
    const current = user({
      middleName: 'Server Middle',
      profile: 'https://server.example.test/profile',
      locale: 'en-GB',
    })
    const restored = restoreEditDraft(current, {
      profile: { nickname: 'countess' },
    })

    expect(restored?.profile.middleName).toBe('Server Middle')
    expect(restored?.profile.profile).toBe(
      'https://server.example.test/profile',
    )
    expect(restored?.profile.locale).toBe('en-GB')

    const input = updateInputFromDraft(current, restored!)
    expect(input?.profile).toEqual({ nickname: 'countess' })
  })

  it('validates untrusted stored JSON field by field', () => {
    const current = user()
    const restored = restoreEditDraft(current, {
      username: 42,
      email: 'ada.lovelace@example.test',
      profile: { givenName: 'Ada', nickname: { value: 'bad' } },
    })

    expect(restored?.username).toBe(current.username)
    expect(restored?.email).toBe('ada.lovelace@example.test')
    expect(restored?.profile.givenName).toBe('Ada')
    expect(restored?.profile.nickname).toBe('ada')
    expect(restoreEditDraft(current, 'not-an-object')).toBeNull()
  })
})

describe('safe create draft snapshots', () => {
  it('always omits the password from the saved snapshot', () => {
    const draft = createDraftFromEmpty()
    draft.username = 'ada'
    draft.email = 'ada@example.test'
    draft.password = 'super-secret-password'
    draft.profile.givenName = 'Ada'

    const snapshot = createDraftSnapshot(draft)

    expect(snapshot).not.toHaveProperty('password')
    expect(JSON.stringify(snapshot)).not.toContain('super-secret-password')
    expect(createDraftSnapshotHasContent(snapshot)).toBe(true)
  })

  it('restores a blank password even when stored JSON contains one', () => {
    const restored = restoreCreateDraft({
      username: 'ada',
      email: 'ada@example.test',
      password: 'untrusted-password',
      profile: { givenName: 'Ada' },
    })

    expect(restored).not.toBeNull()
    expect(restored?.password).toBe('')
    expect(restored?.username).toBe('ada')
    expect(restored?.profile.givenName).toBe('Ada')
  })

  it('ignores invalid stored values and does not treat a bare password as a draft', () => {
    expect(
      restoreCreateDraft({
        username: 42,
        profile: { givenName: 7 },
        password: 'untrusted-password',
      }),
    ).toBeNull()
    expect(restoreCreateDraft('not-an-object')).toBeNull()
    expect(restoreCreateDraft({ password: 'untrusted-password' })).toBeNull()
  })
})
