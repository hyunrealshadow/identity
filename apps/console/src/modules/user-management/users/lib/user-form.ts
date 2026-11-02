import type {
  ConsoleUserQuery,
  CreateUserInput,
  UpdateUserInput,
  UserProfilePatchInput,
} from '#/gql/graphql'

export type ProjectedUser = NonNullable<ConsoleUserQuery['user']>

export const USER_PROFILE_FIELDS = [
  'givenName',
  'familyName',
  'middleName',
  'nickname',
  'profile',
  'picture',
  'website',
  'birthdate',
  'locale',
  'theme',
] as const

export type UserProfileField = (typeof USER_PROFILE_FIELDS)[number]

export type UserProfileDraft = Record<UserProfileField, string>

export interface UserEditDraft {
  username: string
  email: string
  profile: UserProfileDraft
}

export interface CreateUserDraft {
  username: string
  email: string
  password: string
  profile: UserProfileDraft
}

/**
 * Storage-ready edit values. Only fields that differ from the user at the
 * time the draft was saved are present; optimistic-lock and mutation
 * identifiers are deliberately absent.
 */
export interface UserEditDraftSnapshot {
  username?: string
  email?: string
  profile?: Partial<Record<UserProfileField, string>>
}

/**
 * Storage-ready create values. The password is intentionally absent so a
 * restored draft can never prefill or persist an initial credential.
 */
export interface CreateUserDraftSnapshot {
  username: string
  email: string
  profile: UserProfileDraft
}

const MAX_STORED_TEXT = 1000

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function storedText(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined
  return value.length > MAX_STORED_TEXT
    ? value.slice(0, MAX_STORED_TEXT)
    : value
}

function profileSnapshot(draft: UserProfileDraft): UserProfileDraft {
  const profile = emptyProfileDraft()
  for (const field of USER_PROFILE_FIELDS) profile[field] = draft[field]
  return profile
}

export function emptyProfileDraft(): UserProfileDraft {
  return {
    givenName: '',
    familyName: '',
    middleName: '',
    nickname: '',
    profile: '',
    picture: '',
    website: '',
    birthdate: '',
    locale: '',
    theme: '',
  }
}

export function profileDraftFromUser(user: ProjectedUser): UserProfileDraft {
  return {
    givenName: user.givenName ?? '',
    familyName: user.familyName ?? '',
    middleName: user.middleName ?? '',
    nickname: user.nickname ?? '',
    profile: user.profile ?? '',
    picture: user.picture ?? '',
    website: user.website ?? '',
    birthdate: user.birthdate ?? '',
    locale: user.locale ?? '',
    theme: user.theme ?? '',
  }
}

export function editDraftFromUser(user: ProjectedUser): UserEditDraft {
  return {
    username: user.username,
    email: user.email,
    profile: profileDraftFromUser(user),
  }
}

export function createDraftFromEmpty(): CreateUserDraft {
  return {
    username: '',
    email: '',
    password: '',
    profile: emptyProfileDraft(),
  }
}

export function editDraftSnapshot(
  user: ProjectedUser,
  draft: UserEditDraft,
): UserEditDraftSnapshot {
  const snapshot: UserEditDraftSnapshot = {}

  if (draft.username.trim() !== user.username) snapshot.username = draft.username
  if (draft.email.trim() !== user.email) snapshot.email = draft.email

  const profile: Partial<Record<UserProfileField, string>> = {}
  for (const field of USER_PROFILE_FIELDS) {
    if (draft.profile[field] !== (user[field] ?? '')) {
      profile[field] = draft.profile[field]
    }
  }
  if (Object.keys(profile).length > 0) snapshot.profile = profile

  return snapshot
}

export function editDraftSnapshotHasContent(
  snapshot: UserEditDraftSnapshot,
): boolean {
  return (
    snapshot.username !== undefined ||
    snapshot.email !== undefined ||
    Object.keys(snapshot.profile ?? {}).length > 0
  )
}

/**
 * Merge only the saved, actually-edited fields over a freshly loaded user.
 * Hidden fields changed elsewhere and the current record version always come
 * from that fresh read.
 */
export function restoreEditDraft(
  user: ProjectedUser,
  value: unknown,
): UserEditDraft | null {
  if (!isRecord(value)) return null

  const draft = editDraftFromUser(user)

  const username = storedText(value.username)
  if (username !== undefined) draft.username = username

  const email = storedText(value.email)
  if (email !== undefined) draft.email = email

  if (isRecord(value.profile)) {
    for (const field of USER_PROFILE_FIELDS) {
      const next = storedText(value.profile[field])
      if (next !== undefined) draft.profile[field] = next
    }
  }

  return draft
}

export function createDraftSnapshot(
  draft: CreateUserDraft,
): CreateUserDraftSnapshot {
  return {
    username: draft.username,
    email: draft.email,
    profile: profileSnapshot(draft.profile),
  }
}

export function createDraftSnapshotHasContent(
  snapshot: CreateUserDraftSnapshot,
): boolean {
  return (
    snapshot.username.trim() !== '' ||
    snapshot.email.trim() !== '' ||
    USER_PROFILE_FIELDS.some((field) => snapshot.profile[field].trim() !== '')
  )
}

export function restoreCreateDraft(value: unknown): CreateUserDraft | null {
  if (!isRecord(value)) return null

  const draft = createDraftFromEmpty()
  let recognized = false

  const username = storedText(value.username)
  if (username !== undefined) {
    draft.username = username
    recognized = true
  }

  const email = storedText(value.email)
  if (email !== undefined) {
    draft.email = email
    recognized = true
  }

  if (isRecord(value.profile)) {
    for (const field of USER_PROFILE_FIELDS) {
      const next = storedText(value.profile[field])
      if (next !== undefined) {
        draft.profile[field] = next
        recognized = true
      }
    }
  }

  // Never restore a password, even when untrusted stored JSON contains one.
  draft.password = ''
  return recognized ? draft : null
}

export function profileChanged(
  user: ProjectedUser,
  draft: UserProfileDraft,
): boolean {
  return USER_PROFILE_FIELDS.some(
    (field) => draft[field] !== (user[field] ?? ''),
  )
}

export function updateDraftChanged(
  user: ProjectedUser,
  draft: UserEditDraft,
): boolean {
  return (
    draft.username.trim() !== user.username ||
    draft.email.trim() !== user.email ||
    profileChanged(user, draft.profile)
  )
}

export function emailChangeResetsVerification(
  user: ProjectedUser,
  draft: UserEditDraft,
): boolean {
  return draft.email.trim() !== user.email
}

/**
 * Sparse profile patch: omitted values preserve the stored field, while a
 * cleared nullable field is sent explicitly as null.
 */
export function profilePatchFromDraft(
  user: ProjectedUser,
  draft: UserProfileDraft,
): UserProfilePatchInput | undefined {
  const patch: Record<string, string | null> = {}
  for (const field of USER_PROFILE_FIELDS) {
    const next = draft[field]
    const current = user[field] ?? ''
    if (next === current) continue
    patch[field] = next.trim() === '' ? null : next
  }
  return Object.keys(patch).length > 0
    ? (patch as UserProfilePatchInput)
    : undefined
}

export function createInputFromDraft(
  draft: CreateUserDraft,
): CreateUserInput {
  const profile: Record<string, string> = {}
  for (const field of USER_PROFILE_FIELDS) {
    const value = draft.profile[field]
    if (value.trim() !== '') profile[field] = value
  }

  return {
    username: draft.username.trim(),
    email: draft.email.trim(),
    password: draft.password,
    ...(Object.keys(profile).length > 0
      ? { profile: profile as UserProfilePatchInput }
      : {}),
  }
}

/**
 * Only changed identifier/profile fields are included. Username and email are
 * never sent as null; an empty identifier is a local validation error.
 */
export function updateInputFromDraft(
  user: ProjectedUser,
  draft: UserEditDraft,
): UpdateUserInput | null {
  if (!user.version) return null

  const input: UpdateUserInput = {
    id: user.id,
    expectedVersion: user.version,
  }

  const username = draft.username.trim()
  if (username !== user.username) input.username = username

  const email = draft.email.trim()
  if (email !== user.email) input.email = email

  const profile = profilePatchFromDraft(user, draft.profile)
  if (profile) input.profile = profile

  return input
}
