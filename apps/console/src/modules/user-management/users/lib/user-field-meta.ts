import type { MessageKey } from '#/lib/i18n'
import type { UserProfileField } from '#/modules/user-management/users/lib/user-form'

export const USER_PROFILE_LABEL_KEYS: Record<UserProfileField, MessageKey> = {
  givenName: 'usersFieldGivenName',
  familyName: 'usersFieldFamilyName',
  middleName: 'usersFieldMiddleName',
  nickname: 'usersFieldNickname',
  profile: 'usersFieldProfile',
  picture: 'usersFieldPicture',
  website: 'usersFieldWebsite',
  birthdate: 'usersFieldBirthdate',
  locale: 'usersFieldLocale',
  theme: 'usersFieldTheme',
}

export const USER_PROFILE_DATE_FIELDS: ReadonlyArray<UserProfileField> = [
  'birthdate',
]

export const USER_PROFILE_MULTILINE_FIELDS: ReadonlyArray<UserProfileField> = []
