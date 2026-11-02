import { Card, Chip } from '@heroui/react'
import type { ReactNode } from 'react'

import { formatDate, formatDateTime } from '#/lib/format'
import { useLocale, useTranslator } from '#/lib/i18n'
import { useUserDetailContext } from '../components/user-detail-context'
import { UserDetailSkeleton } from '../components/user-detail-skeleton'
import { USER_PROFILE_LABEL_KEYS } from '../lib/user-field-meta'
import type { UserProfileField } from '../lib/user-form'

const PROFILE_FIELDS: ReadonlyArray<UserProfileField> = [
  'givenName',
  'familyName',
  'middleName',
  'nickname',
  'birthdate',
  'website',
  'profile',
  'picture',
]

function DetailField({
  label,
  children,
}: {
  label: string
  children: ReactNode
}) {
  return (
    <div className="min-w-0">
      <dt className="text-sm text-muted">{label}</dt>
      <dd className="mt-2 min-h-6 break-words text-sm font-medium">
        {children}
      </dd>
    </div>
  )
}

export function UserDetailPage() {
  const t = useTranslator()
  const { locale, timeZone } = useLocale()
  const { user } = useUserDetailContext()
  if (!user) return <UserDetailSkeleton />
  const profileFields = PROFILE_FIELDS.filter(
    (field) => (user[field] ?? '').trim() !== '',
  )

  return (
    <div className="space-y-5">
      <Card
        className="console-card border border-border p-0"
        role="region"
        aria-labelledby="user-account-heading"
      >
        <Card.Content className="block p-5 sm:p-6">
          <div className="mb-6 flex h-6 items-center justify-between gap-3">
            <h2 id="user-account-heading" className="text-base font-semibold">
              {t('usersAccountTitle')}
            </h2>
          </div>
          <dl className="grid gap-x-8 gap-y-7 sm:grid-cols-2 xl:grid-cols-3">
            <DetailField label={t('usersFieldUsername')}>
              {user.username}
            </DetailField>
            <DetailField label={t('usersFieldEmail')}>
              <span className="flex flex-wrap items-center gap-2">
                <span className="break-all">{user.email}</span>
                <Chip
                  size="sm"
                  variant="soft"
                  color={user.emailVerified ? 'success' : 'default'}
                >
                  <Chip.Label>
                    {t(
                      user.emailVerified
                        ? 'usersEmailVerified'
                        : 'usersEmailUnverified',
                    )}
                  </Chip.Label>
                </Chip>
              </span>
            </DetailField>
            <DetailField label={t('usersCreatedAtLabel')}>
              {formatDateTime(user.createdAt, locale, timeZone)}
            </DetailField>
            <DetailField label={t('usersUpdatedAtLabel')}>
              {formatDateTime(user.updatedAt, locale, timeZone)}
            </DetailField>
            {user.locked && user.lockedUntil ? (
              <DetailField label={t('usersLockedUntilLabel')}>
                {formatDateTime(user.lockedUntil, locale, timeZone)}
              </DetailField>
            ) : null}
          </dl>
        </Card.Content>
      </Card>
      <Card
        className="console-card border border-border p-0"
        role="region"
        aria-labelledby="user-profile-heading"
      >
        <Card.Content className="block p-5 sm:p-6">
          <div className="mb-6 flex h-6 items-center justify-between gap-3">
            <h2 id="user-profile-heading" className="text-base font-semibold">
              {t('usersProfileTitle')}
            </h2>
          </div>
          {profileFields.length ? (
            <dl className="grid gap-x-8 gap-y-7 sm:grid-cols-2 xl:grid-cols-3">
              {profileFields.map((field) => (
                <DetailField
                  key={field}
                  label={t(USER_PROFILE_LABEL_KEYS[field])}
                >
                  {field === 'birthdate'
                    ? formatDate(user[field], locale)
                    : user[field]}
                </DetailField>
              ))}
            </dl>
          ) : (
            <p className="py-4 text-sm text-muted">{t('usersProfileEmpty')}</p>
          )}
        </Card.Content>
      </Card>
    </div>
  )
}
