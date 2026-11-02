import { Chip } from '@heroui/react'

import { useTranslator } from '#/lib/i18n'

export interface UserStatusSource {
  enabled: boolean | null
  locked: boolean | null
}

export function UserStatusBadges({
  user,
  size = 'sm',
}: {
  user: UserStatusSource
  size?: 'sm' | 'md' | 'lg'
}) {
  const t = useTranslator()

  return (
    <div className="flex flex-wrap items-center gap-1.5">
      {user.enabled === null || user.enabled === undefined ? null : (
        <Chip
          size={size}
          variant="soft"
          color={user.enabled ? 'success' : 'default'}
        >
          <Chip.Label className="whitespace-nowrap">
            {t(user.enabled ? 'usersEnabled' : 'usersDisabled')}
          </Chip.Label>
        </Chip>
      )}
      {user.locked ? (
        <Chip size={size} variant="soft" color="danger">
          <Chip.Label className="whitespace-nowrap">{t('usersLocked')}</Chip.Label>
        </Chip>
      ) : null}
    </div>
  )
}
