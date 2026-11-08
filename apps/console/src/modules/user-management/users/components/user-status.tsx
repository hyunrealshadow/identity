import { Badge } from '@identity/ui/components/badge'

import { useTranslator } from '#/lib/i18n'

export interface UserStatusSource {
  enabled: boolean | null
  locked: boolean | null
}

function badgeSizeClass(size: 'sm' | 'md' | 'lg'): string | undefined {
  if (size === 'lg') return 'h-7 px-3 text-sm'
  if (size === 'md') return 'h-6 px-2.5'
  return undefined
}

function badgeClassName(
  size: 'sm' | 'md' | 'lg',
  tone?: 'success',
): string {
  return [
    'whitespace-nowrap',
    badgeSizeClass(size),
    tone === 'success' ? 'text-success' : undefined,
  ]
    .filter(Boolean)
    .join(' ')
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
        <Badge
          variant="secondary"
          className={badgeClassName(size, user.enabled ? 'success' : undefined)}
        >
          {t(user.enabled ? 'usersEnabled' : 'usersDisabled')}
        </Badge>
      )}
      {user.locked ? (
        <Badge variant="destructive" className={badgeClassName(size)}>
          {t('usersLocked')}
        </Badge>
      ) : null}
    </div>
  )
}
