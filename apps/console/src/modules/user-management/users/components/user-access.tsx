import { Button, Card } from '@heroui/react'
import { Lock, Plus } from 'lucide-react'

import type { UserManagementScope } from '#/modules/user-management/users/lib/user-scope'
import { useTranslator } from '#/lib/i18n'

export function UserReadRestricted({
  scope,
  onCreate,
  onGoHome,
}: {
  scope: UserManagementScope
  onCreate?: () => void
  onGoHome?: () => void
}) {
  const t = useTranslator()
  const writeOnly = scope.canWrite

  return (
    <div className="space-y-4">
      <Card className="console-card border border-border">
        <Card.Content className="p-6 sm:p-8">
          <span className="flex size-10 items-center justify-center rounded-lg bg-surface-secondary text-muted">
            <Lock className="size-5" aria-hidden="true" />
          </span>
          <h2 className="mt-4 text-lg font-semibold tracking-tight">
            {t(writeOnly ? 'usersNoReadTitle' : 'usersNoManagementTitle')}
          </h2>
          <p className="mt-2 max-w-2xl text-sm leading-6 text-muted">
            {t(
              writeOnly
                ? 'usersNoReadWriteOnlyDescription'
                : 'usersNoManagementDescription',
            )}
          </p>
          <div className="mt-5 flex flex-wrap gap-2">
            {scope.create && onCreate ? (
              <Button onPress={onCreate}>
                <Plus className="size-4" aria-hidden="true" />
                {t('usersNewAction')}
              </Button>
            ) : null}
            {onGoHome ? (
              <Button variant="secondary" onPress={onGoHome}>
                {t('goHome')}
              </Button>
            ) : null}
          </div>
        </Card.Content>
      </Card>
    </div>
  )
}

export function UserEditRestricted({
  onBack,
}: {
  scope: UserManagementScope
  onBack?: () => void
}) {
  const t = useTranslator()

  return (
    <div className="space-y-4">
      <Card className="console-card border border-border">
        <Card.Content className="p-6 sm:p-8">
          <span className="flex size-10 items-center justify-center rounded-lg bg-surface-secondary text-muted">
            <Lock className="size-5" aria-hidden="true" />
          </span>
          <h2 className="mt-4 text-lg font-semibold tracking-tight">
            {t('usersEditNoPermissionTitle')}
          </h2>
          <p className="mt-2 max-w-2xl text-sm leading-6 text-muted">
            {t('usersEditNoPermissionDescription')}
          </p>
          {onBack ? (
            <Button variant="secondary" className="mt-5" onPress={onBack}>
              {t('usersBackToDetail')}
            </Button>
          ) : null}
        </Card.Content>
      </Card>
    </div>
  )
}

export function UserCreateRestricted({
  onGoHome,
}: {
  scope: UserManagementScope
  onGoHome?: () => void
}) {
  const t = useTranslator()

  return (
    <div className="space-y-4">
      <Card className="console-card border border-border">
        <Card.Content className="p-6 sm:p-8">
          <span className="flex size-10 items-center justify-center rounded-lg bg-surface-secondary text-muted">
            <Lock className="size-5" aria-hidden="true" />
          </span>
          <h2 className="mt-4 text-lg font-semibold tracking-tight">
            {t('usersCreateNoPermissionTitle')}
          </h2>
          <p className="mt-2 max-w-2xl text-sm leading-6 text-muted">
            {t('usersCreateNoPermissionDescription')}
          </p>
          {onGoHome ? (
            <Button variant="secondary" className="mt-5" onPress={onGoHome}>
              {t('goHome')}
            </Button>
          ) : null}
        </Card.Content>
      </Card>
    </div>
  )
}
