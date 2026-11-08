import { Button } from '@identity/ui/components/button'
import { Card, CardContent } from '@identity/ui/components/card'
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
        <CardContent className="p-6 sm:p-8">
          <span className="flex size-10 items-center justify-center rounded-lg bg-muted text-muted-foreground">
            <Lock className="size-5" aria-hidden="true" />
          </span>
          <h2 className="mt-4 text-lg font-semibold tracking-tight">
            {t(writeOnly ? 'usersNoReadTitle' : 'usersNoManagementTitle')}
          </h2>
          <p className="mt-2 max-w-2xl text-sm leading-6 text-muted-foreground">
            {t(
              writeOnly
                ? 'usersNoReadWriteOnlyDescription'
                : 'usersNoManagementDescription',
            )}
          </p>
          <div className="mt-5 flex flex-wrap gap-2">
            {scope.create && onCreate ? (
              <Button onClick={onCreate}>
                <Plus className="size-4" aria-hidden="true" />
                {t('usersNewAction')}
              </Button>
            ) : null}
            {onGoHome ? (
              <Button variant="secondary" onClick={onGoHome}>
                {t('goHome')}
              </Button>
            ) : null}
          </div>
        </CardContent>
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
        <CardContent className="p-6 sm:p-8">
          <span className="flex size-10 items-center justify-center rounded-lg bg-muted text-muted-foreground">
            <Lock className="size-5" aria-hidden="true" />
          </span>
          <h2 className="mt-4 text-lg font-semibold tracking-tight">
            {t('usersEditNoPermissionTitle')}
          </h2>
          <p className="mt-2 max-w-2xl text-sm leading-6 text-muted-foreground">
            {t('usersEditNoPermissionDescription')}
          </p>
          {onBack ? (
            <Button variant="secondary" className="mt-5" onClick={onBack}>
              {t('usersBackToDetail')}
            </Button>
          ) : null}
        </CardContent>
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
        <CardContent className="p-6 sm:p-8">
          <span className="flex size-10 items-center justify-center rounded-lg bg-muted text-muted-foreground">
            <Lock className="size-5" aria-hidden="true" />
          </span>
          <h2 className="mt-4 text-lg font-semibold tracking-tight">
            {t('usersCreateNoPermissionTitle')}
          </h2>
          <p className="mt-2 max-w-2xl text-sm leading-6 text-muted-foreground">
            {t('usersCreateNoPermissionDescription')}
          </p>
          {onGoHome ? (
            <Button variant="secondary" className="mt-5" onClick={onGoHome}>
              {t('goHome')}
            </Button>
          ) : null}
        </CardContent>
      </Card>
    </div>
  )
}
