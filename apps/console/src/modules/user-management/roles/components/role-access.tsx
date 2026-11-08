import { Button } from '@identity/ui/components/button'
import { Card, CardContent } from '@identity/ui/components/card'
import { Lock } from 'lucide-react'

import { useTranslator, type MessageKey } from '#/lib/i18n'
import type { RbacScope } from '#/modules/user-management/lib/rbac-scope'

export function RbacAccessRestricted({
  title,
  description,
  onBack,
  backLabel,
}: {
  title: MessageKey
  description: MessageKey
  onBack?: () => void
  backLabel?: MessageKey
}) {
  const t = useTranslator()
  return (
    <div className="space-y-4">
      <Card className="console-card border border-border">
        <CardContent className="block p-6 sm:p-8">
          <span className="flex size-10 items-center justify-center rounded-lg bg-muted text-muted-foreground">
            <Lock className="size-5" aria-hidden="true" />
          </span>
          <h2 className="mt-4 text-lg font-semibold tracking-tight">
            {t(title)}
          </h2>
          <p className="mt-2 max-w-2xl text-sm leading-6 text-muted-foreground">
            {t(description)}
          </p>
          {onBack ? (
            <Button variant="secondary" className="mt-5" onClick={onBack}>
              {t(backLabel ?? 'backToUsers')}
            </Button>
          ) : null}
        </CardContent>
      </Card>
    </div>
  )
}

export function roleReadAllowed(scope: RbacScope): boolean {
  return scope.rolesRead
}
