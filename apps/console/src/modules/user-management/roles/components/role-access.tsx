import { Button, Card } from '@heroui/react'
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
        <Card.Content className="p-6 sm:p-8">
          <span className="flex size-10 items-center justify-center rounded-lg bg-surface-secondary text-muted">
            <Lock className="size-5" aria-hidden="true" />
          </span>
          <h2 className="mt-4 text-lg font-semibold tracking-tight">
            {t(title)}
          </h2>
          <p className="mt-2 max-w-2xl text-sm leading-6 text-muted">
            {t(description)}
          </p>
          {onBack ? (
            <Button variant="secondary" className="mt-5" onPress={onBack}>
              {t(backLabel ?? 'backToUsers')}
            </Button>
          ) : null}
        </Card.Content>
      </Card>
    </div>
  )
}

export function roleReadAllowed(scope: RbacScope): boolean {
  return scope.rolesRead
}
