import { Badge } from '@identity/ui/components/badge'

import { useTranslator } from '#/lib/i18n'

export function ClientStatusChip({ enabled }: { enabled: boolean }) {
  const t = useTranslator()
  return (
    <Badge
      variant="secondary"
      className={enabled ? 'text-success' : undefined}
    >
      {t(enabled ? 'clientsEnabled' : 'clientsDisabled')}
    </Badge>
  )
}

export function ClientBuiltInChip() {
  const t = useTranslator()
  return (
    <Badge variant="secondary" className="text-primary">
      {t('clientsBuiltIn')}
    </Badge>
  )
}
