import { Chip } from '@heroui/react'

import { useTranslator } from '#/lib/i18n'

export function ClientStatusChip({ enabled }: { enabled: boolean }) {
  const t = useTranslator()
  return (
    <Chip size="sm" variant="soft" color={enabled ? 'success' : 'default'}>
      <Chip.Label>{t(enabled ? 'clientsEnabled' : 'clientsDisabled')}</Chip.Label>
    </Chip>
  )
}

export function ClientBuiltInChip() {
  const t = useTranslator()
  return (
    <Chip size="sm" variant="soft" color="accent">
      <Chip.Label>{t('clientsBuiltIn')}</Chip.Label>
    </Chip>
  )
}
