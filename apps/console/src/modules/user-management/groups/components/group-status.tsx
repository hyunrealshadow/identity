import { Chip } from '@heroui/react'

import { useTranslator } from '#/lib/i18n'

export function GroupStatusChip({
  enabled,
  size = 'sm',
}: {
  enabled: boolean
  size?: 'sm' | 'md'
}) {
  const t = useTranslator()
  return (
    <Chip size={size} variant="soft" color={enabled ? 'success' : 'default'}>
      <Chip.Label>{t(enabled ? 'groupsEnabled' : 'groupsDisabled')}</Chip.Label>
    </Chip>
  )
}

export function GroupKindChip({
  builtIn,
  size = 'sm',
}: {
  builtIn: boolean
  size?: 'sm' | 'md'
}) {
  const t = useTranslator()
  return (
    <Chip
      size={size}
      variant="soft"
      color={builtIn ? 'accent' : 'default'}
    >
      <Chip.Label>{t(builtIn ? 'groupsBuiltIn' : 'groupsCustom')}</Chip.Label>
    </Chip>
  )
}
