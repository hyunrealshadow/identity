import { Chip } from '@heroui/react'

import { useTranslator, type MessageKey } from '#/lib/i18n'

function BuiltInChip({
  builtIn,
  labelKey,
  size = 'sm',
}: {
  builtIn: boolean
  labelKey: MessageKey
  size?: 'sm' | 'md'
}) {
  const t = useTranslator()
  if (!builtIn) return null
  return (
    <Chip size={size} variant="soft" color="default">
      <Chip.Label>{t(labelKey)}</Chip.Label>
    </Chip>
  )
}

export function RoleBuiltInChip({
  builtIn,
  size = 'sm',
}: {
  builtIn: boolean
  size?: 'sm' | 'md'
}) {
  return (
    <BuiltInChip
      builtIn={builtIn}
      labelKey="rolesBuiltInBadge"
      size={size}
    />
  )
}

export function PermissionBuiltInChip({
  builtIn,
  size = 'sm',
}: {
  builtIn: boolean
  size?: 'sm' | 'md'
}) {
  return (
    <BuiltInChip
      builtIn={builtIn}
      labelKey="permissionBuiltInBadge"
      size={size}
    />
  )
}

export function RoleStatusChip({
  enabled,
  size = 'sm',
}: {
  enabled: boolean
  size?: 'sm' | 'md'
}) {
  const t = useTranslator()
  return (
    <Chip
      size={size}
      variant="soft"
      color={enabled ? 'success' : 'default'}
    >
      <Chip.Label>{t(enabled ? 'rolesEnabled' : 'rolesDisabled')}</Chip.Label>
    </Chip>
  )
}

export function BindingStatusChip({
  enabled,
  revokedAt,
  roleEnabled,
}: {
  enabled: boolean
  revokedAt?: string | null
  roleEnabled?: boolean
}) {
  const t = useTranslator()
  if (!enabled || revokedAt) {
    return (
      <Chip size="sm" variant="soft" color="default">
        <Chip.Label>{t('bindingRevoked')}</Chip.Label>
      </Chip>
    )
  }
  if (roleEnabled === false) {
    return (
      <Chip size="sm" variant="soft" color="warning">
        <Chip.Label>{t('bindingActiveRoleDisabled')}</Chip.Label>
      </Chip>
    )
  }
  return (
    <Chip size="sm" variant="soft" color="success">
      <Chip.Label>{t('bindingActive')}</Chip.Label>
    </Chip>
  )
}
