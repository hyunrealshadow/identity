import { Badge } from '@identity/ui/components/badge'

import { useTranslator, type MessageKey } from '#/lib/i18n'

function badgeSizeClass(size: 'sm' | 'md'): string | undefined {
  return size === 'md' ? 'h-6 px-2.5' : undefined
}

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
    <Badge variant="secondary" className={badgeSizeClass(size)}>
      {t(labelKey)}
    </Badge>
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
    <Badge
      variant="secondary"
      className={[badgeSizeClass(size), enabled ? 'text-success' : undefined]
        .filter(Boolean)
        .join(' ')}
    >
      {t(enabled ? 'rolesEnabled' : 'rolesDisabled')}
    </Badge>
  )
}

export function AssignmentStatusChip({
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
      <Badge variant="secondary">
        {t('assignmentRevoked')}
      </Badge>
    )
  }
  if (roleEnabled === false) {
    return (
      <Badge variant="secondary" className="text-warning">
        {t('assignmentActiveRoleDisabled')}
      </Badge>
    )
  }
  return (
    <Badge variant="secondary" className="text-success">
      {t('assignmentActive')}
    </Badge>
  )
}
