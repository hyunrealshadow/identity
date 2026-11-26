import { Badge } from '@identity/ui/components/badge'

import { useTranslator } from '#/lib/i18n'

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
