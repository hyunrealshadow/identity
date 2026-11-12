import { Badge } from '@identity/ui/components/badge'

import type { KeyStatus, KeyUse } from '#/generated/graphql'
import { useTranslator, type MessageKey } from '#/lib/i18n'

const STATUS: Record<KeyStatus, { label: MessageKey; className?: string }> = {
  ACTIVE: { label: 'keysStatusActive', className: 'text-success' },
  RETIRED: { label: 'keysStatusRetired', className: 'text-primary' },
  EXPIRED: { label: 'keysStatusExpired', className: 'text-warning' },
  REVOKED: { label: 'keysStatusRevoked', className: 'text-destructive' },
}

/**
 * The key's lifecycle state. The active signing key in use signs for clients
 * that ask for no particular algorithm, so it reads "default"; the encryption
 * key in use reads "currently used".
 */
export function KeyStatusChip({
  use,
  status,
  inUse,
}: {
  use: KeyUse
  status: KeyStatus
  inUse: boolean
}) {
  const t = useTranslator()
  const entry = STATUS[status]
  const label =
    status === 'ACTIVE' && inUse
      ? use === 'SIGNING'
        ? 'keysStatusDefault'
        : 'keysStatusInUse'
      : entry.label
  return (
    <Badge variant="secondary" className={entry.className}>
      {t(label)}
    </Badge>
  )
}
