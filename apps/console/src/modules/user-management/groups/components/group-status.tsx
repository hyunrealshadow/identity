import { Badge } from '@identity/ui/components/badge'

import { useTranslator } from '#/lib/i18n'

function badgeSizeClass(size: 'sm' | 'md'): string | undefined {
  return size === 'md' ? 'h-6 px-2.5' : undefined
}

export function GroupStatusChip({
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
      {t(enabled ? 'groupsEnabled' : 'groupsDisabled')}
    </Badge>
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
    <Badge
      variant="secondary"
      className={[badgeSizeClass(size), builtIn ? 'text-primary' : undefined]
        .filter(Boolean)
        .join(' ')}
    >
      {t(builtIn ? 'groupsBuiltIn' : 'groupsCustom')}
    </Badge>
  )
}
