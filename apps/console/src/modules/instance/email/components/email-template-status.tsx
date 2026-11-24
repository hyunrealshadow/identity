import { Badge } from '@identity/ui/components/badge'

import { useTranslator } from '#/lib/i18n'

/** Shows whether an email template uses customized content or the built-in copy. */
export function EmailTemplateStatusChip({ customized }: { customized: boolean }) {
  const t = useTranslator()
  return (
    <Badge variant={customized ? 'secondary' : 'outline'}>
      {t(customized ? 'settingsEmailTemplateCustomized' : 'settingsEmailTemplateBuiltIn')}
    </Badge>
  )
}
