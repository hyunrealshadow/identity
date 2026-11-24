import { Link } from '@tanstack/react-router'
import { ChevronRight } from 'lucide-react'

import { SettingsGroup, SettingsGroupSkeleton } from '#/components/settings-section'
import { useTranslator } from '#/lib/i18n'
import {
  useInstanceSettings,
  useSettingsBlocker,
} from '../../settings/components/instance-settings-context'
import { EmailTemplateStatusChip } from '../components/email-template-status'
import { emailTemplateLabels, emailTemplateSlug } from '../lib/email-form'

export function EmailTemplatesPage() {
  const t = useTranslator()
  const { settings } = useInstanceSettings()
  const blocked = useSettingsBlocker()
  if (blocked) return blocked
  if (!settings) {
    return (
      <div aria-busy="true">
        <SettingsGroupSkeleton rows={['control']} description />
      </div>
    )
  }
  return (
    <SettingsGroup description={t('settingsEmailTemplatesSectionHint')}>
      {settings.email.templates.map((template) => {
        const labels = emailTemplateLabels[template.kind]
        return (
          // The whole row opens the editor, so it is one link rather than a
          // linked title beside an inert chevron.
          <Link
            key={template.kind}
            to="/email/templates/$kind"
            params={{ kind: emailTemplateSlug(template.kind) }}
            className="group flex items-center gap-3 px-5 py-4 transition-colors hover:bg-muted/50 focus-visible:bg-muted/50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-inset"
          >
            <div className="min-w-0 flex-1">
              <div className="text-sm font-medium">{t(labels.title)}</div>
              <div className="mt-0.5 text-xs leading-5 text-muted-foreground">
                {t(labels.description)}
              </div>
            </div>
            <span className="hidden text-xs text-muted-foreground sm:inline">
              {t('emailTemplateTranslationCount', {
                count: template.content.translations.length,
              })}
            </span>
            <EmailTemplateStatusChip customized={template.customized} />
            <ChevronRight
              className="size-4 shrink-0 text-muted-foreground transition-transform group-hover:translate-x-0.5"
              aria-hidden="true"
            />
          </Link>
        )
      })}
    </SettingsGroup>
  )
}
