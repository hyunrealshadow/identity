import { Button } from '@identity/ui/components/button'
import { Pencil } from 'lucide-react'
import type { ReactNode } from 'react'

import { SettingsGroup, SettingsRow } from '#/components/settings-section'
import { useLocale, useTranslator, type MessageKey } from '#/lib/i18n'
import type { LocalizedDraft } from '#/lib/localized-values'
import {
  SELECTABLE_GRANT_TYPES,
  uriLines,
  type ClientKind,
  type ClientSettingsDraft,
} from '../../lib/client-form'
import type { CreateStep } from '../../lib/create-steps'
import { GRANT_LABELS } from '../client-settings-fields'
import { CLIENT_KINDS } from './create-kind-step'
import { visibleRedirectRows } from './create-redirects-step'

export const CREATE_STEP_LABELS: Record<CreateStep, MessageKey> = {
  kind: 'clientsCreateStepKind',
  details: 'clientsCreateStepDetails',
  redirects: 'clientsCreateStepRedirects',
  access: 'clientsCreateStepAccess',
  review: 'clientsCreateStepReview',
}

const REDIRECT_LABELS = {
  webRedirectUris: 'clientsWebRedirectUris',
  nativeRedirectUris: 'clientsNativeRedirectUris',
  postLogoutRedirectUris: 'clientsPostLogoutRedirectUris',
} as const satisfies Record<string, MessageKey>

function Muted({ children }: { children: ReactNode }) {
  return <span className="text-sm text-muted-foreground">{children}</span>
}

export function CreateReviewStep({
  kind,
  text,
  settings,
  steps,
  onEdit,
  isDisabled,
}: {
  kind: ClientKind
  text: LocalizedDraft
  settings: ClientSettingsDraft
  steps: readonly CreateStep[]
  onEdit: (step: CreateStep) => void
  isDisabled: boolean
}) {
  const t = useTranslator()
  const { locale } = useLocale()
  const kindEntry = CLIENT_KINDS.find((entry) => entry.id === kind)
  const onOff = (value: boolean) => <Muted>{t(value ? 'clientsCreateOn' : 'clientsCreateOff')}</Muted>
  const list = new Intl.ListFormat(locale, { style: 'narrow', type: 'conjunction' })
  const grants = [
    ...SELECTABLE_GRANT_TYPES.filter((grant) => settings.grantTypes.includes(grant)),
    ...settings.grantTypes.filter((grant) => !SELECTABLE_GRANT_TYPES.includes(grant)),
  ].map((grant) => t(GRANT_LABELS[grant]))

  const edit = (step: CreateStep) => {
    const section = t(CREATE_STEP_LABELS[step])
    return (
      <Button
        type="button"
        variant="ghost"
        size="sm"
        disabled={isDisabled}
        aria-label={t('clientsCreateEditSection', { section })}
        onClick={() => onEdit(step)}
      >
        <Pencil aria-hidden="true" />
        {t('clientsCreateEdit')}
      </Button>
    )
  }

  return (
    <div className="space-y-6">
      <SettingsGroup title={t('clientsCreateStepKind')} action={edit('kind')}>
        <SettingsRow
          label={kindEntry ? t(kindEntry.label) : kind}
          description={kindEntry ? t(kindEntry.hint) : undefined}
        />
      </SettingsGroup>

      <SettingsGroup title={t('clientsCreateStepDetails')} action={edit('details')}>
        <SettingsRow label={t('localizedName')} action={<span className="text-sm">{text.name}</span>} />
        <SettingsRow
          label={t('localizedDescription')}
          action={
            text.description.trim() ? undefined : <Muted>{t('clientsCreateNotSet')}</Muted>
          }
        >
          {text.description.trim() ? (
            <p className="text-sm whitespace-pre-wrap break-words">{text.description}</p>
          ) : null}
        </SettingsRow>
      </SettingsGroup>

      {steps.includes('redirects') ? (
        <SettingsGroup title={t('clientsCreateStepRedirects')} action={edit('redirects')}>
          {visibleRedirectRows(kind, settings).map((row) => {
            const uris = uriLines(settings[row])
            return (
              <SettingsRow
                key={row}
                label={t(REDIRECT_LABELS[row])}
                action={uris.length ? undefined : <Muted>{t('clientsCreateNotSet')}</Muted>}
              >
                {uris.length ? (
                  <ul className="space-y-1">
                    {uris.map((uri) => (
                      <li key={uri} className="font-mono text-xs break-all">
                        {uri}
                      </li>
                    ))}
                  </ul>
                ) : null}
              </SettingsRow>
            )
          })}
          {kind === 'spa' || settings.corsEnabled ? (
            <SettingsRow label={t('clientsCorsEnabled')} action={onOff(settings.corsEnabled)} />
          ) : null}
        </SettingsGroup>
      ) : null}

      <SettingsGroup title={t('clientsCreateStepAccess')} action={edit('access')}>
        <SettingsRow
          label={t('clientsGrantTypes')}
          action={<span className="text-sm">{list.format(grants)}</span>}
        />
        <SettingsRow
          label={t('clientsAllowPublicFlow')}
          action={onOff(settings.allowPublicClientFlow)}
        />
        <SettingsRow
          label={t('clientsRequirePar')}
          action={onOff(settings.requirePushedAuthorizationRequests)}
        />
      </SettingsGroup>
    </div>
  )
}
