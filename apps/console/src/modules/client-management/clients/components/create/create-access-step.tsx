import { SettingsGroup } from '#/components/settings-section'
import { useTranslator } from '#/lib/i18n'
import type { ClientSettingsDraft, ClientSettingsField } from '../../lib/client-form'
import { GrantTypeRows, ParRow, PublicClientFlowRow } from '../client-settings-fields'

export function CreateAccessStep({
  settings,
  onChange,
  errors,
  isDisabled,
}: {
  settings: ClientSettingsDraft
  onChange: (settings: ClientSettingsDraft) => void
  errors: Partial<Record<ClientSettingsField, string>>
  isDisabled: boolean
}) {
  const t = useTranslator()
  const fieldProps = { draft: settings, onChange, errors, isDisabled }
  return (
    <div className="space-y-6">
      <SettingsGroup title={t('clientsGrantTypes')}>
        <GrantTypeRows {...fieldProps} />
      </SettingsGroup>
      <SettingsGroup
        title={t('clientsPublicClientSection')}
        description={t('clientsPublicClientSectionHint')}
      >
        <PublicClientFlowRow {...fieldProps} />
      </SettingsGroup>
      <SettingsGroup title={t('clientsAuthorizationRequestsSection')}>
        <ParRow {...fieldProps} />
      </SettingsGroup>
    </div>
  )
}
