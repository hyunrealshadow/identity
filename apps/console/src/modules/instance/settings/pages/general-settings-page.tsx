import { CopyButton } from '#/components/copy-button'
import {
  SettingsGroup,
  SettingsGroupSkeleton,
  SettingsRow,
} from '#/components/settings-section'
import { formatDateTime } from '#/lib/format'
import { useLocale, useTranslator } from '#/lib/i18n'
import { useInstanceSettings, useSettingsBlocker } from '../components/settings-shell'

function AddressValue({ value, label }: { value: string | null | undefined; label: string }) {
  if (!value) return null
  return (
    <div className="flex min-w-0 items-center gap-1">
      <code className="break-all text-xs">{value}</code>
      <CopyButton value={value} label={label} />
    </div>
  )
}

/** Deployment facts recorded at installation. They change with the deployment, not here. */
export function GeneralSettingsPage() {
  const t = useTranslator()
  const { locale, timeZone } = useLocale()
  const { settings } = useInstanceSettings()
  const blocked = useSettingsBlocker()
  if (blocked) return blocked
  if (!settings) {
    return (
      <div className="space-y-6" aria-busy="true">
        <SettingsGroupSkeleton rows={['value', 'value', 'value']} description />
        <SettingsGroupSkeleton rows={['value']} />
      </div>
    )
  }
  const general = settings.general
  return (
    <div className="space-y-6">
      <SettingsGroup
        title={t('settingsAddressesSection')}
        description={t('settingsAddressesSectionHint')}
      >
        <SettingsRow
          label={t('settingsIssuer')}
          description={t('settingsIssuerHint')}
          action={<AddressValue value={general.issuer} label={t('settingsIssuer')} />}
        />
        <SettingsRow
          label={t('settingsLoginUrl')}
          description={t('settingsLoginUrlHint')}
          action={<AddressValue value={general.loginUrl} label={t('settingsLoginUrl')} />}
        />
        <SettingsRow
          label={t('settingsConsoleUrl')}
          description={t('settingsConsoleUrlHint')}
          action={<AddressValue value={general.consoleUrl} label={t('settingsConsoleUrl')} />}
        />
      </SettingsGroup>
      <SettingsGroup title={t('settingsInstallationSection')}>
        <SettingsRow
          label={t('settingsInitializedAt')}
          action={
            general.initializedAt ? (
              <span className="text-sm text-muted-foreground">
                {formatDateTime(general.initializedAt, locale, timeZone)}
              </span>
            ) : null
          }
        />
      </SettingsGroup>
    </div>
  )
}
