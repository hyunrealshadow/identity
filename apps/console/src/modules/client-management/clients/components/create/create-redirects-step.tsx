import { SettingsGroup } from '#/components/settings-section'
import type { ClientKind, ClientSettingsDraft, ClientSettingsField } from '../../lib/client-form'
import { uriLines } from '../../lib/client-form'
import { CorsRow, RedirectUriRows, type RedirectRow } from '../client-settings-fields'

/** The redirect lists a kind of client normally needs. */
function redirectRowsFor(kind: ClientKind): readonly RedirectRow[] {
  return kind === 'native'
    ? ['nativeRedirectUris', 'postLogoutRedirectUris']
    : ['webRedirectUris', 'postLogoutRedirectUris']
}

/**
 * The rows this step shows: the ones the kind needs, plus any list that
 * already holds addresses (for example after switching kind), so nothing that
 * will be submitted stays hidden.
 */
export function visibleRedirectRows(
  kind: ClientKind,
  settings: ClientSettingsDraft,
): readonly RedirectRow[] {
  const wanted = redirectRowsFor(kind)
  const order: readonly RedirectRow[] = [
    'webRedirectUris',
    'nativeRedirectUris',
    'postLogoutRedirectUris',
  ]
  return order.filter((row) => wanted.includes(row) || uriLines(settings[row]).length > 0)
}

export function CreateRedirectsStep({
  kind,
  settings,
  onChange,
  errors,
  isDisabled,
}: {
  kind: ClientKind
  settings: ClientSettingsDraft
  onChange: (settings: ClientSettingsDraft) => void
  errors: Partial<Record<ClientSettingsField, string>>
  isDisabled: boolean
}) {
  const rows = visibleRedirectRows(kind, settings)
  // "A redirect address is required" is reported on the Web list; show it on
  // the list this kind actually uses when the Web list is hidden.
  const shown =
    errors.webRedirectUris && !rows.includes('webRedirectUris')
      ? {
          ...errors,
          nativeRedirectUris: errors.nativeRedirectUris ?? errors.webRedirectUris,
        }
      : errors
  const fieldProps = { draft: settings, onChange, errors: shown, isDisabled }
  return (
    <div className="space-y-6">
      <SettingsGroup>
        <RedirectUriRows {...fieldProps} include={rows} />
      </SettingsGroup>
      {kind === 'spa' || settings.corsEnabled ? (
        <SettingsGroup>
          <CorsRow {...fieldProps} />
        </SettingsGroup>
      ) : null}
    </div>
  )
}
