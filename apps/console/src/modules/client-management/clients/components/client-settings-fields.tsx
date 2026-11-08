import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@identity/ui/components/select'
import { Switch } from '@identity/ui/components/switch'

import { SettingsRow } from '#/components/settings-section'

import type {
  ClientGrantType,
  ClientOAuthVersion,
} from '#/generated/graphql'
import { useTranslator, type MessageKey } from '#/lib/i18n'
import { UserTextAreaField } from '#/modules/user-management/users/components/user-form-fields'
import {
  SELECTABLE_GRANT_TYPES,
  type ClientSettingsDraft,
  type ClientSettingsField,
} from '../lib/client-form'

export const GRANT_LABELS: Record<ClientGrantType, MessageKey> = {
  AUTHORIZATION_CODE: 'clientsGrantAuthorizationCode',
  REFRESH_TOKEN: 'clientsGrantRefreshToken',
  CLIENT_CREDENTIALS: 'clientsGrantClientCredentials',
  DEVICE_CODE: 'clientsGrantDeviceCode',
  IMPLICIT: 'clientsGrantImplicit',
}

const GRANT_DESCRIPTIONS: Partial<Record<ClientGrantType, MessageKey>> = {
  AUTHORIZATION_CODE: 'clientsGrantAuthorizationCodeHint',
  REFRESH_TOKEN: 'clientsGrantRefreshTokenHint',
  CLIENT_CREDENTIALS: 'clientsGrantClientCredentialsHint',
  DEVICE_CODE: 'clientsGrantDeviceCodeHint',
}

/** A switch whose name and explanation are shown by the surrounding row. */
function RowSwitch({
  label,
  isSelected,
  onChange,
  isDisabled,
}: {
  label: string
  isSelected: boolean
  onChange: (value: boolean) => void
  isDisabled: boolean
}) {
  return (
    <Switch
      aria-label={label}
      checked={isSelected}
      onCheckedChange={onChange}
      disabled={isDisabled}
    />
  )
}

function RowError({ children }: { children?: string }) {
  return children ? (
    <p role="alert" className="px-4 pb-3 text-xs leading-5 text-destructive">
      {children}
    </p>
  ) : null
}

/** Sentinel for "use the instance's live OAuth version". */
const INHERIT_OAUTH_VERSION = 'inherit'

/** A compact select shown at the end of a row. */
function RowSelect({
  label,
  value,
  onChange,
  options,
  isDisabled,
}: {
  label: string
  value: string
  onChange: (value: string) => void
  options: ReadonlyArray<{ id: string; label: string }>
  isDisabled: boolean
}) {
  return (
    <Select
      value={value}
      onValueChange={(next) => {
        if (next !== null) onChange(String(next))
      }}
      items={options.map((option) => ({
        value: option.id,
        label: option.label,
      }))}
      disabled={isDisabled}
    >
      <SelectTrigger aria-label={label} className="min-h-8 min-w-40 py-1">
        <SelectValue />
      </SelectTrigger>
      <SelectContent>
        {options.map((option) => (
          <SelectItem key={option.id} value={option.id}>
            {option.label}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  )
}

interface FieldsProps {
  draft: ClientSettingsDraft
  onChange: (next: ClientSettingsDraft) => void
  errors: Partial<Record<ClientSettingsField, string>>
  isDisabled?: boolean
}

type SwitchProps = Omit<FieldsProps, 'errors'>

function setter(draft: ClientSettingsDraft, onChange: FieldsProps['onChange']) {
  return <K extends keyof ClientSettingsDraft>(key: K, value: ClientSettingsDraft[K]) =>
    onChange({ ...draft, [key]: value })
}

/** Where the provider may send the browser back after sign-in and sign-out. */
export function RedirectUriRows({ draft, onChange, errors, isDisabled = false }: FieldsProps) {
  const t = useTranslator()
  const set = setter(draft, onChange)
  const rows = [
    {
      key: 'webRedirectUris' as const,
      name: 'web-redirect-uris',
      label: t('clientsWebRedirectUris'),
      hint: t('clientsWebRedirectUrisHint'),
      placeholder: 'https://app.example.com/callback',
      rows: 3,
    },
    {
      key: 'nativeRedirectUris' as const,
      name: 'native-redirect-uris',
      label: t('clientsNativeRedirectUris'),
      hint: t('clientsNativeRedirectUrisHint'),
      placeholder: 'com.example.app:/callback',
      rows: 2,
    },
    {
      key: 'postLogoutRedirectUris' as const,
      name: 'post-logout-redirect-uris',
      label: t('clientsPostLogoutRedirectUris'),
      hint: t('clientsPostLogoutRedirectUrisHint'),
      placeholder: 'https://app.example.com/signed-out',
      rows: 2,
    },
  ]
  return (
    <>
      {rows.map((row) => (
        <SettingsRow key={row.key} label={row.label} description={row.hint}>
          <UserTextAreaField
            name={row.name}
            label={row.label}
            hideLabel
            placeholder={row.placeholder}
            value={draft[row.key]}
            onChange={(value) => set(row.key, value)}
            error={errors[row.key]}
            isDisabled={isDisabled}
            rows={row.rows}
          />
        </SettingsRow>
      ))}
    </>
  )
}

/** Browser cross-origin requests from the Web redirect origins. */
export function CorsRow({ draft, onChange, isDisabled = false }: SwitchProps) {
  const t = useTranslator()
  return (
    <SettingsRow
      label={t('clientsCorsEnabled')}
      description={t('clientsCorsEnabledHint')}
      action={
        <RowSwitch
          label={t('clientsCorsEnabled')}
          isSelected={draft.corsEnabled}
          onChange={(value) => setter(draft, onChange)('corsEnabled', value)}
          isDisabled={isDisabled}
        />
      }
    />
  )
}

/** One row per OAuth grant this client may use. */
export function GrantTypeRows({ draft, onChange, errors, isDisabled = false }: FieldsProps) {
  const t = useTranslator()
  const set = setter(draft, onChange)
  // Keep a display-only value (such as implicit) visible so it can be removed.
  const grantOptions = [
    ...SELECTABLE_GRANT_TYPES,
    ...draft.grantTypes.filter((grant) => !SELECTABLE_GRANT_TYPES.includes(grant)),
  ]
  const toggle = (grant: ClientGrantType, on: boolean) =>
    set(
      'grantTypes',
      on
        ? [...draft.grantTypes, grant]
        : draft.grantTypes.filter((value) => value !== grant),
    )
  return (
    <>
      {grantOptions.map((grant) => (
        <SettingsRow
          key={grant}
          label={t(GRANT_LABELS[grant])}
          description={GRANT_DESCRIPTIONS[grant] ? t(GRANT_DESCRIPTIONS[grant]) : undefined}
          action={
            <RowSwitch
              label={t(GRANT_LABELS[grant])}
              isSelected={draft.grantTypes.includes(grant)}
              onChange={(on) => toggle(grant, on)}
              isDisabled={isDisabled}
            />
          }
        />
      ))}
      <RowError>{errors.grantTypes}</RowError>
    </>
  )
}

/** Authorization requests must be pushed to the PAR endpoint first. */
export function ParRow({ draft, onChange, isDisabled = false }: SwitchProps) {
  const t = useTranslator()
  return (
    <SettingsRow
      label={t('clientsRequirePar')}
      description={t('clientsRequireParHint')}
      action={
        <RowSwitch
          label={t('clientsRequirePar')}
          isSelected={draft.requirePushedAuthorizationRequests}
          onChange={(value) =>
            setter(draft, onChange)('requirePushedAuthorizationRequests', value)
          }
          isDisabled={isDisabled}
        />
      }
    />
  )
}

/** Whether users are asked to confirm the requested scopes. */
export function PublicClientFlowRow({ draft, onChange, isDisabled = false }: SwitchProps) {
  const t = useTranslator()
  return (
    <SettingsRow
      label={t('clientsAllowPublicFlow')}
      description={t('clientsAllowPublicFlowHint')}
      action={
        <RowSwitch
          label={t('clientsAllowPublicFlow')}
          isSelected={draft.allowPublicClientFlow}
          onChange={(value) => setter(draft, onChange)('allowPublicClientFlow', value)}
          isDisabled={isDisabled}
        />
      }
    />
  )
}

/**
 * OAuth rules for this client's authorization-code exchanges. Inheriting keeps
 * the instance's live setting, so a later instance-wide change still applies.
 */
export function OAuthVersionRow({ draft, onChange, isDisabled = false }: SwitchProps) {
  const t = useTranslator()
  const set = setter(draft, onChange)
  return (
    <SettingsRow
      label={t('clientsOAuthVersion')}
      description={t('clientsOAuthVersionHint')}
      action={
        <RowSelect
          label={t('clientsOAuthVersion')}
          value={draft.oauthVersion ?? INHERIT_OAUTH_VERSION}
          onChange={(value) =>
            set(
              'oauthVersion',
              value === INHERIT_OAUTH_VERSION ? null : (value as ClientOAuthVersion),
            )
          }
          options={[
            { id: INHERIT_OAUTH_VERSION, label: t('clientsOAuthVersionInherit') },
            { id: 'OAUTH_2_0', label: 'OAuth 2.0' },
            { id: 'OAUTH_2_1', label: 'OAuth 2.1' },
          ]}
          isDisabled={isDisabled}
        />
      }
    />
  )
}

/** Standard claims the granted scopes cover, in the issued tokens. */
export function ScopedClaimRows({ draft, onChange, isDisabled = false }: SwitchProps) {
  const t = useTranslator()
  const set = setter(draft, onChange)
  return (
    <>
      <SettingsRow
        label={t('clientsScopedClaimsIdToken')}
        description={t('clientsScopedClaimsIdTokenHint')}
        action={
          <RowSwitch
            label={t('clientsScopedClaimsIdToken')}
            isSelected={draft.includeScopedClaimsInIdToken}
            onChange={(value) => set('includeScopedClaimsInIdToken', value)}
            isDisabled={isDisabled}
          />
        }
      />
      <SettingsRow
        label={t('clientsScopedClaimsAccessToken')}
        description={t('clientsScopedClaimsAccessTokenHint')}
        action={
          <RowSwitch
            label={t('clientsScopedClaimsAccessToken')}
            isSelected={draft.includeScopedClaimsInAccessToken}
            onChange={(value) => set('includeScopedClaimsInAccessToken', value)}
            isDisabled={isDisabled}
          />
        }
      />
    </>
  )
}
