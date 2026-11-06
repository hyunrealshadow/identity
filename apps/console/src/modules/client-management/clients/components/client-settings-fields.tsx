import { Switch } from '@heroui/react'

import { SettingsRow } from '#/components/settings-section'

import type { ClientAuthMethod, ClientGrantType } from '#/generated/graphql'
import { useTranslator, type MessageKey } from '#/lib/i18n'
import { UserTextAreaField } from '#/modules/user-management/users/components/user-form-fields'
import {
  SELECTABLE_AUTH_METHODS,
  SELECTABLE_GRANT_TYPES,
  toggleAuthMethod,
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

export const AUTH_METHOD_LABELS: Record<ClientAuthMethod, MessageKey> = {
  CLIENT_SECRET_BASIC: 'clientsAuthSecretBasic',
  CLIENT_SECRET_POST: 'clientsAuthSecretPost',
  CLIENT_SECRET_JWT: 'clientsAuthSecretJwt',
  PRIVATE_KEY_JWT: 'clientsAuthPrivateKeyJwt',
  NONE: 'clientsAuthNone',
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
      isSelected={isSelected}
      onChange={onChange}
      isDisabled={isDisabled}
    >
      <Switch.Content>
        <Switch.Control>
          <Switch.Thumb />
        </Switch.Control>
      </Switch.Content>
    </Switch>
  )
}

function RowError({ children }: { children?: string }) {
  return children ? (
    <p role="alert" className="px-4 pb-3 text-xs leading-5 text-danger">
      {children}
    </p>
  ) : null
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
const AUTH_METHOD_DESCRIPTIONS: Partial<Record<ClientAuthMethod, MessageKey>> = {
  CLIENT_SECRET_BASIC: 'clientsAuthSecretBasicHint',
  CLIENT_SECRET_POST: 'clientsAuthSecretPostHint',
  CLIENT_SECRET_JWT: 'clientsAuthSecretJwtHint',
  NONE: 'clientsAuthNoneHint',
}

/** One row per method the client may use at the token endpoint. */
export function AuthMethodRows({ draft, onChange, errors, isDisabled = false }: FieldsProps) {
  const t = useTranslator()
  const set = setter(draft, onChange)
  // Keep a display-only value (such as private_key_jwt) visible so it can be removed.
  const methodOptions = [
    ...SELECTABLE_AUTH_METHODS,
    ...draft.tokenEndpointAuthMethods.filter(
      (method) => !SELECTABLE_AUTH_METHODS.includes(method),
    ),
  ]
  return (
    <>
      {methodOptions.map((method) => (
        <SettingsRow
          key={method}
          label={t(AUTH_METHOD_LABELS[method])}
          description={
            AUTH_METHOD_DESCRIPTIONS[method] ? t(AUTH_METHOD_DESCRIPTIONS[method]) : undefined
          }
          action={
            <RowSwitch
              label={t(AUTH_METHOD_LABELS[method])}
              isSelected={draft.tokenEndpointAuthMethods.includes(method)}
              onChange={(on) =>
                set(
                  'tokenEndpointAuthMethods',
                  toggleAuthMethod(draft.tokenEndpointAuthMethods, method, on),
                )
              }
              isDisabled={isDisabled}
            />
          }
        />
      ))}
      <RowError>{errors.tokenEndpointAuthMethods}</RowError>
    </>
  )
}

/**
 * The public client flow is a separate switch: registering `none` alone does
 * not let a client authenticate without a secret.
 */
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
