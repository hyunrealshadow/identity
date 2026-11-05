import {
  Checkbox,
  CheckboxGroup,
  Description,
  FieldError,
  Label,
  Switch,
} from '@heroui/react'

import type { ClientAuthMethod, ClientGrantType } from '#/gql/graphql'
import { useTranslator, type MessageKey } from '#/lib/i18n'
import {
  UserSelectField,
  UserTextAreaField,
} from '#/modules/user-management/users/components/user-form-fields'
import {
  SELECTABLE_AUTH_METHODS,
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

export const AUTH_METHOD_LABELS: Record<ClientAuthMethod, MessageKey> = {
  CLIENT_SECRET_BASIC: 'clientsAuthSecretBasic',
  CLIENT_SECRET_POST: 'clientsAuthSecretPost',
  CLIENT_SECRET_JWT: 'clientsAuthSecretJwt',
  PRIVATE_KEY_JWT: 'clientsAuthPrivateKeyJwt',
  NONE: 'clientsAuthNone',
}

function SettingSwitch({
  label,
  description,
  isSelected,
  onChange,
  isDisabled,
}: {
  label: string
  description: string
  isSelected: boolean
  onChange: (value: boolean) => void
  isDisabled: boolean
}) {
  return (
    <Switch isSelected={isSelected} onChange={onChange} isDisabled={isDisabled}>
      <Switch.Control>
        <Switch.Thumb />
      </Switch.Control>
      <Switch.Content>
        <Label>{label}</Label>
        <Description>{description}</Description>
      </Switch.Content>
    </Switch>
  )
}

export function ClientSettingsFields({
  draft,
  onChange,
  errors,
  isDisabled = false,
}: {
  draft: ClientSettingsDraft
  onChange: (next: ClientSettingsDraft) => void
  errors: Partial<Record<ClientSettingsField, string>>
  isDisabled?: boolean
}) {
  const t = useTranslator()
  const set = <K extends keyof ClientSettingsDraft>(
    key: K,
    value: ClientSettingsDraft[K],
  ) => onChange({ ...draft, [key]: value })
  // Keep a display-only value (such as implicit) visible so it can be removed.
  const grantOptions = [
    ...SELECTABLE_GRANT_TYPES,
    ...draft.grantTypes.filter((grant) => !SELECTABLE_GRANT_TYPES.includes(grant)),
  ]
  const methodOptions = SELECTABLE_AUTH_METHODS.includes(
    draft.tokenEndpointAuthMethod,
  )
    ? SELECTABLE_AUTH_METHODS
    : [draft.tokenEndpointAuthMethod, ...SELECTABLE_AUTH_METHODS]

  return (
    <div className="space-y-6">
      <section className="space-y-4">
        <h3 className="text-sm font-semibold">{t('clientsRedirectSection')}</h3>
        <UserTextAreaField
          name="web-redirect-uris"
          label={t('clientsWebRedirectUris')}
          description={t('clientsWebRedirectUrisHint')}
          placeholder="https://app.example.com/callback"
          value={draft.webRedirectUris}
          onChange={(value) => set('webRedirectUris', value)}
          error={errors.webRedirectUris}
          isDisabled={isDisabled}
          rows={3}
        />
        <UserTextAreaField
          name="native-redirect-uris"
          label={t('clientsNativeRedirectUris')}
          description={t('clientsNativeRedirectUrisHint')}
          placeholder="com.example.app:/callback"
          value={draft.nativeRedirectUris}
          onChange={(value) => set('nativeRedirectUris', value)}
          error={errors.nativeRedirectUris}
          isDisabled={isDisabled}
          rows={2}
        />
        <UserTextAreaField
          name="post-logout-redirect-uris"
          label={t('clientsPostLogoutRedirectUris')}
          description={t('clientsPostLogoutRedirectUrisHint')}
          placeholder="https://app.example.com/signed-out"
          value={draft.postLogoutRedirectUris}
          onChange={(value) => set('postLogoutRedirectUris', value)}
          error={errors.postLogoutRedirectUris}
          isDisabled={isDisabled}
          rows={2}
        />
      </section>

      <section className="space-y-4">
        <h3 className="text-sm font-semibold">{t('clientsProtocolSection')}</h3>
        <CheckboxGroup
          name="grant-types"
          value={draft.grantTypes}
          onChange={(value) => set('grantTypes', value as ClientGrantType[])}
          isDisabled={isDisabled}
          isInvalid={Boolean(errors.grantTypes)}
        >
          <Label>{t('clientsGrantTypes')}</Label>
          {grantOptions.map((grant) => (
            <Checkbox key={grant} value={grant}>
              <Checkbox.Content>
                <Checkbox.Control>
                  <Checkbox.Indicator />
                </Checkbox.Control>
                {t(GRANT_LABELS[grant])}
              </Checkbox.Content>
              {GRANT_DESCRIPTIONS[grant] ? (
                <Description>{t(GRANT_DESCRIPTIONS[grant])}</Description>
              ) : null}
            </Checkbox>
          ))}
          {errors.grantTypes ? <FieldError>{errors.grantTypes}</FieldError> : null}
        </CheckboxGroup>
        <div className="max-w-md">
          <UserSelectField
            name="token-endpoint-auth-method"
            label={t('clientsAuthMethod')}
            description={t('clientsAuthMethodHint')}
            value={draft.tokenEndpointAuthMethod}
            onChange={(value) =>
              set('tokenEndpointAuthMethod', value as ClientAuthMethod)
            }
            options={methodOptions.map((method) => ({
              id: method,
              label: t(AUTH_METHOD_LABELS[method]),
            }))}
            error={errors.tokenEndpointAuthMethod}
            isDisabled={isDisabled}
          />
        </div>
      </section>

      <section className="space-y-4">
        <h3 className="text-sm font-semibold">{t('clientsBehaviorSection')}</h3>
        <SettingSwitch
          label={t('clientsCorsEnabled')}
          description={t('clientsCorsEnabledHint')}
          isSelected={draft.corsEnabled}
          onChange={(value) => set('corsEnabled', value)}
          isDisabled={isDisabled}
        />
        <SettingSwitch
          label={t('clientsRequirePar')}
          description={t('clientsRequireParHint')}
          isSelected={draft.requirePushedAuthorizationRequests}
          onChange={(value) => set('requirePushedAuthorizationRequests', value)}
          isDisabled={isDisabled}
        />
        <SettingSwitch
          label={t('clientsSkipConsent')}
          description={t('clientsSkipConsentHint')}
          isSelected={draft.skipConsent}
          onChange={(value) => set('skipConsent', value)}
          isDisabled={isDisabled}
        />
      </section>
    </div>
  )
}
