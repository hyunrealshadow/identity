import { AuthenticationContextClass } from '@identity/graphql-access'
import { Badge } from '@identity/ui/components/badge'
import { Checkbox } from '@identity/ui/components/checkbox'
import { Skeleton } from '@identity/ui/components/skeleton'
import { useState } from 'react'

import {
  SettingsNumberInput,
  SettingsRow,
  SettingsSelect,
  SettingsSwitch,
} from '#/components/settings-section'
import type { ClientSubjectType } from '#/generated/graphql'
import { useTranslator, type MessageKey } from '#/lib/i18n'
import {
  UserTextAreaField,
  UserTextField,
} from '#/modules/user-management/users/components/user-form-fields'
import type { ClientMetadataOptions } from '../hooks/use-client-metadata-options'
import {
  MAX_DEFAULT_MAX_AGE_SECONDS,
  type ClientAdvancedDraft,
  type ClientAdvancedField,
} from '../lib/advanced-form'

export interface AdvancedFieldsProps {
  draft: ClientAdvancedDraft
  onChange: (next: ClientAdvancedDraft) => void
  errors: Partial<Record<ClientAdvancedField, string>>
  isDisabled?: boolean
}

interface OptionProps extends AdvancedFieldsProps {
  /** `null` while the provider's supported values load. */
  options: ClientMetadataOptions | null
}

type ListField = {
  [K in ClientAdvancedField]: ClientAdvancedDraft[K] extends string[] ? K : never
}[ClientAdvancedField]

type TextField = {
  [K in ClientAdvancedField]: ClientAdvancedDraft[K] extends string ? K : never
}[ClientAdvancedField]

type FlagField = {
  [K in ClientAdvancedField]: ClientAdvancedDraft[K] extends boolean ? K : never
}[ClientAdvancedField]

function RowError({ children }: { children?: string }) {
  return children ? (
    <p role="alert" className="mt-2 text-xs leading-5 text-destructive">
      {children}
    </p>
  ) : null
}

/**
 * An algorithm (or level) choice that runs automatically until the
 * administrator pins it down. Automatic stores nothing, so the provider's
 * default behaviour applies, which `autoHint` describes in place of the row
 * description. Specifying shows the
 * supported values; the selection keeps the provider's order, which the
 * runtime tries in turn. A stored value the provider no longer supports stays
 * listed, marked, so it can be removed. With `keyed`, a selected algorithm the
 * provider holds no active key for is marked too: it stays valid, because keys
 * come and go, but issuance skips it until a key exists.
 */
function ChoiceRow({
  field,
  label,
  description,
  supported,
  labels,
  keyed,
  autoHint,
  draft,
  onChange,
  errors,
  isDisabled = false,
}: AdvancedFieldsProps & {
  field: ListField
  label: MessageKey
  description?: MessageKey
  supported: readonly string[] | undefined
  labels?: Partial<Record<string, MessageKey>>
  /** Values the provider holds an active key for; others are marked when selected. */
  keyed?: readonly string[]
  autoHint: MessageKey
}) {
  const t = useTranslator()
  const selected = draft[field]
  // Remembers "specify" while nothing is ticked yet; a stored selection is
  // always shown as specified.
  const [specifying, setSpecifying] = useState(selected.length > 0)
  const custom = specifying || selected.length > 0
  const available = supported ?? []
  const retired = selected.filter((value) => !available.includes(value))
  const choices = [...available, ...retired]
  const toggle = (value: string, on: boolean) => {
    const next = on ? [...selected, value] : selected.filter((item) => item !== value)
    onChange({
      ...draft,
      [field]: choices.filter((choice) => next.includes(choice)),
    })
  }
  const setMode = (mode: string) => {
    if (mode === 'auto') {
      setSpecifying(false)
      if (selected.length > 0) onChange({ ...draft, [field]: [] })
    } else {
      setSpecifying(true)
    }
  }
  return (
    <SettingsRow
      label={t(label)}
      description={!custom ? t(autoHint) : description ? t(description) : undefined}
      action={
        <SettingsSelect
          label={t('clientsAlgorithmMode', { setting: t(label) })}
          value={custom ? 'custom' : 'auto'}
          onChange={setMode}
          options={[
            { id: 'auto', label: t('clientsAlgorithmModeAuto') },
            { id: 'custom', label: t('clientsAlgorithmModeCustom') },
          ]}
          isDisabled={isDisabled}
        />
      }
    >
      {!custom ? (
        errors[field] ? <RowError>{errors[field]}</RowError> : null
      ) : !supported && choices.length === 0 ? (
        // Checkbox-shaped placeholders while the supported values load.
        <div aria-busy="true" className="flex flex-wrap gap-x-5 gap-y-2">
          {[0, 1, 2, 3].map((index) => (
            <Skeleton key={index} className="h-5 w-20 rounded-lg" />
          ))}
        </div>
      ) : choices.length === 0 ? (
        <p className="text-sm text-muted-foreground">{t('clientsAlgorithmNoneAvailable')}</p>
      ) : (
        <>
          <fieldset aria-label={t(label)} className="flex flex-wrap gap-x-5 gap-y-2">
            {choices.map((value) => (
              <label
                key={value}
                className="flex cursor-pointer items-center gap-2 text-sm has-disabled:cursor-not-allowed"
              >
                <Checkbox
                  checked={selected.includes(value)}
                  onCheckedChange={(checked) => toggle(value, checked === true)}
                  disabled={isDisabled}
                />
                <span className={labels?.[value] ? undefined : 'font-mono text-xs'}>
                  {labels?.[value] ? t(labels[value]) : value}
                </span>
                {retired.includes(value) ? (
                  <Badge variant="outline" className="text-warning">
                    {t('clientsAlgorithmUnavailable')}
                  </Badge>
                ) : keyed && selected.includes(value) && !keyed.includes(value) ? (
                  <Badge variant="outline" className="text-warning">
                    {t('clientsAlgorithmNoActiveKey')}
                  </Badge>
                ) : null}
              </label>
            ))}
          </fieldset>
          {selected.length === 0 ? (
            <p className="mt-2 text-xs text-muted-foreground">
              {t('clientsAlgorithmCustomEmptyHint')}
            </p>
          ) : keyed && !selected.some((value) => keyed.includes(value)) ? (
            <p className="mt-2 text-xs text-warning">{t('clientsAlgorithmNoKeyedSelection')}</p>
          ) : null}
          <RowError>{errors[field]}</RowError>
        </>
      )}
    </SettingsRow>
  )
}

function UriRow({
  field,
  label,
  description,
  placeholder,
  draft,
  onChange,
  errors,
  isDisabled = false,
}: AdvancedFieldsProps & {
  field: TextField
  label: MessageKey
  description: MessageKey
  placeholder: string
}) {
  const t = useTranslator()
  return (
    <SettingsRow label={t(label)} description={t(description)}>
      <UserTextField
        name={field}
        label={t(label)}
        hideLabel
        type="url"
        placeholder={placeholder}
        value={draft[field]}
        onChange={(value) => onChange({ ...draft, [field]: value })}
        error={errors[field]}
        isDisabled={isDisabled}
      />
    </SettingsRow>
  )
}

function SwitchRow({
  field,
  label,
  description,
  draft,
  onChange,
  isDisabled = false,
}: Omit<AdvancedFieldsProps, 'errors'> & {
  field: FlagField
  label: MessageKey
  description: MessageKey
}) {
  const t = useTranslator()
  return (
    <SettingsRow
      label={t(label)}
      description={t(description)}
      action={
        <SettingsSwitch
          label={t(label)}
          isSelected={draft[field]}
          onChange={(value) => onChange({ ...draft, [field]: value })}
          isDisabled={isDisabled}
        />
      }
    />
  )
}

/** Links and contacts shown to users on sign-in and consent pages. */
export function ApplicationLinkRows(props: AdvancedFieldsProps) {
  const t = useTranslator()
  const { draft, onChange, errors, isDisabled = false } = props
  return (
    <>
      <UriRow
        {...props}
        field="logoUri"
        label="clientsLogoUri"
        description="clientsLogoUriHint"
        placeholder="https://app.example.com/logo.png"
      />
      <UriRow
        {...props}
        field="clientUri"
        label="clientsClientUri"
        description="clientsClientUriHint"
        placeholder="https://app.example.com"
      />
      <UriRow
        {...props}
        field="policyUri"
        label="clientsPolicyUri"
        description="clientsPolicyUriHint"
        placeholder="https://app.example.com/privacy"
      />
      <UriRow
        {...props}
        field="tosUri"
        label="clientsTosUri"
        description="clientsTosUriHint"
        placeholder="https://app.example.com/terms"
      />
      <SettingsRow label={t('clientsContacts')} description={t('clientsContactsHint')}>
        <UserTextAreaField
          name="contacts"
          label={t('clientsContacts')}
          hideLabel
          placeholder="ops@example.com"
          value={draft.contacts}
          onChange={(contacts) => onChange({ ...draft, contacts })}
          error={errors.contacts}
          isDisabled={isDisabled}
          rows={2}
        />
      </SettingsRow>
    </>
  )
}

/** Front-channel and back-channel logout notifications. */
export function LogoutChannelRows(props: AdvancedFieldsProps) {
  return (
    <>
      <UriRow
        {...props}
        field="frontchannelLogoutUri"
        label="clientsFrontchannelLogoutUri"
        description="clientsFrontchannelLogoutUriHint"
        placeholder="https://app.example.com/logout/frontchannel"
      />
      <SwitchRow
        {...props}
        field="frontchannelLogoutSessionRequired"
        label="clientsFrontchannelSessionRequired"
        description="clientsFrontchannelSessionRequiredHint"
      />
      <UriRow
        {...props}
        field="backchannelLogoutUri"
        label="clientsBackchannelLogoutUri"
        description="clientsBackchannelLogoutUriHint"
        placeholder="https://app.example.com/logout/backchannel"
      />
      <SwitchRow
        {...props}
        field="backchannelLogoutSessionRequired"
        label="clientsBackchannelSessionRequired"
        description="clientsBackchannelSessionRequiredHint"
      />
    </>
  )
}

const SUBJECT_LABELS: Record<ClientSubjectType, MessageKey> = {
  PUBLIC: 'clientsSubjectPublic',
  PAIRWISE: 'clientsSubjectPairwise',
}

/** How the `sub` claim is formed, and the sector a pairwise one belongs to. */
export function SubjectRows(props: OptionProps) {
  const t = useTranslator()
  const { draft, onChange, isDisabled = false, options } = props
  const supported = options?.subjectTypes ?? ['public', 'pairwise']
  const choices = (Object.keys(SUBJECT_LABELS) as ClientSubjectType[]).filter(
    (type) => supported.includes(type.toLowerCase()) || draft.subjectType === type,
  )
  return (
    <>
      <SettingsRow
        label={t('clientsSubjectType')}
        description={t(
          draft.subjectType === 'PAIRWISE'
            ? 'clientsSubjectPairwiseHint'
            : 'clientsSubjectPublicHint',
        )}
        action={
          <SettingsSelect
            label={t('clientsSubjectType')}
            value={draft.subjectType}
            onChange={(value) =>
              onChange({ ...draft, subjectType: value as ClientSubjectType })
            }
            options={choices.map((type) => ({ id: type, label: t(SUBJECT_LABELS[type]) }))}
            isDisabled={isDisabled}
          />
        }
      />
      {draft.subjectType === 'PAIRWISE' ? (
        <UriRow
          {...props}
          field="sectorIdentifierUri"
          label="clientsSectorIdentifierUri"
          description="clientsSectorIdentifierUriHint"
          placeholder="https://app.example.com/sector.json"
        />
      ) : null}
    </>
  )
}

const ACR_LABELS: Partial<Record<string, MessageKey>> = {
  [AuthenticationContextClass.SingleFactor]: 'clientsAcrSingleFactor',
  [AuthenticationContextClass.MultiFactor]: 'clientsAcrMultiFactor',
  [AuthenticationContextClass.PhishingResistant]: 'clientsAcrPhishingResistant',
}

/** Defaults applied when an authorization request does not ask itself. */
export function AuthenticationRequirementRows(props: OptionProps) {
  const t = useTranslator()
  const { draft, onChange, errors, isDisabled = false, options } = props
  return (
    <>
      <SettingsRow
        label={t('clientsDefaultMaxAge')}
        description={t('clientsDefaultMaxAgeHint')}
        action={
          <SettingsNumberInput
            name="defaultMaxAge"
            label={t('clientsDefaultMaxAge')}
            value={draft.defaultMaxAge}
            onChange={(defaultMaxAge) => onChange({ ...draft, defaultMaxAge })}
            min={0}
            max={MAX_DEFAULT_MAX_AGE_SECONDS}
            unit={t('clientsSecondsUnit')}
            invalid={Boolean(errors.defaultMaxAge)}
            isDisabled={isDisabled}
          />
        }
      >
        {errors.defaultMaxAge ? <RowError>{errors.defaultMaxAge}</RowError> : null}
      </SettingsRow>
      <SwitchRow
        {...props}
        field="requireAuthTime"
        label="clientsRequireAuthTime"
        description="clientsRequireAuthTimeHint"
      />
      <ChoiceRow
        {...props}
        field="defaultAcrValues"
        autoHint="clientsAutoRequestDecides"
        label="clientsDefaultAcrValues"
        description="clientsDefaultAcrValuesHint"
        supported={options?.acrValues}
        labels={ACR_LABELS}
      />
    </>
  )
}

/** ID Token and UserInfo signing and encryption. */
export function TokenProtectionRows(props: OptionProps) {
  const { options } = props
  return (
    <>
      <ChoiceRow
        {...props}
        field="idTokenSignedResponseAlgs"
        autoHint="clientsAutoActiveSigningKey"
        label="clientsIdTokenSigning"
        description="clientsIdTokenSigningHint"
        supported={options?.idTokenSigningAlgs}
        keyed={options?.activeSigningAlgs}
      />
      <ChoiceRow
        {...props}
        field="idTokenEncryptedResponseAlgs"
        autoHint="clientsAutoNoEncryption"
        label="clientsIdTokenEncryptionAlg"
        description="clientsEncryptionAlgHint"
        supported={options?.idTokenEncryptionAlgs}
      />
      <ChoiceRow
        {...props}
        field="idTokenEncryptedResponseEncs"
        autoHint={
          props.draft.idTokenEncryptedResponseAlgs.length > 0
            ? 'clientsAutoDefaultContentEncryption'
            : 'clientsAutoContentEncryptionOff'
        }
        label="clientsIdTokenEncryptionEnc"
        supported={options?.idTokenEncryptionEncs}
      />
      <ChoiceRow
        {...props}
        field="userinfoSignedResponseAlgs"
        autoHint="clientsAutoUnsignedUserinfo"
        label="clientsUserinfoSigning"
        description="clientsUserinfoSigningHint"
        supported={options?.userinfoSigningAlgs}
        keyed={options?.activeSigningAlgs}
      />
      <ChoiceRow
        {...props}
        field="userinfoEncryptedResponseAlgs"
        autoHint="clientsAutoNoEncryption"
        label="clientsUserinfoEncryptionAlg"
        description="clientsEncryptionAlgHint"
        supported={options?.userinfoEncryptionAlgs}
      />
      <ChoiceRow
        {...props}
        field="userinfoEncryptedResponseEncs"
        autoHint={
          props.draft.userinfoEncryptedResponseAlgs.length > 0
            ? 'clientsAutoDefaultContentEncryption'
            : 'clientsAutoContentEncryptionOff'
        }
        label="clientsUserinfoEncryptionEnc"
        supported={options?.userinfoEncryptionEncs}
      />
    </>
  )
}

/** Signed and encrypted request objects, and pre-registered `request_uri`s. */
export function RequestObjectRows(props: OptionProps) {
  const t = useTranslator()
  const { draft, onChange, errors, isDisabled = false, options } = props
  return (
    <>
      <ChoiceRow
        {...props}
        field="requestObjectSigningAlgs"
        autoHint="clientsAutoAcceptSupported"
        label="clientsRequestObjectSigning"
        description="clientsRequestObjectSigningHint"
        supported={options?.requestObjectSigningAlgs}
        labels={{ none: 'clientsAlgorithmUnsigned' }}
      />
      <ChoiceRow
        {...props}
        field="requestObjectEncryptionAlgs"
        autoHint="clientsAutoAcceptSupported"
        label="clientsRequestObjectEncryptionAlg"
        description="clientsRequestObjectEncryptionAlgHint"
        supported={options?.requestObjectEncryptionAlgs}
        keyed={options?.activeRequestObjectEncryptionAlgs}
      />
      <ChoiceRow
        {...props}
        field="requestObjectEncryptionEncs"
        autoHint="clientsAutoAcceptSupported"
        label="clientsRequestObjectEncryptionEnc"
        supported={options?.requestObjectEncryptionEncs}
      />
      <SettingsRow label={t('clientsRequestUris')} description={t('clientsRequestUrisHint')}>
        <UserTextAreaField
          name="requestUris"
          label={t('clientsRequestUris')}
          hideLabel
          placeholder="https://app.example.com/requests/signed.jwt"
          value={draft.requestUris}
          onChange={(requestUris) => onChange({ ...draft, requestUris })}
          error={errors.requestUris}
          isDisabled={isDisabled}
          rows={2}
        />
      </SettingsRow>
    </>
  )
}

/** Algorithms accepted for `private_key_jwt` and `client_secret_jwt` assertions. */
export function ClientAssertionRow(props: OptionProps) {
  return (
    <ChoiceRow
      {...props}
      field="tokenEndpointAuthSigningAlgs"
      autoHint="clientsAutoAcceptSupported"
      label="clientsAssertionSigning"
      description="clientsAssertionSigningHint"
      supported={props.options?.tokenEndpointAuthSigningAlgs}
    />
  )
}

/** Where a third party may start sign-in for this client. */
export function InitiateLoginRow(props: AdvancedFieldsProps) {
  return (
    <UriRow
      {...props}
      field="initiateLoginUri"
      label="clientsInitiateLoginUri"
      description="clientsInitiateLoginUriHint"
      placeholder="https://app.example.com/login"
    />
  )
}
