import { Field, FieldError, FieldLabel } from '@identity/ui/components/field'
import { ShieldAlert } from 'lucide-react'
import { useState } from 'react'

import { AuthShell } from '#/components/auth-shell'
import { ErrorAlert } from '#/components/form-alert'
import { ProgressiveForm } from '#/components/progressive-form'
import { SubmitButton } from '#/components/submit-button'
import { translate, type Locale } from '#/lib/i18n'
import type { DeviceVerificationPageData } from '#/lib/identity-types'
import { ConsentAccount } from '#/modules/consent/components/consent-account'
import { ConsentNotice } from '#/modules/consent/components/consent-notice'
import { ConsentPermissions } from '#/modules/consent/components/consent-permissions'
import { DeviceOutcomePage } from '#/modules/device/components/device-outcome'
import { GroupedCodeInput } from '#/modules/mfa/components/totp-input'

export interface DeviceSearch {
  login_id?: string
  user_code?: string
  error?: string
  ui_locales?: string
}

export interface DeviceRouteData {
  device?: DeviceVerificationPageData
  userCode: string
  prefilled: boolean
  locale: Locale
  uiLocales: string
  error?: string
  codeError?: string
}

/// A request that is already answered or gone cannot be decided again, so the
/// page reports its state instead of offering the buttons.
function decidedOutcome(status: DeviceVerificationPageData['status']) {
  switch (status) {
    case 'approved':
      return 'approved'
    case 'denied':
      return 'denied'
    case 'expired':
    case 'consumed':
      return 'expired'
    default:
      return undefined
  }
}

export function DevicePageView({
  data,
  search,
}: {
  data: DeviceRouteData
  search: DeviceSearch
}) {
  const device = data.device
  const outcome = device ? decidedOutcome(device.status) : undefined
  const visibleError = search.error ?? data.error
  const t = (
    key: Parameters<typeof translate>[1],
    values?: Record<string, string | number>,
  ) => translate(data.locale, key, values)

  if (outcome) {
    return <DeviceOutcomePage locale={data.locale} outcome={outcome} />
  }

  if (!device) {
    return (
      <CodeEntryPage
        locale={data.locale}
        uiLocales={data.uiLocales}
        userCode={data.userCode}
        prefilled={data.prefilled}
        error={visibleError}
        codeError={data.codeError}
      />
    )
  }

  return (
    <AuthShell
      lang={data.locale}
      locale={data.locale}
      showPreferences
      title={t('deviceVerifyTitle')}
      description={t('deviceVerifyDescription', { client: device.client_name })}
    >
      {visibleError ? (
        <DeviceError title={t('deviceLoadFailed')} message={visibleError} />
      ) : null}

      <ConsentAccount account={device.account} locale={data.locale} />

      {device.consent_required ? (
        <ConsentPermissions scopes={device.scopes} locale={data.locale} />
      ) : null}

      <DeviceCaution message={t('deviceCaution')} />

      <ProgressiveForm
        action="/device"
        className="progressive-form mt-4 grid grid-cols-2 gap-3"
        enhancementErrorMessage={t('enhancedNavigationError')}
      >
        <input type="hidden" name="login_id" value={device.login_id} />
        <input type="hidden" name="csrf_token" value={device.csrf_token} />
        {data.uiLocales ? (
          <input type="hidden" name="ui_locales" value={data.uiLocales} />
        ) : null}
        <SubmitButton fullWidth name="decision" value="deny" variant="outline">
          {t('deny')}
        </SubmitButton>
        <SubmitButton fullWidth name="decision" value="approve">
          {t('allow')}
        </SubmitButton>
      </ProgressiveForm>

      {/* Trusted clients skip the permission list but still need this
          explicit, CSRF-protected confirmation. */}
      <ConsentNotice
        message={t(
          device.consent_required ? 'revoke' : 'deviceTrustedClient',
        )}
      />
    </AuthShell>
  )
}

function CodeEntryPage({
  locale,
  uiLocales,
  userCode,
  prefilled,
  error,
  codeError,
}: {
  locale: Locale
  uiLocales: string
  userCode: string
  prefilled: boolean
  error?: string
  codeError?: string
}) {
  const [fieldError, setFieldError] = useState(codeError)
  const t = (
    key: Parameters<typeof translate>[1],
    values?: Record<string, string | number>,
  ) => translate(locale, key, values)

  return (
    <AuthShell
      lang={locale}
      locale={locale}
      showPreferences
      title={t('deviceTitle')}
      description={t(
        prefilled ? 'deviceConfirmCodeDescription' : 'deviceDescription',
      )}
    >
      {error ? (
        <DeviceError title={t('deviceLoadFailed')} message={error} />
      ) : null}
      <ProgressiveForm
        action="/device"
        className="progressive-form space-y-6"
        enhancementErrorMessage={t('enhancedNavigationError')}
      >
        <input type="hidden" name="intent" value="enter-code" />
        {uiLocales ? (
          <input type="hidden" name="ui_locales" value={uiLocales} />
        ) : null}
        <Field data-invalid={fieldError ? true : undefined} className="min-w-0">
          <FieldLabel htmlFor="device-user-code">
            {t('deviceCodeLabel')}
          </FieldLabel>
          <GroupedCodeInput
            id="device-user-code"
            name="user_code"
            type="text"
            required
            autoFocus={!prefilled}
            isInvalid={!!fieldError}
            aria-describedby={fieldError ? 'device-user-code-error' : undefined}
            defaultValue={userCode}
            onChange={() => setFieldError(undefined)}
          />
          {fieldError ? (
            <FieldError id="device-user-code-error">{fieldError}</FieldError>
          ) : null}
        </Field>
        <SubmitButton fullWidth autoFocus={prefilled}>
          {t('deviceSubmit')}
        </SubmitButton>
      </ProgressiveForm>
    </AuthShell>
  )
}

function DeviceError({ message, title }: { message: string; title: string }) {
  return <ErrorAlert className="mb-5" title={title} message={message} />
}

function DeviceCaution({ message }: { message: string }) {
  return (
    <p className="mt-6 flex items-start gap-2 text-xs leading-5 text-muted-foreground">
      <ShieldAlert className="mt-0.5 size-4 shrink-0" aria-hidden="true" />
      <span>{message}</span>
    </p>
  )
}
