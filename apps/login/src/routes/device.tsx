import { Field, FieldError, FieldLabel } from '@identity/ui/components/field'
import { createFileRoute } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { Check, Clock, ShieldAlert, X } from 'lucide-react'
import { useState } from 'react'

import { ConsentAccount } from '#/components/consent-account'
import { AuthShell } from '#/components/auth-shell'
import { ErrorAlert } from '#/components/form-alert'
import { ProgressiveForm } from '#/components/progressive-form'
import { ConsentPermissions } from '#/components/consent-permissions'
import { ConsentNotice } from '#/components/consent-notice'
import { SubmitButton } from '#/components/submit-button'
import { GroupedCodeInput } from '#/components/totp-input'
import { errorMessage, LocalizedError } from '#/lib/identity.server'
import {
  beginDeviceVerification,
  decideDeviceVerification,
  deviceInteractionPath,
  loadDeviceVerification,
} from '#/lib/device-verification.server'
import type { DeviceVerificationPageData } from '#/lib/identity-types'
import {
  consumeFormFlash,
  formErrorResponse,
  navigationResponse,
} from '#/lib/responses.server'
import { translate } from '#/lib/i18n'
import { formLocale, requestLocale } from '#/lib/i18n.server'

interface DeviceSearch {
  login_id?: string
  user_code?: string
  done?: string
  error?: string
  ui_locales?: string
}

type DeviceOutcome = 'approved' | 'denied' | 'expired'

function optionalString(value: unknown) {
  return typeof value === 'string' ? value : undefined
}

function deviceOutcome(value: string | undefined): DeviceOutcome | undefined {
  return value === 'approved' || value === 'denied' ? value : undefined
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

const loadDevicePage = createServerFn({ method: 'GET' })
  .validator((data: { userCode: string; loginId: string; uiLocales?: string }) => data)
  .handler(async ({ data }) => {
    const flash = consumeFormFlash('/device')
    const loginId = data.loginId || flash?.values.login_id || ''
    const uiLocales = data.uiLocales ?? ''
    const locale = requestLocale(uiLocales.split(' '))
    const codeError =
      flash?.fields?.user_code ??
      (flash?.field === 'user_code' ? flash.message : undefined)
    const pageError = codeError ? undefined : flash?.message

    // Without a bound interaction the page is the code form. A code carried
    // by the link (`verification_uri_complete`) is only prefilled: the user
    // must confirm it matches the device before the request is started, so a
    // link sent by someone else cannot start a sign-in by being opened.
    if (!loginId) {
      return {
        device: undefined,
        userCode: flash?.values.user_code || data.userCode,
        prefilled: !flash && !!data.userCode,
        locale,
        uiLocales,
        error: pageError,
        codeError,
      }
    }

    const lookup = await loadDeviceVerification(loginId, locale)
    return {
      device: lookup.status === 'described' ? lookup.description : undefined,
      userCode: '',
      prefilled: false,
      locale,
      uiLocales,
      error: pageError ?? (lookup.status === 'failed' ? lookup.message : undefined),
      codeError,
    }
  })

export const Route = createFileRoute('/device')({
  validateSearch: (search): DeviceSearch => ({
    login_id: optionalString(search.login_id),
    user_code: optionalString(search.user_code),
    done: optionalString(search.done),
    error: optionalString(search.error),
    ui_locales: optionalString(search.ui_locales),
  }),
  loaderDeps: ({ search }) => ({
    loginId: search.login_id ?? '',
    userCode: search.user_code ?? '',
    uiLocales: search.ui_locales,
  }),
  loader: ({ deps }) => {
    return loadDevicePage({ data: deps })
  },
  server: {
    handlers: {
      POST: async ({ request }) => {
        const form = await request.formData()
        const locale = formLocale(request, form.get('ui_locales'))
        const uiLocales = optionalString(form.get('ui_locales'))
        const code = String(form.get('user_code') ?? '').trim()
        const loginId = String(form.get('login_id') ?? '')

        // The entered code is resolved here so a code that matches no request
        // is reported on the entry form itself, instead of sending the browser
        // to a page that can only ask it to sign in.
        if (form.get('intent') === 'enter-code') {
          const values = { user_code: code, ui_locales: uiLocales }
          if (!code) {
            return formErrorResponse(
              request,
              '/device',
              translate(locale, 'missingDeviceCode'),
              { ui_locales: uiLocales },
              'user_code',
            )
          }

          const lookup = await beginDeviceVerification(code, locale, uiLocales)
          if (lookup.status === 'unknown') {
            return formErrorResponse(
              request,
              '/device',
              translate(locale, 'deviceCodeInvalid'),
              values,
              'user_code',
            )
          }
          if (lookup.status === 'failed') {
            return formErrorResponse(request, '/device', lookup.message, values)
          }

          return navigationResponse(request, lookup.loginUri)
        }

        const decision = form.get('decision') === 'deny' ? 'deny' : 'approve'
        if (!loginId) {
          return formErrorResponse(
            request,
            '/device',
            translate(locale, 'missingConsentShort'),
            { ui_locales: uiLocales },
          )
        }

        try {
          const result = await decideDeviceVerification(
            loginId,
            decision,
            String(form.get('csrf_token') ?? ''),
          )
          const outcome = deviceOutcome(result.status)
          if (!outcome) {
            throw new LocalizedError(translate(locale, 'deviceDecisionUnknown'))
          }

          return navigationResponse(
            request,
            `/device?done=${outcome}${uiLocales ? `&ui_locales=${encodeURIComponent(uiLocales)}` : ''}`,
          )
        } catch (error) {
          return formErrorResponse(
            request,
            '/device',
            errorMessage(error, locale),
            { login_id: loginId, ui_locales: uiLocales },
            undefined,
            deviceInteractionPath(loginId, uiLocales),
          )
        }
      },
    },
  },
  component: DevicePage,
})

function DevicePage() {
  const search = Route.useSearch()
  const data = Route.useLoaderData()
  const device = data.device
  const outcome =
    deviceOutcome(search.done) ?? (device ? decidedOutcome(device.status) : undefined)
  const visibleError = search.error ?? data.error
  const t = (key: Parameters<typeof translate>[1], values?: Record<string, string | number>) =>
    translate(data.locale, key, values)

  if (outcome) {
    const titles = {
      approved: 'deviceApprovedTitle',
      denied: 'deviceDeniedTitle',
      expired: 'deviceExpiredTitle',
    } as const
    const descriptions = {
      approved: 'deviceApprovedDescription',
      denied: 'deviceDeniedDescription',
      expired: 'deviceExpiredDescription',
    } as const
    const OutcomeIcon = outcome === 'approved' ? Check : outcome === 'denied' ? X : Clock

    return (
      <AuthShell
        lang={data.locale}
        locale={data.locale}
        showPreferences
        title={t(titles[outcome])}
        description={t(descriptions[outcome])}
        compact
        titleIcon={<OutcomeIcon className="size-6" aria-hidden="true" />}
      >
        {null}
      </AuthShell>
    )
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
        message={t(device.consent_required ? 'revoke' : 'deviceTrustedClient')}
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
  locale: Parameters<typeof translate>[0]
  uiLocales: string
  userCode: string
  prefilled: boolean
  error?: string
  codeError?: string
}) {
  const [fieldError, setFieldError] = useState(codeError)
  const t = (key: Parameters<typeof translate>[1], values?: Record<string, string | number>) =>
    translate(locale, key, values)

  return (
    <AuthShell
      lang={locale}
      locale={locale}
      showPreferences
      title={t('deviceTitle')}
      description={t(prefilled ? 'deviceConfirmCodeDescription' : 'deviceDescription')}
    >
      {error ? <DeviceError title={t('deviceLoadFailed')} message={error} /> : null}
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
            <FieldLabel htmlFor="device-user-code">{t('deviceCodeLabel')}</FieldLabel>
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
            {fieldError ? <FieldError id="device-user-code-error">{fieldError}</FieldError> : null}
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
