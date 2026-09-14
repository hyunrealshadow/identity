import { Alert, Chip, FieldError, Label, TextField } from '@heroui/react'
import { createFileRoute } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { Check, ExternalLink } from 'lucide-react'
import { useState } from 'react'

import { AuthShell } from '#/components/auth-shell'
import { ProgressiveForm } from '#/components/progressive-form'
import { SubmitButton } from '#/components/submit-button'
import { GroupedCodeInput } from '#/components/totp-input'
import {
  errorMessage,
  IdentityApiError,
  identityJson,
} from '#/lib/identity.server'
import type {
  ConsentApiResponse,
  DeviceVerificationPageData,
} from '#/lib/identity-types'
import {
  consumeFormFlash,
  formErrorResponse,
  navigationResponse,
} from '#/lib/responses.server'
import { scopeDescription, translate } from '#/lib/i18n'
import { formLocale, requestLocale } from '#/lib/i18n.server'

/** Error code the identity service answers with when the browser is signed out. */
const LOGIN_REQUIRED = 26022

interface DeviceSearch {
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

function devicePath(userCode: string, uiLocales?: string) {
  const search = new URLSearchParams()
  if (userCode) search.set('user_code', userCode)
  if (uiLocales) search.set('ui_locales', uiLocales)
  return search.size ? `/device?${search}` : '/device'
}

/// A link into the sign-in flow, which is itself an authorization request.
async function signInLinkIfNeeded(
  error: unknown,
  userCode: string,
  uiLocales: string,
) {
  if (!(error instanceof IdentityApiError) || error.code !== LOGIN_REQUIRED) {
    return undefined
  }

  const { startSignIn } = await import('#/lib/oauth.server')

  return (await startSignIn(devicePath(userCode, uiLocales))).toString()
}

const loadDevicePage = createServerFn({ method: 'GET' })
  .validator((data: { userCode: string; uiLocales?: string }) => data)
  .handler(async ({ data }) => {
    const flash = consumeFormFlash('/device')
    const userCode = data.userCode || flash?.values.user_code || ''
    const uiLocales = data.uiLocales || flash?.values.ui_locales || ''
    const codeError =
      flash?.fields?.user_code ??
      (flash?.field === 'user_code' ? flash.message : undefined)
    const pageError = codeError ? undefined : flash?.message

    if (!userCode) {
      const locale = requestLocale(uiLocales.split(' '))
      return {
        device: undefined,
        signInHref: undefined,
        userCode,
        needsSignIn: false,
        locale,
        uiLocales,
        error: pageError,
        codeError,
      }
    }

    try {
      const device = await identityJson<DeviceVerificationPageData>(
        `/oauth2/consent?user_code=${encodeURIComponent(userCode)}`,
      )
      return {
        device,
        signInHref: undefined,
        userCode: device.user_code,
        needsSignIn: false,
        locale: requestLocale(
          uiLocales ? uiLocales.split(' ') : device.ui_locales,
        ),
        uiLocales,
        error: pageError,
        codeError,
      }
    } catch (error) {
      const locale = requestLocale(uiLocales.split(' '))
      return {
        device: undefined,
        userCode,
        // The browser has no session yet: the page offers to sign in and come
        // back to this same code instead of reporting a failure.
        needsSignIn:
          error instanceof IdentityApiError && error.code === LOGIN_REQUIRED,
        // The sign-in itself is an authorization flow: hand the page a link
        // into it so the button works even before hydration.
        signInHref: await signInLinkIfNeeded(error, userCode, uiLocales),
        locale,
        uiLocales,
        error: pageError ?? errorMessage(error, locale),
        codeError,
      }
    }
  })

export const Route = createFileRoute('/device')({
  validateSearch: (search): DeviceSearch => ({
    user_code: optionalString(search.user_code),
    done: optionalString(search.done),
    error: optionalString(search.error),
    ui_locales: optionalString(search.ui_locales),
  }),
  loaderDeps: ({ search }) => ({
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

        // The code entry form only routes to the verification page; the
        // identity service owns normalization and lookup.
        if (form.get('intent') === 'enter-code') {
          if (!code) {
            return formErrorResponse(
              request,
              '/device',
              translate(locale, 'missingDeviceCode'),
              { ui_locales: uiLocales },
              'user_code',
            )
          }

          return navigationResponse(request, devicePath(code, uiLocales))
        }

        const decision = form.get('decision') === 'deny' ? 'deny' : 'approve'
        if (!code) {
          return formErrorResponse(
            request,
            '/device',
            translate(locale, 'missingDeviceCodeShort'),
            { ui_locales: uiLocales },
          )
        }

        try {
          const result = await identityJson<ConsentApiResponse>(
            '/oauth2/consent',
            {
              method: 'POST',
              csrfToken: String(form.get('csrf_token') ?? ''),
              body: { user_code: code, decision },
            },
          )
          const outcome = deviceOutcome(result.status)
          if (!outcome) {
            throw new Error(translate(locale, 'deviceDecisionUnknown'))
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
            { user_code: code, ui_locales: uiLocales },
            undefined,
            devicePath(code, uiLocales),
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
    const labels = {
      approved: 'deviceApproved',
      denied: 'deviceDenied',
      expired: 'deviceExpired',
    } as const

    return (
      <AuthShell
        lang={data.locale}
        locale={data.locale}
        showPreferences
        title={t(titles[outcome])}
        description={t(descriptions[outcome])}
      >
        <Chip size="lg" variant="soft" className="mx-auto mt-2 flex w-fit">
          {t(labels[outcome])}
        </Chip>
      </AuthShell>
    )
  }

  if (data.needsSignIn) {
    return (
      <AuthShell
        lang={data.locale}
        locale={data.locale}
        showPreferences
        title={t('deviceSignInTitle')}
        description={t('deviceSignInDescription')}
      >
        <a
          href={data.signInHref}
          className="flex min-h-11 w-full items-center justify-center rounded-field bg-accent px-4 text-sm font-semibold text-accent-foreground transition-opacity hover:opacity-90"
        >
          {t('deviceSignIn')}
        </a>
        <p className="mt-4 text-center text-xs leading-5 text-muted">
          {t('deviceCodeKept', { code: data.userCode })}
        </p>
      </AuthShell>
    )
  }

  if (!device) {
    return (
      <CodeEntryPage
        locale={data.locale}
        uiLocales={data.uiLocales}
        userCode={data.userCode}
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

      <div className="mb-5 rounded-xl border border-border bg-surface-secondary p-4">
        <div className="flex items-center gap-3">
          {device.logo_uri ? (
            <img
              src={device.logo_uri}
              alt=""
              className="size-10 shrink-0 rounded-xl object-contain"
              referrerPolicy="no-referrer"
            />
          ) : null}
          <div className="min-w-0">
            <p className="font-semibold">{device.client_name}</p>
            {device.client_uri ? (
              <a
                href={device.client_uri}
                target="_blank"
                rel="noreferrer"
                className="mt-1 inline-flex items-center gap-1 truncate text-xs font-medium text-accent hover:underline"
              >
                {device.client_uri}
                <ExternalLink className="size-3" aria-hidden="true" />
              </a>
            ) : null}
          </div>
        </div>
        <p className="mt-4 text-xs font-medium uppercase tracking-wide text-muted">
          {t('deviceCodeLabel')}
        </p>
        <p className="mt-1 font-mono text-2xl font-semibold tracking-[0.2em]">
          {device.user_code}
        </p>
      </div>

      <section aria-labelledby="device-permissions-title">
        <div className="mb-3 flex items-center justify-between gap-3">
          <h2 id="device-permissions-title" className="text-sm font-semibold">
            {t('permissions')}
          </h2>
          <Chip size="sm" variant="soft">
            {t('permissionCount', { count: device.scopes.length })}
          </Chip>
        </div>
        <ul className="auth-stagger-fast space-y-2">
          {device.scopes.map((scope) => (
            <li
              key={scope.name}
              className="flex gap-3 rounded-xl border border-border px-3 py-3 transition-colors duration-200 hover:bg-surface-secondary"
            >
              <Check
                className="mt-0.5 size-4 shrink-0 text-accent"
                aria-hidden="true"
              />
              <span className="min-w-0">
                <span className="flex items-center gap-2 text-sm font-semibold">
                  {scope.name}
                  {scope.essential ? (
                    <Chip size="sm" variant="soft">
                      {t('required')}
                    </Chip>
                  ) : null}
                </span>
                <span className="mt-0.5 block text-xs leading-5 text-muted">
                  {scopeDescription(data.locale, scope.name, scope.description)}
                </span>
              </span>
            </li>
          ))}
        </ul>
      </section>

      <ProgressiveForm
        action="/device"
        className="progressive-form mt-6 grid grid-cols-2 gap-3"
        enhancementErrorMessage={t('enhancedNavigationError')}
      >
        <input type="hidden" name="user_code" value={device.user_code} />
        <input type="hidden" name="csrf_token" value={device.csrf_token} />
        {data.uiLocales ? (
          <input type="hidden" name="ui_locales" value={data.uiLocales} />
        ) : null}
        <SubmitButton fullWidth name="decision" value="deny" variant="secondary">
          {t('deny')}
        </SubmitButton>
        <SubmitButton fullWidth name="decision" value="approve">
          {t('allow')}
        </SubmitButton>
      </ProgressiveForm>

      <p className="mt-5 text-center text-xs leading-5 text-muted">
        {t('deviceVerifyHint')}
      </p>
    </AuthShell>
  )
}

function CodeEntryPage({
  locale,
  uiLocales,
  userCode,
  error,
  codeError,
}: {
  locale: Parameters<typeof translate>[0]
  uiLocales: string
  userCode: string
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
      description={t('deviceDescription')}
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
        <div className="grid gap-2">
          <TextField isRequired fullWidth name="user_code" isInvalid={!!fieldError}>
            <Label>{t('deviceCodeLabel')}</Label>
            <GroupedCodeInput
              name="user_code"
              type="text"
              required
              autoFocus
              defaultValue={userCode}
              className="w-full"
              groupClassName="w-full justify-between"
              slotClassName="flex-none"
              onChange={() => setFieldError(undefined)}
            />
          </TextField>
          <FieldError>{fieldError}</FieldError>
        </div>
        <SubmitButton fullWidth>{t('deviceSubmit')}</SubmitButton>
      </ProgressiveForm>
    </AuthShell>
  )
}

function DeviceError({ message, title }: { message: string; title: string }) {
  return (
    <Alert status="danger" className="auth-alert mb-5">
      <Alert.Indicator />
      <Alert.Content>
        <Alert.Title>{title}</Alert.Title>
        <Alert.Description>{message}</Alert.Description>
      </Alert.Content>
    </Alert>
  )
}
