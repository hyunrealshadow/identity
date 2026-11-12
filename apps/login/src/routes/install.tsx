import { createFileRoute } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { getRequest } from '@tanstack/react-start/server'

import { AuthShell } from '#/components/auth-shell'
import { ErrorAlert } from '#/components/form-alert'
import { ProgressiveForm } from '#/components/progressive-form'
import { SubmitButton } from '#/components/submit-button'
import { SigningAlgorithmField } from '#/components/signing-algorithm-field'
import { TextField } from '#/components/text-field'
import {
  errorMessage,
  IdentityApiError,
  identityInternalJson,
} from '#/lib/identity.server'
import type { InstallResponse } from '#/lib/identity-types'
import {
  cachedInstallationStatus,
  markInstallationComplete,
} from '#/lib/installation-status.server'
import { translate } from '#/lib/i18n'
import { formLocale, requestLocale } from '#/lib/i18n.server'
import {
  consumeFormFlash,
  formErrorResponse,
  formValidationErrorResponse,
  navigationResponse,
} from '#/lib/responses.server'

interface InstallSearch {
  error?: string
  username?: string
  email?: string
  domain?: string
  application_url?: string
  console_url?: string
}

const visibleInstallFields = new Set([
  'domain',
  'application_url',
  'console_url',
  'username',
  'email',
  'password',
  'confirm_password',
  'signing_algorithm',
])

/** Offered first: compact keys that every client library verifies. */
const DEFAULT_SIGNING_OPTION = 'ES256:ECDSA_P256'

function optionalString(value: unknown) {
  return typeof value === 'string' ? value : undefined
}

const loadInstallPage = createServerFn({ method: 'GET' }).handler(async () => {
  const flash = consumeFormFlash('/install')
  const hasUnmappedFieldError = Object.keys(flash?.fields ?? {}).some(
    (field) => !visibleInstallFields.has(field),
  )
  const url = new URL(getRequest().url)
  url.protocol = 'https:'
  const development = process.env.NODE_ENV === 'development'
  const status = await cachedInstallationStatus()
  return {
    signingAlgorithms: status.signing_algorithms ?? [],
    // Draft defaults only: submitted addresses are validated and persisted by Identity.
    defaults: {
      domain: development ? 'https://localhost:5150' : url.origin,
      application_url: development ? 'https://localhost:3000' : url.origin,
      console_url: development ? 'https://localhost:3100' : url.origin,
    },
    locale: requestLocale(),
    error:
      flash?.field || (flash?.fields && !hasUnmappedFieldError)
        ? undefined
        : flash?.message,
    fieldErrors: {
      ...(flash?.fields ?? {}),
      ...(flash?.field ? { [flash.field]: flash.message } : {}),
    },
    formValues: flash?.values ?? {},
  }
})

export const Route = createFileRoute('/install')({
  validateSearch: (search): InstallSearch => ({
    error: optionalString(search.error),
    username: optionalString(search.username),
    email: optionalString(search.email),
    domain: optionalString(search.domain),
    application_url: optionalString(search.application_url),
    console_url: optionalString(search.console_url),
  }),
  loader: () => loadInstallPage(),
  server: {
    handlers: {
      POST: async ({ request }) => {
        const form = await request.formData()
        const username = String(form.get('username') ?? '').trim()
        const email = String(form.get('email') ?? '').trim()
        const domain = String(form.get('domain') ?? '').trim()
        const applicationUrl = String(
          form.get('application_url') ?? '',
        ).trim()
        const consoleUrl = String(form.get('console_url') ?? '').trim()
        const password = String(form.get('password') ?? '')
        const confirmPassword = String(form.get('confirm_password') ?? '')
        const values = {
          username,
          email,
          domain,
          application_url: applicationUrl,
          console_url: consoleUrl,
          signing_option: `${String(form.get('signing_algorithm') ?? '')}:${String(form.get('key_algorithm') ?? '')}`,
        }
        const locale = formLocale(request, null)

        if (password !== confirmPassword) {
          return formErrorResponse(
            request,
            '/install',
            translate(locale, 'installPasswordMismatch'),
            values,
            'confirm_password',
          )
        }

        try {
          await identityInternalJson<InstallResponse>('/internal/installation', {
            method: 'POST',
            locale,
            body: {
              username,
              email,
              password,
              domain,
              application_url: applicationUrl,
              console_url: consoleUrl,
              // Enum values from the chosen option; Identity rejects others.
              signing_algorithm: String(form.get('signing_algorithm') ?? ''),
              key_algorithm: String(form.get('key_algorithm') ?? ''),
            },
          })
          markInstallationComplete()
          return navigationResponse(request, '/')
        } catch (error) {
          if (error instanceof IdentityApiError && error.fields.length > 0) {
            return formValidationErrorResponse(
              request,
              '/install',
              error.message,
              values,
              Object.fromEntries(
                error.fields.map((fieldError) => [
                  fieldError.field,
                  fieldError.message,
                ]),
              ),
            )
          }
          return formErrorResponse(
            request,
            '/install',
            errorMessage(error, locale),
            values,
          )
        }
      },
    },
  },
  component: InstallPage,
})

function InstallPage() {
  const search = Route.useSearch()
  const { locale, error, fieldErrors, formValues, defaults, signingAlgorithms } =
    Route.useLoaderData()
  const t = (key: Parameters<typeof translate>[1]) => translate(locale, key)

  return (
    <AuthShell
      lang={locale}
      title={t('installTitle')}
      description={t('installDescription')}
    >
      {error ? <ErrorAlert className="mb-5" title={t('installFailed')} message={error} /> : null}

      <ProgressiveForm
        action="/install"
        className="progressive-form space-y-5"
        enhancementErrorMessage={t('installNavigationError')}
        validationErrors={fieldErrors}
      >
        <TextField
          required
          name="domain"
          label={t('installIdentityUrl')}
          defaultValue={formValues.domain ?? search.domain ?? defaults.domain}
          autoFocus
          inputMode="url"
          placeholder="https://id.example.com"
        />
        <TextField
          required
          name="application_url"
          label={t('installApplicationUrl')}
          defaultValue={formValues.application_url ?? search.application_url ?? defaults.application_url}
          inputMode="url"
          placeholder="https://login.example.com"
        />
        <TextField
          required
          name="console_url"
          label={t('installConsoleUrl')}
          description={t('installConsoleOriginDescription')}
          defaultValue={formValues.console_url ?? search.console_url ?? defaults.console_url}
          inputMode="url"
          placeholder="https://login.example.com"
        />
        <TextField
          required
          name="username"
          label={t('installAdminUsername')}
          defaultValue={formValues.username ?? search.username}
          autoComplete="username"
          placeholder="admin"
        />
        <TextField
          required
          name="email"
          label={t('installAdminEmail')}
          defaultValue={formValues.email ?? search.email}
          autoComplete="email"
          inputMode="email"
          placeholder="admin@example.com"
        />
        <TextField
          required
          name="password"
          type="password"
          label={t('installPassword')}
          autoComplete="new-password"
        />
        <TextField
          required
          name="confirm_password"
          type="password"
          label={t('installConfirmPassword')}
          autoComplete="new-password"
        />

        <SigningAlgorithmField
          label={t('installSigningAlgorithm')}
          description={t('installSigningAlgorithmDescription')}
          options={signingAlgorithms}
          defaultValue={formValues.signing_option || DEFAULT_SIGNING_OPTION}
        />

        <SubmitButton fullWidth>{t('installSubmit')}</SubmitButton>
      </ProgressiveForm>
    </AuthShell>
  )
}
