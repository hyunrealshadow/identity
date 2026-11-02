import { Alert, FieldError, Input, Label, TextField } from '@heroui/react'
import { createFileRoute } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { getRequest } from '@tanstack/react-start/server'

import { AuthShell } from '#/components/auth-shell'
import { ProgressiveForm } from '#/components/progressive-form'
import { SubmitButton } from '#/components/submit-button'
import {
  errorMessage,
  IdentityApiError,
  identityInternalJson,
} from '#/lib/identity.server'
import type { InstallResponse } from '#/lib/identity-types'
import { markInstallationComplete } from '#/lib/installation-status.server'
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
])

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
  return {
    // Draft defaults only: submitted addresses are validated and persisted by Identity.
    defaults: {
      domain: development ? 'https://localhost:5150' : url.origin,
      application_url: development ? 'https://localhost:3000' : url.origin,
      console_url: development ? 'https://localhost:3100/console/' : `${url.origin}/console/`,
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
              key_algorithm: String(
                form.get('key_algorithm') ?? 'ecdsa-p256',
              ),
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
  const { locale, error, fieldErrors, formValues, defaults } = Route.useLoaderData()
  const t = (key: Parameters<typeof translate>[1]) => translate(locale, key)

  return (
    <AuthShell
      lang={locale}
      title={t('installTitle')}
      description={t('installDescription')}
    >
      {error ? (
        <Alert
          status="danger"
          className="auth-alert mb-5"
        >
          <Alert.Indicator />
          <Alert.Content>
            <Alert.Title>{t('installFailed')}</Alert.Title>
            <Alert.Description>{error}</Alert.Description>
          </Alert.Content>
        </Alert>
      ) : null}

      <ProgressiveForm
        action="/install"
        className="progressive-form space-y-5"
        enhancementErrorMessage={t('installNavigationError')}
        validationErrors={fieldErrors}
      >
        <TextField
          isRequired
          fullWidth
          name="domain"
          defaultValue={formValues.domain ?? search.domain ?? defaults.domain}
        >
          <Label>{t('installIdentityUrl')}</Label>
          <Input
            autoFocus
            inputMode="url"
            placeholder="https://id.example.com"
          />
          <FieldError />
        </TextField>

        <TextField
          isRequired
          fullWidth
          name="application_url"
          defaultValue={formValues.application_url ?? search.application_url ?? defaults.application_url}
        >
          <Label>{t('installApplicationUrl')}</Label>
          <Input
            inputMode="url"
            placeholder="https://login.example.com"
          />
          <FieldError />
        </TextField>

        <TextField
          isRequired
          fullWidth
          name="console_url"
          defaultValue={formValues.console_url ?? search.console_url ?? defaults.console_url}
        >
          <Label>{t('installConsoleUrl')}</Label>
          <Input
            inputMode="url"
            placeholder="https://login.example.com/console/"
          />
          <FieldError />
        </TextField>

        <TextField
          isRequired
          fullWidth
          name="username"
          defaultValue={formValues.username ?? search.username}
        >
          <Label>{t('installAdminUsername')}</Label>
          <Input
            autoComplete="username"
            placeholder="admin"
          />
          <FieldError />
        </TextField>

        <TextField
          isRequired
          fullWidth
          name="email"
          defaultValue={formValues.email ?? search.email}
        >
          <Label>{t('installAdminEmail')}</Label>
          <Input
            autoComplete="email"
            inputMode="email"
            placeholder="admin@example.com"
          />
          <FieldError />
        </TextField>

        <TextField
          isRequired
          fullWidth
          name="password"
          type="password"
        >
          <Label>{t('installPassword')}</Label>
          <Input autoComplete="new-password" type="password" />
          <FieldError />
        </TextField>

        <TextField
          isRequired
          fullWidth
          name="confirm_password"
          type="password"
        >
          <Label>{t('installConfirmPassword')}</Label>
          <Input autoComplete="new-password" type="password" />
          <FieldError />
        </TextField>

        <input type="hidden" name="key_algorithm" value="ecdsa-p256" />

        <SubmitButton fullWidth>{t('installSubmit')}</SubmitButton>
      </ProgressiveForm>
    </AuthShell>
  )
}
