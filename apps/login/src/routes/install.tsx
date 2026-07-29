import { Alert, FieldError, Input, Label, TextField } from '@heroui/react'
import { createFileRoute } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'

import { AuthShell } from '#/components/auth-shell'
import { ProgressiveForm } from '#/components/progressive-form'
import { SubmitButton } from '#/components/submit-button'
import { errorMessage, identityJson } from '#/lib/identity.server'
import type { InstallResponse } from '#/lib/identity-types'
import { translate } from '#/lib/i18n'
import { formLocale, requestLocale } from '#/lib/i18n.server'
import {
  consumeFormFlash,
  formErrorResponse,
  navigationResponse,
} from '#/lib/responses.server'

interface InstallSearch {
  error?: string
  username?: string
  email?: string
  domain?: string
}

function optionalString(value: unknown) {
  return typeof value === 'string' ? value : undefined
}

const loadInstallPage = createServerFn({ method: 'GET' }).handler(async () => {
  const flash = consumeFormFlash('/install')
  return {
    locale: requestLocale(),
    error: flash?.field ? undefined : flash?.message,
    fieldError: flash?.field ? { name: flash.field, message: flash.message } : undefined,
    formValues: flash?.values ?? {},
  }
})

export const Route = createFileRoute('/install')({
  validateSearch: (search): InstallSearch => ({
    error: optionalString(search.error),
    username: optionalString(search.username),
    email: optionalString(search.email),
    domain: optionalString(search.domain),
  }),
  loader: () => loadInstallPage(),
  server: {
    handlers: {
      POST: async ({ request }) => {
        const form = await request.formData()
        const username = String(form.get('username') ?? '').trim()
        const email = String(form.get('email') ?? '').trim()
        const domain = String(form.get('domain') ?? '').trim()
        const password = String(form.get('password') ?? '')
        const confirmPassword = String(form.get('confirm_password') ?? '')
        const values = { username, email, domain }
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
          await identityJson<InstallResponse>('/install', {
            method: 'POST',
            body: {
              username,
              email,
              password,
              domain,
              key_algorithm: String(
                form.get('key_algorithm') ?? 'ecdsa-p256',
              ),
            },
          })
          return navigationResponse(request, '/')
        } catch (error) {
          return formErrorResponse(
            request,
            '/install',
            errorMessage(error),
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
  const { locale, error, fieldError, formValues } = Route.useLoaderData()
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
      >
        <TextField isRequired fullWidth name="domain">
          <Label>{t('installIdentityUrl')}</Label>
          <Input
            autoFocus
            defaultValue={
              formValues.domain ?? search.domain ?? 'https://localhost:5150'
            }
            inputMode="url"
            placeholder="https://id.example.com"
          />
        </TextField>

        <TextField isRequired fullWidth name="username">
          <Label>{t('installAdminUsername')}</Label>
          <Input
            autoComplete="username"
            defaultValue={formValues.username ?? search.username}
            placeholder="admin"
          />
        </TextField>

        <TextField isRequired fullWidth name="email">
          <Label>{t('installAdminEmail')}</Label>
          <Input
            autoComplete="email"
            defaultValue={formValues.email ?? search.email}
            inputMode="email"
            placeholder="admin@example.com"
          />
        </TextField>

        <TextField isRequired fullWidth name="password">
          <Label>{t('installPassword')}</Label>
          <Input autoComplete="new-password" type="password" />
        </TextField>

        <TextField
          isRequired
          fullWidth
          name="confirm_password"
          isInvalid={fieldError?.name === 'confirm_password'}
        >
          <Label>{t('installConfirmPassword')}</Label>
          <Input autoComplete="new-password" type="password" />
          <FieldError>
            {fieldError?.name === 'confirm_password' ? fieldError.message : undefined}
          </FieldError>
        </TextField>

        <input type="hidden" name="key_algorithm" value="ecdsa-p256" />

        <SubmitButton fullWidth>{t('installSubmit')}</SubmitButton>
      </ProgressiveForm>
    </AuthShell>
  )
}
