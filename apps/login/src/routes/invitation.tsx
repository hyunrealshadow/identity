import { createFileRoute } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { UserPlus } from 'lucide-react'

import { AccountAvatar } from '#/components/account-avatar'
import { AuthShell } from '#/components/auth-shell'
import { ErrorAlert } from '#/components/form-alert'
import { ProgressiveForm } from '#/components/progressive-form'
import { SubmitButton } from '#/components/submit-button'
import { TextField } from '#/components/text-field'
import { errorMessage, IdentityApiError } from '#/lib/identity.server'
import type { InvitationCheckResponse } from '#/lib/identity-types'
import { translate } from '#/lib/i18n'
import { formLocale, requestLocale } from '#/lib/i18n.server'
import { acceptInvitation, checkInvitation, isFinalInvitationError } from '#/lib/invitation.server'
import {
  consumeFormFlash,
  formErrorResponse,
  formValidationErrorResponse,
  navigationResponse,
} from '#/lib/responses.server'

const PATH = '/invitation'

interface InvitationSearch {
  token?: string
  ui_locales?: string
}

function optionalString(value: unknown) {
  return typeof value === 'string' ? value : undefined
}

function destination(token: string, uiLocales?: string) {
  const search = new URLSearchParams({ token })
  if (uiLocales && uiLocales !== 'browser') search.set('ui_locales', uiLocales)
  return `${PATH}?${search}`
}

function acceptedDestination(uiLocales?: string) {
  if (!uiLocales || uiLocales === 'browser') return `${PATH}/accepted`
  return `${PATH}/accepted?${new URLSearchParams({ ui_locales: uiLocales })}`
}

const loadInvitationPage = createServerFn({ method: 'GET' })
  .validator((data: { token: string; uiLocales?: string }) => data)
  .handler(async ({ data }) => {
    const flash = consumeFormFlash(PATH)
    const uiLocales = data.uiLocales ?? ''
    const locale = requestLocale(uiLocales.split(' '))
    const page = {
      locale,
      uiLocales,
      token: data.token,
      account: undefined as InvitationCheckResponse | undefined,
      error: flash?.fields ? undefined : flash?.message,
      fields: flash?.fields ?? {},
      linkError: undefined as string | undefined,
    }
    if (!data.token) return page
    try {
      page.account = await checkInvitation(data.token, locale)
    } catch (error) {
      page.linkError = errorMessage(error, locale)
    }
    return page
  })

/**
 * Where an emailed invitation link lands. Opening the link only shows the
 * account; the password is set when the form is submitted, so a mail
 * scanner that fetches the link cannot use it. No session is needed, so the
 * link also works on another device.
 */
export const Route = createFileRoute('/invitation')({
  validateSearch: (search): InvitationSearch => ({
    token: optionalString(search.token),
    ui_locales: optionalString(search.ui_locales),
  }),
  loaderDeps: ({ search }) => ({ token: search.token ?? '', uiLocales: search.ui_locales }),
  loader: ({ deps }) => loadInvitationPage({ data: deps }),
  headers: () => ({
    'Cache-Control': 'no-store',
    // The token is in this page's address; never pass it on.
    'Referrer-Policy': 'no-referrer',
  }),
  server: {
    handlers: {
      POST: async ({ request }) => {
        const form = await request.formData()
        const uiLocalesEntry = form.get('ui_locales')
        const uiLocales = typeof uiLocalesEntry === 'string' ? uiLocalesEntry.trim() : ''
        const locale = formLocale(request, uiLocalesEntry)
        const token = String(form.get('token') ?? '').trim()
        const errorPath = uiLocales && uiLocales !== 'browser'
          ? `${PATH}?${new URLSearchParams({ ui_locales: uiLocales })}`
          : PATH
        if (!token) {
          return formErrorResponse(
            request,
            PATH,
            translate(locale, 'invitationNoLinkDescription'),
            {},
            undefined,
            errorPath,
          )
        }
        const newPassword = String(form.get('new_password') ?? '')
        const confirmPassword = String(form.get('confirm_password') ?? '')
        const retryUrl = destination(token, uiLocales)
        if (!newPassword) {
          const message = translate(locale, 'challengeRequired')
          return formValidationErrorResponse(request, PATH, message, {}, { new_password: message }, retryUrl)
        }
        if (newPassword !== confirmPassword) {
          const message = translate(locale, 'accountPasswordMismatch')
          return formValidationErrorResponse(request, PATH, message, {}, { confirm_password: message }, retryUrl)
        }
        try {
          await acceptInvitation(token, newPassword, locale)
          return navigationResponse(request, acceptedDestination(uiLocales))
        } catch (error) {
          if (error instanceof IdentityApiError && error.fields.length > 0) {
            return formValidationErrorResponse(
              request,
              PATH,
              error.message,
              {},
              Object.fromEntries(
                error.fields.map((field) => [
                  field.field === 'newPassword' ? 'new_password' : field.field,
                  field.message,
                ]),
              ),
              retryUrl,
            )
          }
          // A link that can never work is not offered again; a transient
          // failure keeps it so the user can retry.
          return formErrorResponse(
            request,
            PATH,
            errorMessage(error, locale),
            {},
            undefined,
            isFinalInvitationError(error) ? errorPath : retryUrl,
          )
        }
      },
    },
  },
  component: InvitationPage,
})

function InvitationPage() {
  const data = Route.useLoaderData()
  const t = (key: Parameters<typeof translate>[1]) => translate(data.locale, key)
  const account = data.account

  return (
    <AuthShell
      lang={data.locale}
      locale={data.locale}
      showPreferences
      title={t('invitationTitle')}
      description={t(account ? 'invitationDescription' : 'invitationNoLinkDescription')}
      titleIcon={<UserPlus className="size-6" aria-hidden="true" />}
    >
      {data.linkError ? (
        <ErrorAlert className="mb-5" title={t('invitationLinkFailed')} message={data.linkError} />
      ) : data.error ? (
        <ErrorAlert className="mb-5" message={data.error} />
      ) : null}
      {account ? (
        <>
          <div className="mb-6 flex items-center gap-3 rounded-xl border bg-muted/50 p-3">
            <AccountAvatar name={account.username} />
            <div className="min-w-0 flex-1">
              <p className="truncate text-sm font-semibold">{account.username}</p>
              <p className="truncate text-xs text-muted-foreground">{account.email}</p>
            </div>
          </div>
          <ProgressiveForm
            action={PATH}
            className="progressive-form space-y-6"
            enhancementErrorMessage={t('enhancedNavigationError')}
            validationErrors={data.fields}
            noValidate
          >
            <input type="hidden" name="token" value={data.token} />
            <input type="hidden" name="ui_locales" value={data.uiLocales} />
            {/* Lets password managers save the new password for this account. */}
            <input type="hidden" name="username" value={account.username} autoComplete="username" />
            <TextField
              required
              name="new_password"
              label={t('accountNewPassword')}
              error={data.fields.new_password}
              autoFocus
              type="password"
              autoComplete="new-password"
              reveal={{ show: t('showPassword'), hide: t('hidePassword') }}
            />
            <TextField
              required
              name="confirm_password"
              label={t('accountConfirmPassword')}
              error={data.fields.confirm_password}
              type="password"
              autoComplete="new-password"
            />
            <SubmitButton fullWidth>{t('invitationSubmit')}</SubmitButton>
          </ProgressiveForm>
        </>
      ) : null}
    </AuthShell>
  )
}
