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
}

function optionalString(value: unknown) {
  return typeof value === 'string' ? value : undefined
}

function destination(token: string) {
  return `${PATH}?${new URLSearchParams({ token })}`
}

const loadInvitationPage = createServerFn({ method: 'GET' })
  .validator((data: { token: string }) => data)
  .handler(async ({ data }) => {
    const flash = consumeFormFlash(PATH)
    const locale = requestLocale()
    const page = {
      locale,
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
  }),
  loaderDeps: ({ search }) => ({ token: search.token ?? '' }),
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
        const locale = formLocale(request, null)
        const token = String(form.get('token') ?? '').trim()
        if (!token) {
          return formErrorResponse(request, PATH, translate(locale, 'invitationNoLinkDescription'), {})
        }
        const newPassword = String(form.get('new_password') ?? '')
        const confirmPassword = String(form.get('confirm_password') ?? '')
        if (!newPassword) {
          const message = translate(locale, 'challengeRequired')
          return formValidationErrorResponse(request, PATH, message, {}, { new_password: message }, destination(token))
        }
        if (newPassword !== confirmPassword) {
          const message = translate(locale, 'accountPasswordMismatch')
          return formValidationErrorResponse(request, PATH, message, {}, { confirm_password: message }, destination(token))
        }
        try {
          await acceptInvitation(token, newPassword, locale)
          return navigationResponse(request, `${PATH}/accepted`)
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
              destination(token),
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
            isFinalInvitationError(error) ? PATH : destination(token),
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
            noValidate
          >
            <input type="hidden" name="token" value={data.token} />
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
