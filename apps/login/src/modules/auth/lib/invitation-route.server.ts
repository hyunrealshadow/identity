import { errorMessage, IdentityApiError } from '#/lib/identity.server'
import { translate } from '#/lib/i18n'
import { formLocale } from '#/lib/i18n.server'
import {
  formErrorResponse,
  formValidationErrorResponse,
  navigationResponse,
} from '#/lib/responses.server'
import {
  acceptInvitation,
  isFinalInvitationError,
} from '#/modules/auth/lib/invitation.server'

export const INVITATION_PATH = '/invitation'

function destination(token: string, uiLocales?: string) {
  const search = new URLSearchParams({ token })
  if (uiLocales && uiLocales !== 'browser') search.set('ui_locales', uiLocales)
  return `${INVITATION_PATH}?${search}`
}

function acceptedDestination(uiLocales?: string) {
  if (!uiLocales || uiLocales === 'browser') return `${INVITATION_PATH}/accepted`
  return `${INVITATION_PATH}/accepted?${new URLSearchParams({ ui_locales: uiLocales })}`
}

export async function submitInvitationPost(request: Request) {
  const form = await request.formData()
  const uiLocalesEntry = form.get('ui_locales')
  const uiLocales =
    typeof uiLocalesEntry === 'string' ? uiLocalesEntry.trim() : ''
  const locale = formLocale(request, uiLocalesEntry)
  const token = String(form.get('token') ?? '').trim()
  const errorPath =
    uiLocales && uiLocales !== 'browser'
      ? `${INVITATION_PATH}?${new URLSearchParams({ ui_locales: uiLocales })}`
      : INVITATION_PATH
  if (!token) {
    return formErrorResponse(
      request,
      INVITATION_PATH,
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
    return formValidationErrorResponse(
      request,
      INVITATION_PATH,
      message,
      {},
      { new_password: message },
      retryUrl,
    )
  }
  if (newPassword !== confirmPassword) {
    const message = translate(locale, 'accountPasswordMismatch')
    return formValidationErrorResponse(
      request,
      INVITATION_PATH,
      message,
      {},
      { confirm_password: message },
      retryUrl,
    )
  }
  try {
    await acceptInvitation(token, newPassword, locale)
    return navigationResponse(request, acceptedDestination(uiLocales))
  } catch (error) {
    if (error instanceof IdentityApiError && error.fields.length > 0) {
      return formValidationErrorResponse(
        request,
        INVITATION_PATH,
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
      INVITATION_PATH,
      errorMessage(error, locale),
      {},
      undefined,
      isFinalInvitationError(error) ? errorPath : retryUrl,
    )
  }
}
