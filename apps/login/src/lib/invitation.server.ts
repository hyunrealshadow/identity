import { identityInternalJson, IdentityApiError } from './identity.server'
import type { InvitationAcceptResponse, InvitationCheckResponse } from './identity-types'
import type { Locale } from './i18n'

/** Error code of an invitation link that is unknown, expired, used, or no
    longer matches its account. */
export const INVITATION_LINK_INVALID = 11038

/**
 * The account an invitation link belongs to, without using the link.
 * Holding the link proves control of the mailbox, so no session is needed;
 * the token only travels from this server to Identity's private listener.
 */
export async function checkInvitation(token: string, locale: Locale) {
  return identityInternalJson<InvitationCheckResponse>('/internal/invitation/check', {
    method: 'POST',
    body: { token },
    locale,
  })
}

/** Set the first password of an invited account. */
export async function acceptInvitation(token: string, newPassword: string, locale: Locale) {
  return identityInternalJson<InvitationAcceptResponse>('/internal/invitation/accept', {
    method: 'POST',
    body: { token, new_password: newPassword },
    locale,
  })
}

/** Whether retrying the same link cannot succeed. */
export function isFinalInvitationError(error: unknown) {
  return error instanceof IdentityApiError && error.code === INVITATION_LINK_INVALID
}
