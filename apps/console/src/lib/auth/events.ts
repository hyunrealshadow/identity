export const BEFORE_AUTH_REDIRECT_EVENT = 'identity.console.before-auth-redirect'
export const AUTH_LOGOUT_EVENT = 'identity.console.auth-logout'

/**
 * Dispatched synchronously while the previous in-memory session is still
 * readable. It must never carry tokens, credentials or form payloads.
 */
export function emitBeforeAuthRedirect(): void {
  if (typeof window === 'undefined') return
  try {
    window.dispatchEvent(new Event(BEFORE_AUTH_REDIRECT_EVENT))
  } catch {
    // Draft preservation is best effort; authentication navigation continues.
  }
}

/**
 * Dispatched only for an explicit sign-out, before the scoped session is
 * cleared. Expiry and reauthentication deliberately use the redirect event.
 */
export function emitAuthLogout(): void {
  if (typeof window === 'undefined') return
  try {
    window.dispatchEvent(new Event(AUTH_LOGOUT_EVENT))
  } catch {
    // A blocked listener must not prevent the local sign-out.
  }
}
