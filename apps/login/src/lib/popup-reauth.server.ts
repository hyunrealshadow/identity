import { PASSKEY_MANAGEMENT_CONTINUATION } from './account-reauth'
import type { AccountReauthRequest } from './popup-reauth'
import { startPopupReauthorization } from './oauth.server'

/**
 * Passkey management authorizes through the same bounded reauthentication as
 * the rest of the account center, but resumes the passkey dialog.
 */
export function startPopupPasskeyReauth(requirements: {
  loginHint: string
  acrValues?: string
  maxAge?: number
}): Promise<AccountReauthRequest> {
  return startPopupReauthorization(
    PASSKEY_MANAGEMENT_CONTINUATION,
    'account',
    {
      loginHint: requirements.loginHint,
      acrValues: requirements.acrValues ?? 'aal1',
      maxAge: requirements.maxAge,
    },
  )
}

/**
 * The passkey service still emits the standard bounded reauthentication
 * redirect. Convert that server-generated redirect into the dialog request
 * without trusting anything else from it.
 */
export function startPopupPasskeyReauthFromRedirect(
  location?: string,
): Promise<AccountReauthRequest> | undefined {
  if (!location) return
  let url: URL
  try {
    url = new URL(location)
  } catch {
    return
  }
  if (!url.pathname.endsWith('/oauth2/authorize')) return
  const loginHint = url.searchParams.get('login_hint')
  if (!loginHint) return
  const rawMaxAge = url.searchParams.get('max_age')
  const maxAge = rawMaxAge === null ? undefined : Number(rawMaxAge)
  return startPopupPasskeyReauth({
    loginHint,
    acrValues: url.searchParams.get('acr_values') ?? undefined,
    maxAge: Number.isFinite(maxAge) ? maxAge : undefined,
  })
}
