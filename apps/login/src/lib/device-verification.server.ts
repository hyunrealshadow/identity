import { errorMessage, IdentityApiError, identityJson } from './identity.server'

import type { Locale } from './i18n'
import type {
  ConsentApiResponse,
  DeviceVerificationPageData,
} from './identity-types'

const DEVICE_CODE_UNKNOWN = 26010

type DeviceFailure =
  | { status: 'unknown' }
  | { status: 'failed'; message: string }

export type DeviceVerificationLookup =
  | { status: 'described'; description: DeviceVerificationPageData }
  | DeviceFailure

/** Validate the code before starting native login, without claiming or approving it. */
export async function beginDeviceVerification(
  userCode: string,
  locale: Locale,
  uiLocales?: string,
): Promise<{ status: 'login'; loginUri: string } | DeviceFailure> {
  try {
    const check = await identityJson<{ csrf_token: string }>(
      `/oauth2/consent?user_code=${encodeURIComponent(userCode)}`,
    )
    const login = await identityJson<{ login_id: string; login_uri: string }>(
      '/oauth2/device/login',
      {
        method: 'POST',
        csrfToken: check.csrf_token,
        body: { user_code: userCode },
      },
    )
    // Native /login owns account selection (including multiple sessions) and
    // challenges. Neither this check nor begin grants device authorization.
    const loginUri = new URL(login.login_uri, 'https://identity.invalid')
    if (uiLocales) loginUri.searchParams.set('ui_locales', uiLocales)
    return { status: 'login', loginUri: `${loginUri.pathname}${loginUri.search}` }
  } catch (error) {
    return deviceFailure(error, locale)
  }
}

/** Reload only the bound interaction: the short code was consumed at login. */
export async function loadDeviceVerification(
  loginId: string,
  locale: Locale,
): Promise<DeviceVerificationLookup> {
  try {
    const description = await identityJson<DeviceVerificationPageData>(
      `/oauth2/consent?login_id=${encodeURIComponent(loginId)}`,
    )
    return { status: 'described', description }
  } catch (error) {
    // A bound interaction failure is not an invalid entry-code field error.
    return { status: 'failed', message: errorMessage(error, locale) }
  }
}

export function decideDeviceVerification(
  loginId: string,
  decision: 'approve' | 'deny',
  csrfToken: string,
) {
  return identityJson<ConsentApiResponse>('/oauth2/consent', {
    method: 'POST',
    csrfToken,
    body: { login_id: loginId, decision },
  })
}

export function deviceInteractionPath(loginId: string, uiLocales?: string) {
  const search = new URLSearchParams({ login_id: loginId })
  if (uiLocales) search.set('ui_locales', uiLocales)
  return `/device?${search}`
}

function deviceFailure(error: unknown, locale: Locale): DeviceFailure {
  if (error instanceof IdentityApiError && error.code === DEVICE_CODE_UNKNOWN) {
    return { status: 'unknown' }
  }
  return { status: 'failed', message: errorMessage(error, locale) }
}
