import { deleteCookie, getCookie, setCookie } from '@tanstack/react-start/server'

import { isThemePreference, type ThemePreference } from './appearance'
import { forwardedProtoIsHttps } from './upstream-https'

export const THEME_COOKIE_NAME = 'identity-theme'

export function isSecureRequest(request?: Request) {
  if (!request) return true
  try {
    if (new URL(request.url).protocol === 'https:') return true
  } catch {
    // Malformed URL falls back to forwarded proto check.
  }
  return forwardedProtoIsHttps(request.headers)
}

export function anonymousThemePreference(): ThemePreference | undefined {
  const value = getCookie(THEME_COOKIE_NAME)
  return isThemePreference(value) && value !== 'system' ? value : undefined
}

export function storeAnonymousThemePreference(theme: ThemePreference, request?: Request) {
  if (theme === 'system') {
    deleteCookie(THEME_COOKIE_NAME, { path: '/' })
    return
  }

  setCookie(THEME_COOKIE_NAME, theme, {
    path: '/',
    maxAge: 60 * 60 * 24 * 365,
    sameSite: 'lax',
    secure: isSecureRequest(request),
  })
}
