import { deleteCookie, getCookie, setCookie } from '@tanstack/react-start/server'

import { isThemePreference, type ThemePreference } from './appearance'

export const THEME_COOKIE_NAME = 'identity-theme'

export function anonymousThemePreference(): ThemePreference | undefined {
  const value = getCookie(THEME_COOKIE_NAME)
  return isThemePreference(value) && value !== 'system' ? value : undefined
}

export function storeAnonymousThemePreference(theme: ThemePreference) {
  if (theme === 'system') {
    deleteCookie(THEME_COOKIE_NAME, { path: '/' })
    return
  }

  setCookie(THEME_COOKIE_NAME, theme, {
    path: '/',
    maxAge: 60 * 60 * 24 * 365,
    sameSite: 'lax',
    secure: true,
  })
}
