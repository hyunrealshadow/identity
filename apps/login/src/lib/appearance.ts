export const THEME_STORAGE_KEY = 'identity-theme'

export type ThemePreference = 'system' | 'light' | 'dark'
export type ResolvedTheme = 'light' | 'dark'

export function isThemePreference(value: unknown): value is ThemePreference {
  return value === 'system' || value === 'light' || value === 'dark'
}

export function storedThemePreference(value: string | null): ThemePreference {
  return isThemePreference(value) ? value : 'system'
}

export function resolveTheme(
  preference: ThemePreference,
  systemPrefersDark: boolean,
): ResolvedTheme {
  return preference === 'system'
    ? systemPrefersDark ? 'dark' : 'light'
    : preference
}

export function themePreferenceValue(value: string | undefined) {
  return value === 'light' || value === 'dark' ? value : null
}

export function safeAppearanceReturnTo(requestUrl: string, value: unknown) {
  if (typeof value !== 'string') return '/login'

  try {
    const destination = new URL(value, requestUrl)
    if (destination.origin !== new URL(requestUrl).origin) return '/login'
    return `${destination.pathname}${destination.search}${destination.hash}`
  } catch {
    return '/login'
  }
}

export function applyTheme(preference: ThemePreference) {
  const systemPrefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches
  const theme = resolveTheme(preference, systemPrefersDark)
  const root = document.documentElement
  root.dataset.theme = theme
  root.classList.toggle('dark', theme === 'dark')
  root.classList.toggle('light', theme === 'light')
}
