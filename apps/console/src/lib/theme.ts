export type ThemePreference = 'light' | 'dark' | 'system'

export const THEME_STORAGE_KEY = 'identity-theme'

export function isThemePreference(value: unknown): value is ThemePreference {
  return value === 'light' || value === 'dark' || value === 'system'
}

export function storedThemePreference(value: string | null): ThemePreference {
  return isThemePreference(value) ? value : 'system'
}

/** Apply a preference: explicit light/dark win, `system` follows the OS. */
export function applyTheme(preference: ThemePreference) {
  const dark =
    preference === 'dark' ||
    (preference === 'system' &&
      window.matchMedia('(prefers-color-scheme: dark)').matches)
  const root = document.documentElement
  root.classList.toggle('dark', dark)
  root.dataset.themePreference = preference
  root.style.colorScheme = dark ? 'dark' : 'light'
}

/**
 * Cache the applied preference for the next document load. `index.html` reads
 * it before React runs so the first paint already uses the right palette; the
 * account preference replaces it as soon as the account read resolves.
 */
export function rememberTheme(preference: ThemePreference) {
  try {
    window.localStorage.setItem(THEME_STORAGE_KEY, preference)
  } catch {
    // The preference still applies to this page when storage is unavailable.
  }
}
