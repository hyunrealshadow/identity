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
