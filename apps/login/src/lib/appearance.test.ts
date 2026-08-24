// @vitest-environment jsdom

import { afterEach, describe, expect, it, vi } from 'vitest'

import {
  applyTheme,
  isThemePreference,
  resolveTheme,
  safeAppearanceReturnTo,
  storedThemePreference,
  themePreferenceValue,
} from './appearance'

afterEach(() => {
  document.documentElement.classList.remove('light', 'dark')
  delete document.documentElement.dataset.theme
  vi.unstubAllGlobals()
})

describe('appearance preferences', () => {
  it('resolves system, light, and dark preferences deterministically', () => {
    expect(resolveTheme('system', true)).toBe('dark')
    expect(resolveTheme('system', false)).toBe('light')
    expect(resolveTheme('light', true)).toBe('light')
    expect(resolveTheme('dark', false)).toBe('dark')
  })

  it('accepts only supported persisted preferences', () => {
    expect(isThemePreference('system')).toBe(true)
    expect(isThemePreference('dark')).toBe(true)
    expect(isThemePreference('sepia')).toBe(false)
  })

  it('falls back to the system preference when no valid choice is stored', () => {
    expect(storedThemePreference(null)).toBe('system')
    expect(storedThemePreference('system')).toBe('system')
    expect(storedThemePreference('dark')).toBe('dark')
    expect(storedThemePreference('sepia')).toBe('system')
  })

  it('stores system preference as an unset user field', () => {
    expect(themePreferenceValue('system')).toBeNull()
    expect(themePreferenceValue('light')).toBe('light')
    expect(themePreferenceValue('dark')).toBe('dark')
  })

  it('only redirects appearance forms back to the same origin', () => {
    const requestUrl = 'https://identity.example/appearance'
    expect(safeAppearanceReturnTo(requestUrl, '/login/challenge?login_id=123')).toBe(
      '/login/challenge?login_id=123',
    )
    expect(safeAppearanceReturnTo(requestUrl, 'https://evil.example/phish')).toBe('/login')
    expect(safeAppearanceReturnTo(requestUrl, null)).toBe('/login')
  })

  it('activates the resolved theme using HeroUI theme classes', () => {
    vi.stubGlobal('matchMedia', vi.fn(() => ({ matches: true })))

    applyTheme('system')
    expect(document.documentElement.dataset.theme).toBe('dark')
    expect(document.documentElement.classList.contains('dark')).toBe(true)
    expect(document.documentElement.classList.contains('light')).toBe(false)

    applyTheme('light')
    expect(document.documentElement.dataset.theme).toBe('light')
    expect(document.documentElement.classList.contains('light')).toBe(true)
    expect(document.documentElement.classList.contains('dark')).toBe(false)
  })
})
