import { act, waitFor } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'

import { AccountThemeSync, themeFromAccount } from '#/lib/account-theme'
import { applyTheme } from '#/lib/theme'
import { renderWithLocale } from '#/test/render'

const mocks = vi.hoisted(() => ({
  account: { current: { theme: null } as { theme: string | null } | null },
  failure: { current: null as Error | null },
  requests: { current: 0 },
}))

vi.mock('#/lib/auth/context', () => ({
  useAuth: () => ({ status: 'authenticated', sessionVersion: 0 }),
}))

vi.mock('#/lib/graphql/use-graphql', () => ({
  useGraphQL: () => async () => {
    mocks.requests.current += 1
    if (mocks.failure.current) throw mocks.failure.current
    return { data: { account: mocks.account.current } }
  },
}))

/** Stub the OS preference and let a test switch it while the page is open. */
function stubSystemTheme(initialDark: boolean) {
  const listeners = new Set<() => void>()
  let dark = initialDark
  vi.stubGlobal('matchMedia', (query: string) => ({
    get matches() {
      return query.includes('prefers-color-scheme: dark') ? dark : false
    },
    media: query,
    onchange: null,
    addEventListener: (_type: string, listener: () => void) => {
      listeners.add(listener)
    },
    removeEventListener: (_type: string, listener: () => void) => {
      listeners.delete(listener)
    },
    dispatchEvent: () => false,
  }))
  return {
    setDark(next: boolean) {
      dark = next
      for (const listener of listeners) listener()
    },
  }
}

function isDark() {
  return document.documentElement.classList.contains('dark')
}

describe('account theme', () => {
  it('maps only real preferences and treats everything else as the system', () => {
    expect(themeFromAccount('light')).toBe('light')
    expect(themeFromAccount('dark')).toBe('dark')
    expect(themeFromAccount(null)).toBe('system')
    expect(themeFromAccount('sepia')).toBe('system')
  })

  it('applies an explicit account preference and caches it for the next load', async () => {
    stubSystemTheme(false)
    mocks.account.current = { theme: 'dark' }

    renderWithLocale(<AccountThemeSync />)

    await waitFor(() => expect(isDark()).toBe(true))
    expect(document.documentElement.dataset.themePreference).toBe('dark')
    expect(window.localStorage.getItem('identity-theme')).toBe('dark')
  })

  it('follows the system when the account has no preference and reacts to changes', async () => {
    const system = stubSystemTheme(true)
    mocks.account.current = { theme: null }

    renderWithLocale(<AccountThemeSync />)

    await waitFor(() => expect(document.documentElement.dataset.themePreference).toBe('system'))
    expect(isDark()).toBe(true)

    act(() => system.setDark(false))
    expect(isDark()).toBe(false)

    act(() => system.setDark(true))
    expect(isDark()).toBe(true)
  })

  it('keeps the current theme when the account read fails', async () => {
    stubSystemTheme(true)
    applyTheme('light')
    mocks.failure.current = new Error('account.read is missing from the session')

    renderWithLocale(<AccountThemeSync />)

    await waitFor(() => expect(mocks.requests.current).toBeGreaterThan(0))
    expect(isDark()).toBe(false)
    expect(document.documentElement.dataset.themePreference).toBe('light')
    expect(window.localStorage.getItem('identity-theme')).toBeNull()
  })
})
