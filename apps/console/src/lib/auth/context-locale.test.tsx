import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { AuthProvider, useAuth } from '#/lib/auth/context'
import { buildTransaction, saveTransaction } from '#/lib/auth/transaction'
import {
  clearAuthSession,
  setAuthSession,
  type AuthSession,
} from '#/lib/auth/session'
import type { RuntimeConfig } from '#/lib/config'
import {
  LocaleProvider,
  resolveBrowserLocale,
  useLocale,
} from '#/lib/i18n'
import { RuntimeConfigProvider } from '#/lib/runtime-config'

const mocks = vi.hoisted(() => ({
  completeAuthorization: vi.fn(),
}))

vi.mock('#/lib/auth/oidc', async (importOriginal) => {
  const actual = await importOriginal<typeof import('#/lib/auth/oidc')>()
  return {
    ...actual,
    completeAuthorization: mocks.completeAuthorization,
  }
})

const config: RuntimeConfig = {
  issuer: 'https://issuer.example.test',
  graphqlUrl: 'https://issuer.example.test/graphql',
  clientId: 'console',
  redirectUri: `${window.location.origin}/callback`,
  postLogoutRedirectUri: `${window.location.origin}/signed-out`,
  accountUrl: 'https://account.example.test',
  scope: 'openid profile email',
  displayName: 'Identity Console',
  environment: 'test',
}

function session(sub: string, locale: string | undefined, token = `token-${sub}`): AuthSession {
  const now = Math.floor(Date.now() / 1000)
  return {
    accessToken: token,
    idToken: `id-${sub}`,
    expiresAt: Date.now() + 60_000,
    scope: 'openid profile email',
    grantedScopes: ['openid', 'profile', 'email'],
    claims: {
      sub,
      iss: config.issuer,
      aud: config.clientId,
      exp: now + 3_600,
      locale,
    },
    endSessionEndpoint: `${config.issuer}/logout`,
  }
}

let authApi: ReturnType<typeof useAuth> | undefined

function AuthProbe() {
  authApi = useAuth()
  const { locale, timeZone } = useLocale()
  return <><span data-testid="locale">{locale}</span><span data-testid="time-zone">{timeZone}</span></>
}

function LocaleProbe() {
  const { locale, applyAccountLocale } = useLocale()
  return (
    <div>
      <span data-testid="locale">{locale}</span>
      <button type="button" onClick={() => applyAccountLocale('zh-CN')}>
        apply-zh
      </button>
      <button type="button" onClick={() => applyAccountLocale(null)}>
        apply-browser
      </button>
    </div>
  )
}

function renderAuth() {
  return render(
    <RuntimeConfigProvider config={config}>
      <LocaleProvider>
        <AuthProvider>
          <AuthProbe />
        </AuthProvider>
      </LocaleProvider>
    </RuntimeConfigProvider>,
  )
}

beforeEach(() => {
  vi.restoreAllMocks()
  clearAuthSession()
  window.localStorage.clear()
  window.sessionStorage.clear()
  mocks.completeAuthorization.mockReset()
  authApi = undefined
})

describe('console account locale', () => {

  it('treats a null account locale as the browser fallback', () => {
    render(
      <LocaleProvider>
        <LocaleProbe />
      </LocaleProvider>,
    )

    fireEvent.click(screen.getByRole('button', { name: 'apply-zh' }))
    expect(screen.getByTestId('locale').textContent).toBe('zh-CN')

    fireEvent.click(screen.getByRole('button', { name: 'apply-browser' }))
    expect(screen.getByTestId('locale').textContent).toBe(resolveBrowserLocale())
  })

  it('applies the ID-token locale when rehydrating the in-memory session', async () => {
    setAuthSession(session('user-a', 'zh-CN'))

    renderAuth()

    await waitFor(() => {
      expect(screen.getByTestId('locale').textContent).toBe('zh-CN')
    })
  })

  it.each(['logoutLocal', 'expire', 'logoutSso'] as const)('%s clears the previous account preference', async (action) => {
    setAuthSession(session('user-a', 'zh-CN'))
    renderAuth()
    await waitFor(() => expect(screen.getByTestId('locale').textContent).toBe('zh-CN'))
    act(() => { authApi?.[action]() })
    await waitFor(() => expect(screen.getByTestId('locale').textContent).toBe(resolveBrowserLocale()))
  })

  it.each([
    ['en-US', 'zh-CN', 'zh-CN', 'en-US'],
    ['zh-CN', 'en-US', 'en-US', 'zh-CN'],
    [undefined, 'zh-CN', 'en-US', 'zh-CN'],
    ['fr-FR', 'zh-CN', 'en-US', 'zh-CN'],
  ])('resolves saved %s with browser %s and stale storage %s', async (saved, detected, stale, expected) => {
    vi.spyOn(window.navigator, 'languages', 'get').mockReturnValue([detected])
    window.localStorage.setItem('identity.console.locale', stale)
    setAuthSession(session('user-a', saved))
    renderAuth()
    await waitFor(() => {
      expect(screen.getByTestId('locale').textContent).toBe(expected)
      expect(document.documentElement.lang).toBe(expected)
    })
    expect(window.localStorage.getItem('identity.console.locale')).toBe(stale)
  })

  it.each([
    [undefined, 'zh-CN'],
    ['en-US', 'en-US'],
  ])('handles browser changes with saved account locale %s', async (saved, expected) => {
    const languages = vi.spyOn(window.navigator, 'languages', 'get').mockReturnValue(['en-US'])
    setAuthSession(session('user-a', saved))
    renderAuth()
    await waitFor(() => expect(document.documentElement.lang).toBe('en-US'))
    languages.mockReturnValue(['zh-CN'])
    act(() => { window.dispatchEvent(new Event('languagechange')) })
    await waitFor(() => expect(document.documentElement.lang).toBe(expected))
  })

  it.each(['Asia/Shanghai', 'America/New_York', 'Invalid/Zone', undefined])('applies saved time zone %s and clears it on logout', async (saved) => {
    const current = session('user-a', 'en-US')
    current.claims.zoneinfo = saved
    setAuthSession(current)
    renderAuth()
    const browserZone = Intl.DateTimeFormat().resolvedOptions().timeZone
    const expected = saved && saved !== 'Invalid/Zone' ? saved : browserZone
    await waitFor(() => expect(screen.getByTestId('time-zone').textContent).toBe(expected))
    act(() => { authApi?.logoutLocal() })
    await waitFor(() => expect(screen.getByTestId('time-zone').textContent).toBe(browserZone))
  })

  it('applies the newly authenticated account locale without retaining the previous account', async () => {
    setAuthSession(session('user-a', 'zh-CN'))
    renderAuth()
    await waitFor(() => expect(screen.getByTestId('locale').textContent).toBe('zh-CN'))
    mocks.completeAuthorization.mockResolvedValueOnce(session('user-b', 'en-US', 'token-b'))
    saveTransaction(buildTransaction({
      state: 'state-b', nonce: 'nonce-b', codeVerifier: 'verifier-b',
      locale: 'zh-CN', returnTo: '/',
    }))
    await act(async () => {
      await authApi?.completeCallback(`${window.location.origin}/callback?state=state-b`)
    })
    await waitFor(() => expect(screen.getByTestId('locale').textContent).toBe('en-US'))
    expect(authApi?.claims?.sub).toBe('user-b')
  })
})
