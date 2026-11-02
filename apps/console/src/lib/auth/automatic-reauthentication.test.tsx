import { act, render, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { AuthProvider, useAuth } from '#/lib/auth/context'
import {
  AUTH_LOGOUT_EVENT,
  BEFORE_AUTH_REDIRECT_EVENT,
} from '#/lib/auth/events'
import type { AuthorizationRequest } from '#/lib/auth/oidc'
import {
  REAUTH_MARKER_KEY,
  readReauthenticationMarker,
  saveReauthenticationMarker,
  type ReauthenticationMarker,
} from '#/lib/auth/reauthentication'
import {
  clearAuthSession,
  getAuthSession,
  setAuthSession,
  type AuthSession,
} from '#/lib/auth/session'
import {
  AUTH_TRANSACTION_TTL_MS,
  AuthError,
  buildTransaction,
  saveTransaction,
} from '#/lib/auth/transaction'
import type { RuntimeConfig } from '#/lib/config'
import { LocaleProvider } from '#/lib/i18n'
import { RuntimeConfigProvider } from '#/lib/runtime-config'
import { readDraft, writeDraft } from '#/lib/draft-storage'

const mocks = vi.hoisted(() => ({
  beginAuthorization: vi.fn(),
  completeAuthorization: vi.fn(),
}))

vi.mock('#/lib/auth/oidc', async (importOriginal) => {
  const actual = await importOriginal<typeof import('#/lib/auth/oidc')>()
  return {
    ...actual,
    beginAuthorization: mocks.beginAuthorization,
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

function fakePopup(): {
  closed: boolean
  close: ReturnType<typeof vi.fn>
  location: { replace: ReturnType<typeof vi.fn> }
  document: { title: string }
} {
  return {
    closed: false,
    close: vi.fn(),
    location: { replace: vi.fn() },
    document: { title: '' },
  }
}

function session(sub = 'user-a'): AuthSession {
  const now = Math.floor(Date.now() / 1000)
  return {
    accessToken: `access-${sub}`,
    idToken: `id-${sub}`,
    expiresAt: Date.now() + 60_000,
    scope: config.scope,
    grantedScopes: ['openid', 'profile', 'email'],
    claims: {
      sub,
      iss: config.issuer,
      aud: config.clientId,
      exp: now + 3_600,
      preferred_username: sub,
      email: `${sub}@example.test`,
    },
    endSessionEndpoint: `${config.issuer}/logout`,
  }
}

interface BeginOptions {
  returnTo?: string
  expectedSubject?: string
  stepUp?: { acrValues?: string; maxAge?: number }
}

function authorizationRequest(
  options: BeginOptions = {},
): AuthorizationRequest {
  return {
    url: 'about:blank',
    discovery: {} as never,
    transaction: buildTransaction({
      state: 'state-a',
      nonce: 'nonce-a',
      codeVerifier: 'verifier-a',
      locale: 'en-US',
      returnTo: options.returnTo ?? '/',
      acrValues: options.stepUp?.acrValues,
      maxAge: options.stepUp?.maxAge,
      expectedSubject: options.expectedSubject,
    }),
  }
}

let authApi: ReturnType<typeof useAuth> | undefined

function AuthProbe() {
  authApi = useAuth()
  return null
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

function completedMarker(
  overrides: Partial<ReauthenticationMarker> = {},
): ReauthenticationMarker {
  const now = Date.now()
  return {
    version: 1,
    phase: 'completed',
    subject: 'user-a',
    issuer: config.issuer,
    returnTo: '/',
    state: 'state-a',
    startedAt: now - 1_000,
    completedAt: now,
    expiresAt: now - 1_000 + AUTH_TRANSACTION_TTL_MS,
    ...overrides,
  }
}

beforeEach(() => {
  vi.restoreAllMocks()
  clearAuthSession()
  window.localStorage.clear()
  window.sessionStorage.clear()
  window.history.replaceState({}, '', '/')
  mocks.beginAuthorization
    .mockReset()
    .mockImplementation(async (options: BeginOptions) =>
      authorizationRequest({
        returnTo: options.returnTo,
        expectedSubject: options.expectedSubject,
        stepUp: options.stepUp,
      }),
    )
  mocks.completeAuthorization.mockReset()
  vi.spyOn(window, 'open').mockReturnValue(fakePopup() as unknown as Window)
  authApi = undefined
})

afterEach(() => {
  vi.useRealTimers()
  window.history.replaceState({}, '', '/')
})

describe('automatic console reauthentication', () => {
  it('bounds ordinary rejected-session recovery after a successful callback and allows explicit retry', async () => {
    setAuthSession(session())
    mocks.beginAuthorization.mockImplementation(async (options) => {
      const request = authorizationRequest(options)
      saveTransaction(request.transaction)
      options.beforeRedirect?.(request)
      return request
    })
    mocks.completeAuthorization.mockResolvedValue(session())
    renderAuth()
    await act(async () => {
      await authApi?.requireReauthentication(undefined, {
        reason: 'unauthorized',
      })
    })
    expect(readReauthenticationMarker()?.phase).toBe('pending')
    expect(getAuthSession()).toBeNull()
    expect(mocks.beginAuthorization.mock.calls[0][0].stepUp).toBeUndefined()
    expect(mocks.beginAuthorization.mock.calls[0][0].loginHint).toBeUndefined()
    await act(async () => {
      await authApi?.completeCallback(
        `${window.location.origin}/callback?state=state-a`,
      )
    })
    expect(readReauthenticationMarker()?.phase).toBe('completed')
    await act(async () => {
      await authApi?.requireReauthentication(undefined, {
        reason: 'unauthorized',
      })
    })
    expect(mocks.beginAuthorization).toHaveBeenCalledTimes(1)
    expect(authApi?.status).toBe('error')
    expect(authApi?.errorCode).toBe('reauthentication_loop')
    expect(window.open).not.toHaveBeenCalled()
    await act(async () => {
      await authApi?.retryReauthentication()
    })
    expect(mocks.beginAuthorization).toHaveBeenCalledTimes(2)
  })

  it('coalesces concurrent challenges into one retained popup request with fresh auth', async () => {
    window.history.replaceState({}, '', '/users?filter=a#section')
    setAuthSession(session())

    renderAuth()

    await act(async () => {
      const first = authApi?.requireReauthentication({
        acrValues: 'urn:extension',
        maxAge: 120,
      })
      const second = authApi?.requireReauthentication({
        acrValues: 'urn:extension',
        maxAge: 120,
      })
      await Promise.all([first, second])
    })

    expect(mocks.beginAuthorization).toHaveBeenCalledTimes(1)
    const options = mocks.beginAuthorization.mock.calls[0][0]
    expect(options.deferNavigation).toBe(true)
    expect(options.returnTo).toBe('/users?filter=a#section')
    expect(options.stepUp).toEqual({ acrValues: 'urn:extension', maxAge: 0 })
    expect(options.loginHint).toBe('user-a')
    expect(options.expectedSubject).toBe('user-a')
    expect(options.selectAccount).toBe(false)
    // The old session and its claims remain readable for the whole popup.
    expect(getAuthSession()?.claims.sub).toBe('user-a')
    expect(authApi?.status).toBe('authenticated')
    expect(authApi?.claims?.sub).toBe('user-a')
    expect(authApi?.reauthenticationPopup?.phase).toBe('waiting')

    expect(readReauthenticationMarker()).toMatchObject({
      phase: 'pending',
      subject: 'user-a',
      issuer: config.issuer,
      returnTo: '/users?filter=a#section',
      state: 'state-a',
    })
  })

  it('falls back to an email hint and binds the current subject', async () => {
    const current = session()
    current.claims.preferred_username = undefined
    current.claims.email = 'user-a@example.test'
    setAuthSession(current)
    renderAuth()

    await act(async () => {
      await authApi?.requireReauthentication({ acrValues: 'aal2' })
    })

    const options = mocks.beginAuthorization.mock.calls[0][0]
    expect(options.loginHint).toBe('user-a@example.test')
    expect(options.expectedSubject).toBe('user-a')
  })

  it('binds an explicit sign-in step-up to the current session identity', async () => {
    setAuthSession(session())
    renderAuth()

    await act(async () => {
      await authApi?.signIn({ stepUp: { acrValues: 'aal2', maxAge: 0 } })
    })

    const options = mocks.beginAuthorization.mock.calls[0][0]
    expect(options.loginHint).toBe('user-a')
    expect(options.expectedSubject).toBe('user-a')
    expect(options.stepUp).toEqual({ acrValues: 'aal2', maxAge: 0 })
    expect(options.acrValues).toBeUndefined()
  })

  it('does not send a hint, subject binding or max_age for ordinary sign-in', async () => {
    setAuthSession(session())
    renderAuth()

    await act(async () => {
      await authApi?.signIn()
    })

    const options = mocks.beginAuthorization.mock.calls[0][0]
    expect(options.loginHint).toBeUndefined()
    expect(options.expectedSubject).toBeUndefined()
    expect(options.stepUp).toBeUndefined()
    expect(options.acrValues).toBe('aal2')
    expect(options.selectAccount).toBe(false)
  })

  it('captures subject-scoped drafts before clearing a switched account', async () => {
    window.history.replaceState({}, '', '/users?filter=a#section')
    setAuthSession(session())
    saveReauthenticationMarker(completedMarker())
    renderAuth()

    let observedSubject: string | undefined
    let logoutCount = 0
    const onBeforeRedirect = () => {
      observedSubject = getAuthSession()?.claims.sub
      writeDraft('switch-draft', { page: 'users' })
    }
    const onLogout = () => {
      logoutCount += 1
    }
    window.addEventListener(BEFORE_AUTH_REDIRECT_EVENT, onBeforeRedirect)
    window.addEventListener(AUTH_LOGOUT_EVENT, onLogout)

    await act(async () => {
      await authApi?.signIn({ selectAccount: true })
    })

    window.removeEventListener(BEFORE_AUTH_REDIRECT_EVENT, onBeforeRedirect)
    window.removeEventListener(AUTH_LOGOUT_EVENT, onLogout)

    const options = mocks.beginAuthorization.mock.calls[0][0]
    expect(options.selectAccount).toBe(true)
    expect(options.returnTo).toBe('/users?filter=a#section')
    expect(options.loginHint).toBeUndefined()
    expect(options.expectedSubject).toBeUndefined()
    expect(options.stepUp).toBeUndefined()
    expect(observedSubject).toBe('user-a')
    expect(logoutCount).toBe(0)
    // The previous session survives until the validated request is ready to
    // replace the page. A failed discovery would therefore remain usable.
    expect(getAuthSession()?.claims.sub).toBe('user-a')
    expect(authApi?.claims?.sub).toBe('user-a')

    act(() => {
      options.beforeRedirect?.(
        authorizationRequest({ returnTo: options.returnTo }),
      )
    })

    expect(getAuthSession()).toBeNull()
    expect(authApi?.claims).toBeUndefined()
    expect(readReauthenticationMarker()).toBeNull()

    // The old account's draft survived the switch and stays isolated by subject.
    setAuthSession(session())
    expect(readDraft('switch-draft')).toEqual({ page: 'users' })
  })

  it('keeps the previous account when a switch request cannot be validated', async () => {
    setAuthSession(session())
    mocks.beginAuthorization.mockRejectedValueOnce(
      new AuthError('discovery_failed'),
    )
    renderAuth()

    await act(async () => {
      await authApi?.signIn({ selectAccount: true })
    })

    expect(getAuthSession()?.claims.sub).toBe('user-a')
    expect(authApi?.claims?.sub).toBe('user-a')
    expect(authApi?.status).toBe('authenticated')
    expect(authApi?.errorCode).toBe('discovery_failed')
  })

  it('rejects account selection combined with a step-up instead of dropping the binding', async () => {
    setAuthSession(session())
    renderAuth()

    await act(async () => {
      await authApi?.signIn({
        selectAccount: true,
        stepUp: { acrValues: 'aal2', maxAge: 0 },
      })
    })

    expect(mocks.beginAuthorization).not.toHaveBeenCalled()
    expect(getAuthSession()?.claims.sub).toBe('user-a')
    expect(authApi?.status).toBe('error')
    expect(authApi?.errorCode).toBe('invalid_transaction')
  })

  it('stops at one recoverable global error after a completed loop and retries manually', async () => {
    setAuthSession(session())
    saveReauthenticationMarker(completedMarker())
    renderAuth()

    await act(async () => {
      await authApi?.requireReauthentication(
        { acrValues: 'aal2' },
        {
          requestId: 'request-recovery',
          traceId: '11111111111111111111111111111111',
        },
      )
    })

    expect(mocks.beginAuthorization).not.toHaveBeenCalled()
    expect(authApi?.status).toBe('error')
    expect(authApi?.errorCode).toBe('reauthentication_loop')
    expect(authApi?.recoveryCorrelation).toEqual({
      requestId: 'request-recovery',
      traceId: '11111111111111111111111111111111',
    })

    await act(async () => {
      await authApi?.retryReauthentication()
    })

    expect(mocks.beginAuthorization).toHaveBeenCalledTimes(1)
    const options = mocks.beginAuthorization.mock.calls[0][0]
    expect(options.returnTo).toBe('/')
    expect(options.stepUp).toBeUndefined()
    expect(options.deferNavigation).toBeUndefined()
    expect(window.open).not.toHaveBeenCalled()
  })

  it('marks a valid callback complete and rejects an immediate repeated challenge', async () => {
    setAuthSession(session())
    mocks.completeAuthorization.mockResolvedValue(session())
    saveTransaction(
      buildTransaction({
        state: 'state-b',
        nonce: 'nonce-b',
        codeVerifier: 'verifier-b',
        locale: 'en-US',
        returnTo: '/',
        expectedSubject: 'user-a',
      }),
    )
    const now = Date.now()
    saveReauthenticationMarker({
      version: 1,
      phase: 'pending',
      subject: 'user-a',
      issuer: config.issuer,
      returnTo: '/',
      state: 'state-b',
      startedAt: now,
      expiresAt: now + AUTH_TRANSACTION_TTL_MS,
    })
    renderAuth()

    await act(async () => {
      await authApi?.completeCallback(
        `${window.location.origin}/callback?state=state-b`,
      )
    })

    await waitFor(() => expect(authApi?.status).toBe('authenticated'))
    expect(readReauthenticationMarker()?.phase).toBe('completed')
    expect(
      mocks.completeAuthorization.mock.calls[0][0].transaction.expectedSubject,
    ).toBe('user-a')

    await act(async () => {
      await authApi?.requireReauthentication({ acrValues: 'aal2' })
    })

    expect(mocks.beginAuthorization).not.toHaveBeenCalled()
    expect(authApi?.status).toBe('error')
    expect(authApi?.errorCode).toBe('reauthentication_loop')
  })

  it('dispatches logout before clearing and never dispatches it for expiry', async () => {
    setAuthSession(session())
    let logoutCount = 0
    let logoutSubject: string | undefined
    let redirectCount = 0
    const onLogout = () => {
      logoutCount += 1
      logoutSubject = getAuthSession()?.claims.sub
    }
    const onBeforeRedirect = () => {
      redirectCount += 1
    }
    window.addEventListener(AUTH_LOGOUT_EVENT, onLogout)
    window.addEventListener(BEFORE_AUTH_REDIRECT_EVENT, onBeforeRedirect)

    renderAuth()

    act(() => {
      authApi?.logoutLocal()
    })

    expect(logoutCount).toBe(1)
    expect(logoutSubject).toBe('user-a')
    expect(redirectCount).toBe(0)
    expect(authApi?.status).toBe('anonymous')

    setAuthSession(session())
    act(() => {
      authApi?.expire()
    })

    expect(logoutCount).toBe(1)
    // Expiry emits only the redirect transition, never the logout event.
    expect(redirectCount).toBe(1)
    expect(authApi?.status).toBe('expired')

    window.removeEventListener(AUTH_LOGOUT_EVENT, onLogout)
    window.removeEventListener(BEFORE_AUTH_REDIRECT_EVENT, onBeforeRedirect)
  })

  it('removes only corrupt markers without touching a valid one', () => {
    window.sessionStorage.setItem(REAUTH_MARKER_KEY, '{bad-json')
    expect(readReauthenticationMarker()).toBeNull()
    expect(window.sessionStorage.getItem(REAUTH_MARKER_KEY)).toBeNull()
    const now = Date.now()
    const valid = {
      version: 1,
      phase: 'pending',
      subject: 'user-a',
      issuer: config.issuer,
      returnTo: '/users',
      state: 'valid-state',
      startedAt: now,
      expiresAt: now + 60_000,
    }
    const stored = JSON.stringify(valid)
    window.sessionStorage.setItem(REAUTH_MARKER_KEY, stored)
    expect(readReauthenticationMarker()).toEqual(valid)
    expect(window.sessionStorage.getItem(REAUTH_MARKER_KEY)).toBe(stored)
  })

  it('uses top-level ordinary sign-in without a popup on token expiry', async () => {
    vi.useFakeTimers()
    setAuthSession({ ...session(), expiresAt: Date.now() + 1_000 })
    renderAuth()

    await act(async () => {
      await vi.advanceTimersByTimeAsync(1_001)
    })

    expect(mocks.beginAuthorization).toHaveBeenCalledTimes(1)
    const options = mocks.beginAuthorization.mock.calls[0][0]
    expect(options.deferNavigation).toBeUndefined()
    expect(options.stepUp).toBeUndefined()
    expect(options.loginHint).toBeUndefined()
    expect(options.expectedSubject).toBeUndefined()
    expect(authApi?.status).toBe('authorizing')
    expect(authApi?.reauthenticationPopup).toBeNull()
    expect(window.open).not.toHaveBeenCalled()
  })

  it('coalesces rejected-session recovery and saves drafts before clearing the session', async () => {
    const current = session()
    setAuthSession(current)
    window.history.replaceState({}, '', '/groups?query=test')
    const saveDraft = vi.fn(() =>
      writeDraft('session-recovery', { name: 'unsaved group' }),
    )
    window.addEventListener(BEFORE_AUTH_REDIRECT_EVENT, saveDraft)
    mocks.beginAuthorization.mockImplementation(async (options) => {
      const request = authorizationRequest(options)
      options.beforeRedirect?.(request)
      return request
    })
    renderAuth()
    try {
      await act(async () => {
        await Promise.all([
          authApi?.requireReauthentication(undefined, {
            reason: 'unauthorized',
          }),
          authApi?.requireReauthentication(undefined, {
            reason: 'unauthorized',
          }),
        ])
      })
      expect(mocks.beginAuthorization).toHaveBeenCalledTimes(1)
      expect(mocks.beginAuthorization.mock.calls[0][0]).toMatchObject({
        returnTo: '/groups?query=test',
        acrValues: 'aal2',
      })
      expect(mocks.beginAuthorization.mock.calls[0][0].stepUp).toBeUndefined()
      expect(window.open).not.toHaveBeenCalled()
      expect(saveDraft).toHaveBeenCalledTimes(1)
      expect(getAuthSession()).toBeNull()
      setAuthSession(current)
      expect(readDraft('session-recovery')).toEqual({ name: 'unsaved group' })
    } finally {
      window.removeEventListener(BEFORE_AUTH_REDIRECT_EVENT, saveDraft)
    }
  })

  it('closes an outstanding step-up when the server rejects the session', async () => {
    setAuthSession(session())
    renderAuth()
    await act(async () => {
      await authApi?.requireReauthentication({ acrValues: 'aal2', maxAge: 300 })
    })
    expect(window.open).toHaveBeenCalledTimes(1)
    const popup = vi.mocked(window.open).mock.results[0].value
    await act(async () => {
      await authApi?.requireReauthentication(undefined, {
        reason: 'unauthorized',
      })
    })
    expect(popup?.close).toHaveBeenCalled()
    expect(window.open).toHaveBeenCalledTimes(1)
    expect(authApi?.reauthenticationPopup).toBeNull()
    expect(mocks.beginAuthorization.mock.calls[1][0].stepUp).toBeUndefined()
    expect(
      mocks.beginAuthorization.mock.calls[1][0].deferNavigation,
    ).toBeUndefined()
  })

  it.each(['logoutLocal', 'logoutSso'] as const)(
    'clears saved drafts on %s without a form page',
    async (logout) => {
      setAuthSession({ ...session(), endSessionEndpoint: undefined })
      writeDraft('unmounted-form', { reason: 'discard on logout' })
      renderAuth()
      act(() => {
        authApi?.[logout]()
      })
      setAuthSession(session())
      expect(readDraft('unmounted-form')).toBeNull()
    },
  )
})
