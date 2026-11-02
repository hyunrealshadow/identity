import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi, type MockInstance } from 'vitest'

import { AuthProvider, useAuth } from '#/lib/auth/context'
import {
  POPUP_CALLBACK_MESSAGE_TYPE,
  type PopupReauthenticationPrompt,
} from '#/lib/auth/popup-reauthentication'
import type { AuthorizationRequest } from '#/lib/auth/oidc'
import { readReauthenticationMarker } from '#/lib/auth/reauthentication'
import {
  clearAuthSession,
  getAuthSession,
  setAuthSession,
  type AuthSession,
} from '#/lib/auth/session'
import { AuthError, buildTransaction } from '#/lib/auth/transaction'
import type { RuntimeConfig } from '#/lib/config'
import { LocaleProvider } from '#/lib/i18n'
import { RuntimeConfigProvider } from '#/lib/runtime-config'

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

vi.mock('#/components/reauthentication-popup', async () => {
  const React = await import('react')
  return {
    ReauthenticationPopup: ({
      prompt,
      onContinue,
      onFallback,
      onCancel,
    }: {
      prompt: PopupReauthenticationPrompt
      onContinue: () => void
      onFallback: () => void
      onCancel: () => void
    }) => {
      if (prompt.phase !== 'blocked' && prompt.phase !== 'failed') return null
      return React.createElement(
        'div',
        { 'data-testid': 'reauth-notice' },
        React.createElement(
          'span',
          { 'data-testid': 'reauth-phase' },
          prompt.phase,
        ),
        React.createElement(
          'button',
          { type: 'button', onClick: onContinue },
          'continue-popup',
        ),
        React.createElement(
          'button',
          { type: 'button', onClick: onFallback },
          'fallback-popup',
        ),
        React.createElement(
          'button',
          { type: 'button', onClick: onCancel },
          'cancel-popup',
        ),
      )
    },
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

interface FakePopup {
  closed: boolean
  close: ReturnType<typeof vi.fn>
  location: { replace: ReturnType<typeof vi.fn> }
  document: { title: string }
}

function fakePopup(): FakePopup {
  const popup: FakePopup = {
    closed: false,
    close: vi.fn(),
    location: { replace: vi.fn() },
    document: { title: '' },
  }
  popup.close.mockImplementation(() => {
    popup.closed = true
  })
  return popup
}

let popup: FakePopup
let openSpy: MockInstance<typeof window.open>

function session(sub = 'user-a', token = 'access-a'): AuthSession {
  const now = Math.floor(Date.now() / 1000)
  return {
    accessToken: token,
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

function authorizationRequest(
  options: {
    returnTo?: string
    expectedSubject?: string
    stepUp?: { acrValues?: string; maxAge?: number }
  } = {},
): AuthorizationRequest {
  return {
    url: 'about:blank',
    discovery: {} as never,
    transaction: buildTransaction({
      state: 'state-a',
      nonce: 'nonce-a',
      codeVerifier: 'verifier-a',
      locale: 'en-US',
      returnTo: options.returnTo ?? '/users',
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

async function openPopup(): Promise<PopupReauthenticationPrompt> {
  await act(async () => {
    await authApi?.requireReauthentication(
      { acrValues: 'aal2' },
      { reason: 'step_up' },
    )
  })
  await waitFor(() => {
    expect(authApi?.reauthenticationPopup?.phase).toBe('waiting')
  })
  return authApi!.reauthenticationPopup!
}

function callbackMessage(
  prompt: PopupReauthenticationPrompt,
  overrides: {
    origin?: string
    source?: unknown
    state?: string
    path?: string
  } = {},
) {
  const state = overrides.state ?? prompt.transaction!.state
  const redirect = new URL(config.redirectUri)
  const path = overrides.path ?? redirect.pathname
  return {
    origin: overrides.origin ?? redirect.origin,
    source: overrides.source ?? (popup as unknown as Window),
    data: {
      type: POPUP_CALLBACK_MESSAGE_TYPE,
      callbackUrl: `${redirect.origin}${path}?state=${state}&code=code-a`,
      state,
    },
  }
}

function dispatch(message: {
  origin: string
  source: unknown
  data: unknown
}) {
  window.dispatchEvent(
    new MessageEvent('message', {
      origin: message.origin,
      source: message.source as MessageEventSource,
      data: message.data,
    }),
  )
}

beforeEach(() => {
  vi.restoreAllMocks()
  clearAuthSession()
  window.localStorage.clear()
  window.sessionStorage.clear()
  window.history.replaceState({}, '', '/users')
  popup = fakePopup()
  openSpy = vi
    .spyOn(window, 'open')
    .mockReturnValue(popup as unknown as Window)
  mocks.beginAuthorization.mockReset().mockImplementation(
    async (options: {
      returnTo?: string
      expectedSubject?: string
      stepUp?: { acrValues?: string; maxAge?: number }
    }) =>
      authorizationRequest({
        returnTo: options.returnTo,
        expectedSubject: options.expectedSubject,
        stepUp: options.stepUp,
      }),
  )
  mocks.completeAuthorization.mockReset()
  authApi = undefined
})

describe('popup fresh authentication', () => {
  it('opens a real popup and retains the session while requesting fresh authentication without a prompt', async () => {
    setAuthSession(session())
    renderAuth()

    await openPopup()

    expect(openSpy).toHaveBeenCalledTimes(1)
    const [url, name, features] = openSpy.mock.calls[0]
    expect(url).toBe('about:blank')
    expect(String(name)).toMatch(/^identity-console-reauth-/)
    expect(String(features)).toContain('popup=yes')
    expect(String(features)).toContain('width=')
    expect(String(features)).toContain('height=')
    expect(popup.location.replace).toHaveBeenCalledWith('about:blank')
    expect(popup.document.title).toBeTruthy()

    expect(mocks.beginAuthorization).toHaveBeenCalledTimes(1)
    const options = mocks.beginAuthorization.mock.calls[0][0]
    expect(options.deferNavigation).toBe(true)
    expect(options.selectAccount).toBe(false)
    expect(options.stepUp).toEqual({ acrValues: 'aal2', maxAge: 0 })
    expect(options.loginHint).toBe('user-a')
    expect(options.expectedSubject).toBe('user-a')
    expect(options.returnTo).toBe('/users')
    expect('prompt' in options).toBe(false)

    expect(authApi?.status).toBe('authenticated')
    expect(authApi?.claims?.sub).toBe('user-a')
    expect(authApi?.accessToken()).toBe('access-a')
    expect(getAuthSession()?.claims.sub).toBe('user-a')
    expect(readReauthenticationMarker()).toMatchObject({
      phase: 'pending',
      subject: 'user-a',
      state: 'state-a',
    })
    expect(screen.queryByTestId('reauth-notice')).toBeNull()
  })

  it('accepts only the owned popup, callback origin, state and callback path', async () => {
    setAuthSession(session())
    mocks.completeAuthorization.mockResolvedValue(
      session('user-a', 'access-refreshed'),
    )
    renderAuth()
    const prompt = await openPopup()

    await act(async () => {
      dispatch(
        callbackMessage(prompt, { origin: 'https://attacker.example.test' }),
      )
      dispatch(callbackMessage(prompt, { source: window }))
      dispatch(callbackMessage(prompt, { state: 'state-b' }))
      dispatch(callbackMessage(prompt, { path: '/other' }))
    })

    expect(mocks.completeAuthorization).not.toHaveBeenCalled()
    expect(authApi?.reauthenticationPopup?.phase).toBe('waiting')

    await act(async () => {
      dispatch(callbackMessage(prompt))
      await Promise.resolve()
    })

    await waitFor(() => expect(authApi?.reauthenticationPopup).toBeNull())
    expect(mocks.completeAuthorization).toHaveBeenCalledTimes(1)
    expect(
      mocks.completeAuthorization.mock.calls[0][0].transaction.expectedSubject,
    ).toBe('user-a')
    expect(getAuthSession()?.accessToken).toBe('access-refreshed')
    expect(popup.close).toHaveBeenCalled()
    expect(authApi?.status).toBe('authenticated')
    expect(authApi?.sessionVersion).toBe(1)
  })

  it('consumes a callback once and ignores duplicates', async () => {
    setAuthSession(session())
    mocks.completeAuthorization.mockResolvedValue(
      session('user-a', 'access-refreshed'),
    )
    renderAuth()
    const prompt = await openPopup()

    await act(async () => {
      dispatch(callbackMessage(prompt))
      dispatch(callbackMessage(prompt))
      await Promise.resolve()
    })

    await waitFor(() => expect(authApi?.reauthenticationPopup).toBeNull())
    expect(mocks.completeAuthorization).toHaveBeenCalledTimes(1)
  })

  it('preserves the usable session when the user closes the popup', async () => {
    const current = session()
    setAuthSession(current)
    renderAuth()
    await openPopup()

    popup.closed = true

    await waitFor(
      () => expect(authApi?.reauthenticationPopup).toBeNull(),
      { timeout: 2_000 },
    )
    expect(mocks.completeAuthorization).not.toHaveBeenCalled()
    expect(readReauthenticationMarker()).toBeNull()
    expect(authApi?.status).toBe('authenticated')
    expect(authApi?.claims?.sub).toBe('user-a')
    expect(authApi?.accessToken()).toBe('access-a')
    expect(getAuthSession()).toBe(current)
  })

  it('shows a compact notice when the popup is blocked and continues after a synchronous reservation', async () => {
    setAuthSession(session())
    openSpy.mockReturnValue(null)
    renderAuth()

    await act(async () => {
      await authApi?.requireReauthentication({ acrValues: 'aal2' })
    })

    await waitFor(() => {
      expect(authApi?.reauthenticationPopup?.phase).toBe('blocked')
      expect(authApi?.reauthenticationPopup?.transaction).toBeTruthy()
    })
    expect(mocks.beginAuthorization).toHaveBeenCalledTimes(1)
    expect(authApi?.status).toBe('authenticated')
    expect(await screen.findByTestId('reauth-notice')).toBeTruthy()

    const next = fakePopup()
    openSpy.mockReturnValue(next as unknown as Window)

    await act(async () => {
      fireEvent.click(screen.getByText('continue-popup'))
      await Promise.resolve()
    })

    await waitFor(() => {
      expect(authApi?.reauthenticationPopup?.phase).toBe('waiting')
    })
    expect(openSpy).toHaveBeenCalledTimes(2)
    expect(mocks.beginAuthorization).toHaveBeenCalledTimes(1)
    expect(next.location.replace).toHaveBeenCalledWith('about:blank')
    expect(authApi?.status).toBe('authenticated')
  })

  it('cancels a blocked popup without changing the usable session', async () => {
    const current = session()
    setAuthSession(current)
    openSpy.mockReturnValue(null)
    renderAuth()

    await act(async () => {
      await authApi?.requireReauthentication({ acrValues: 'aal2' })
    })
    await waitFor(() => {
      expect(authApi?.reauthenticationPopup?.phase).toBe('blocked')
    })

    const cancel = await screen.findByText('cancel-popup')
    act(() => {
      fireEvent.click(cancel)
    })

    expect(authApi?.reauthenticationPopup).toBeNull()
    expect(authApi?.status).toBe('authenticated')
    expect(authApi?.claims?.sub).toBe('user-a')
    expect(authApi?.accessToken()).toBe('access-a')
    expect(getAuthSession()).toBe(current)
    expect(mocks.completeAuthorization).not.toHaveBeenCalled()
  })

  it('keeps the previous session when the callback subject binding fails', async () => {
    setAuthSession(session())
    mocks.completeAuthorization.mockRejectedValue(
      new AuthError('claims_invalid'),
    )
    renderAuth()
    const prompt = await openPopup()

    await act(async () => {
      dispatch(callbackMessage(prompt))
      await Promise.resolve()
    })

    await waitFor(() => {
      expect(authApi?.reauthenticationPopup?.phase).toBe('failed')
    })

    expect(mocks.completeAuthorization).toHaveBeenCalledTimes(1)
    expect(
      mocks.completeAuthorization.mock.calls[0][0].transaction.expectedSubject,
    ).toBe('user-a')
    expect(authApi?.reauthenticationPopup?.errorCode).toBe('claims_invalid')
    expect(getAuthSession()?.claims.sub).toBe('user-a')
    expect(authApi?.claims?.sub).toBe('user-a')
    expect(authApi?.status).toBe('authenticated')
    expect(popup.close).toHaveBeenCalled()
  })
})
