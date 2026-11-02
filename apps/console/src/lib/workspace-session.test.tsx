import { act, render, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { clearAuthSession, setAuthSession, type AuthSession } from '#/lib/auth/session'
import type { RuntimeConfig } from '#/lib/config'
import { RuntimeConfigProvider } from '#/lib/runtime-config'
import { WorkspaceProvider, useWorkspace } from '#/lib/workspace'

const mocks = vi.hoisted(() => ({
  request: vi.fn(),
  auth: {
    status: 'authenticated',
    sessionVersion: 0,
    requireReauthentication: vi.fn(),
  },
}))
vi.mock('#/lib/auth/context', () => ({ useAuth: () => mocks.auth }))
vi.mock('#/lib/graphql/use-graphql', () => ({ useGraphQL: () => mocks.request }))

const config = { scope: 'management.*' } as RuntimeConfig
function session(token: string): AuthSession {
  return {
    accessToken: token, idToken: token, expiresAt: Date.now() + 60_000,
    scope: '', grantedScopes: [],
    claims: { sub: 'same-user', iss: 'https://issuer.test', aud: 'console', exp: 9e9 },
  }
}
function bootstrap(recent: boolean) {
  return {
    data: {
      effectivePermissions: {
        requestableScopes: ['management.user.update'],
        effectiveScopes: recent ? ['management.user.update'] : [],
        authentication: { aal2: true, recent },
      },
      instanceInfo: { name: 'Identity' },
    }, errors: [], partial: false, forbidden: false, unauthorized: false,
  }
}
function deferred<T>() {
  let resolve!: (value: T) => void
  const promise = new Promise<T>((done) => { resolve = done })
  return { promise, resolve }
}
let workspace: ReturnType<typeof useWorkspace>
function Probe() { workspace = useWorkspace(); return null }
function App() {
  return <RuntimeConfigProvider config={config}><WorkspaceProvider><Probe /></WorkspaceProvider></RuntimeConfigProvider>
}
beforeEach(() => {
  clearAuthSession()
  mocks.request.mockReset()
  mocks.auth.requireReauthentication.mockReset()
  mocks.auth.sessionVersion = 0
})

describe('workspace session replacement', () => {
  it('withholds the old capability snapshot until the refreshed session bootstrap completes', async () => {
    setAuthSession(session('old'))
    mocks.request.mockResolvedValueOnce(bootstrap(true))
    const view = render(<App />)
    await waitFor(() => expect(workspace.status).toBe('ready'))
    const pending = deferred<ReturnType<typeof bootstrap>>()
    mocks.request.mockReturnValueOnce(pending.promise)
    setAuthSession(session('fresh'))
    mocks.auth.sessionVersion++
    view.rerender(<App />)
    expect(workspace.status).toBe('loading')
    expect(workspace.data).toBeUndefined()
    await act(async () => pending.resolve(bootstrap(true)))
    await waitFor(() => expect(workspace.status).toBe('ready'))
    expect(mocks.auth.requireReauthentication).not.toHaveBeenCalled()
  })

  it('starts a new bootstrap and ignores a late challenge from the previous session', async () => {
    setAuthSession(session('old'))
    const old = deferred<ReturnType<typeof bootstrap>>()
    const fresh = deferred<ReturnType<typeof bootstrap>>()
    mocks.request.mockReturnValueOnce(old.promise).mockReturnValueOnce(fresh.promise)
    const view = render(<App />)
    await waitFor(() => expect(mocks.request).toHaveBeenCalledTimes(1))
    setAuthSession(session('fresh'))
    mocks.auth.sessionVersion++
    view.rerender(<App />)
    await waitFor(() => expect(mocks.request).toHaveBeenCalledTimes(2))
    await act(async () => fresh.resolve(bootstrap(true)))
    await waitFor(() => expect(workspace.status).toBe('ready'))
    await act(async () => old.resolve(bootstrap(false)))
    expect(workspace.status).toBe('ready')
    expect(workspace.data?.effectivePermissions?.authentication.recent).toBe(true)
    expect(mocks.auth.requireReauthentication).not.toHaveBeenCalled()
  })

  it('keeps an actual bootstrap failure visible instead of waiting indefinitely', async () => {
    setAuthSession(session('current'))
    mocks.request.mockResolvedValue({ data: null, errors: [], partial: false })
    render(<App />)
    await waitFor(() => expect(workspace.status).toBe('error'))
    expect(workspace.failure?.code).toBe('missing_overview_data')
  })
})
