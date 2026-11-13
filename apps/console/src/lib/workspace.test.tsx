import { render, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { AuthProvider } from '#/lib/auth/context'
import {
  clearAuthSession,
  setAuthSession,
  type AuthSession,
} from '#/lib/auth/session'
import type { RuntimeConfig } from '#/lib/config'
import { LocaleProvider } from '#/lib/i18n'
import { RuntimeConfigProvider } from '#/lib/runtime-config'
import { WorkspaceProvider, useWorkspace } from '#/lib/workspace'
import { QueryTestProvider } from '#/test/render'

const mocks = vi.hoisted(() => ({
  beginAuthorization: vi.fn(),
  request: vi.fn(),
}))

vi.mock('#/lib/auth/oidc', async (importOriginal) => {
  const actual = await importOriginal<typeof import('#/lib/auth/oidc')>()
  return {
    ...actual,
    beginAuthorization: mocks.beginAuthorization,
  }
})

vi.mock('#/lib/graphql/use-graphql', () => ({
  useGraphQL: () => mocks.request,
}))

const config: RuntimeConfig = {
  issuer: 'https://issuer.example.test',
  graphqlUrl: 'https://issuer.example.test/graphql',
  clientId: 'console',
  redirectUri: `${window.location.origin}/callback`,
  postLogoutRedirectUri: `${window.location.origin}/signed-out`,
  accountUrl: 'https://account.example.test',
  scope:
    'openid management.user.read management.user.update management.group.read',
  displayName: 'Identity Console',
  environment: 'test',
}

function session(): AuthSession {
  const now = Math.floor(Date.now() / 1000)
  return {
    accessToken: 'access-token',
    idToken: 'id-token',
    expiresAt: Date.now() + 60_000,
    scope: config.scope,
    grantedScopes: ['openid', 'management.user.read'],
    claims: {
      sub: 'user-a',
      iss: config.issuer,
      aud: config.clientId,
      exp: now + 3_600,
    },
    endSessionEndpoint: `${config.issuer}/logout`,
  }
}

function bootstrap(permissions: {
  requestableScopes: string[]
  effectiveScopes: string[]
  authentication: { aal2: boolean; recent: boolean }
}) {
  return {
    data: {
      effectivePermissions: {
        grantedScopes: [],
        ...permissions,
      },
      instanceInfo: {
        name: 'Identity',
        environment: 'test',
        issuer: config.issuer,
        version: '0.1.0',
      },
    },
    errors: [],
    partial: false,
    unauthorized: false,
    forbidden: false,
  }
}

let workspaceApi: ReturnType<typeof useWorkspace> | undefined

function Probe() {
  workspaceApi = useWorkspace()
  return null
}

function renderWorkspace() {
  return render(
    <QueryTestProvider>
      <RuntimeConfigProvider config={config}>
        <LocaleProvider>
          <AuthProvider>
            <WorkspaceProvider>
              <Probe />
            </WorkspaceProvider>
          </AuthProvider>
        </LocaleProvider>
      </RuntimeConfigProvider>
    </QueryTestProvider>,
  )
}

beforeEach(() => {
  vi.restoreAllMocks()
  clearAuthSession()
  window.sessionStorage.clear()
  mocks.beginAuthorization.mockReset().mockResolvedValue(undefined)
  mocks.request.mockReset()
  workspaceApi = undefined
})

describe('workspace operation-based reauthentication', () => {
  it('allows a read-only user with all effective requestable permissions despite stale recency', async () => {
    setAuthSession(session())
    mocks.request.mockResolvedValue(
      bootstrap({
        requestableScopes: ['management.user.read', 'management.group.read'],
        effectiveScopes: ['management.user.read', 'management.group.read'],
        authentication: { aal2: true, recent: false },
      }),
    )
    renderWorkspace()

    await waitFor(() => expect(workspaceApi?.status).toBe('ready'))
    expect(mocks.beginAuthorization).not.toHaveBeenCalled()
  })

  it('never redirects a principal who has no requestable permissions', async () => {
    setAuthSession(session())
    mocks.request.mockResolvedValue(
      bootstrap({
        requestableScopes: [],
        effectiveScopes: [],
        authentication: { aal2: false, recent: false },
      }),
    )
    renderWorkspace()

    await waitFor(() => expect(workspaceApi?.status).toBe('ready'))
    expect(mocks.beginAuthorization).not.toHaveBeenCalled()
  })

  it('keeps stale write capabilities on the page until an operation actually needs them', async () => {
    setAuthSession(session())
    mocks.request.mockResolvedValue(
      bootstrap({
        requestableScopes: [
          'management.user.read',
          'management.user.update',
          'management.group.read',
        ],
        effectiveScopes: ['management.user.read', 'management.group.read'],
        authentication: { aal2: true, recent: false },
      }),
    )
    renderWorkspace()

    await waitFor(() => expect(workspaceApi?.status).toBe('ready'))
    expect(
      workspaceApi?.data?.effectivePermissions?.authentication.recent,
    ).toBe(false)
    expect(mocks.beginAuthorization).not.toHaveBeenCalled()
  })
})
