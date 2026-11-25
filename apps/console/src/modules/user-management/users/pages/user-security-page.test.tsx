import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import type { EffectivePermissions } from '#/lib/workspace'
import { UserDetailContext } from '#/modules/user-management/users/components/user-detail-context'
import type { UserDetailState } from '#/modules/user-management/users/hooks/use-user-detail'
import type { ProjectedUser } from '#/modules/user-management/users/lib/user-form'
import { UserSecurityPage } from '#/modules/user-management/users/pages/user-security-page'
import { renderWithLocale } from '#/test/render'

const mocks = vi.hoisted(() => ({
  subject: 'User:operator',
  permissions: {} as EffectivePermissions,
  sessions: [] as Array<{
    id: string
    deviceName: string | null
    deviceType: string | null
    osName: string | null
    osVersion: string | null
    browserName: string | null
    browserVersion: string | null
    ipAddress: string | null
    lastActiveAt: string
    createdAt: string
  }>,
  refreshSessions: vi.fn().mockResolvedValue(null),
  resetPassword: vi.fn(),
  resetMfa: vi.fn(),
  revokeSessions: vi.fn(),
  update: vi.fn(),
}))

vi.mock('#/lib/auth/context', () => ({
  useAuth: () => ({ claims: { sub: mocks.subject } }),
}))
vi.mock('#/lib/runtime-config', () => ({
  useRuntimeConfig: () => ({ accountUrl: 'https://login.example.test/account' }),
}))
vi.mock('#/lib/workspace', () => ({
  useWorkspace: () => ({
    status: 'ready',
    data: { effectivePermissions: mocks.permissions },
  }),
}))
vi.mock('#/lib/graphql/use-console-query', () => ({
  useConsoleQuery: () => ({
    status: 'ready',
    data: {
      user: {
        id: 'User:target',
        sessions: {
          pageInfo: { hasNextPage: false, endCursor: null },
          edges: mocks.sessions.map((node) => ({ cursor: node.id, node })),
        },
      },
    },
    errors: [],
    partial: false,
    forbidden: false,
    unauthorized: false,
    refreshing: false,
    refresh: mocks.refreshSessions,
    refetchResult: vi.fn(),
  }),
}))
vi.mock('#/modules/user-management/users/hooks/user-mutations', () => ({
  useUserMutations: () => ({
    resetPassword: mocks.resetPassword,
    resetMfa: mocks.resetMfa,
    revokeSessions: mocks.revokeSessions,
    update: mocks.update,
  }),
}))

function permissions(effective: string[]): EffectivePermissions {
  return {
    effectiveScopes: effective,
    requestableScopes: [],
    grantedScopes: [],
    authentication: { acr: 'urn:identity:aal2', authTime: null, aal2: true, recent: true },
  }
}

function makeUser(overrides: Partial<ProjectedUser> = {}): ProjectedUser {
  return {
    id: 'User:target',
    username: 'target',
    email: 'target@example.test',
    emailVerified: true,
    enabled: true,
    locked: false,
    lockedUntil: null,
    failedAttempts: 0,
    invitation: null,
    requiredActions: [],
    authenticationMethods: {
      password: true,
      authenticatorApp: true,
      recoveryCodes: true,
      passkey: false,
    },
    version: '5e7f4626-1618-4ef5-b227-703e5802d10d',
    givenName: null,
    familyName: null,
    middleName: null,
    nickname: null,
    profile: null,
    picture: null,
    website: null,
    birthdate: null,
    locale: null,
    theme: null,
    createdAt: '2026-10-26T00:00:00Z',
    updatedAt: null,
    ...overrides,
  }
}

function makeDetail(
  user: ProjectedUser | null,
  status: UserDetailState['status'] = 'ready',
  reload = vi.fn().mockResolvedValue({ kind: 'ready', user }),
): UserDetailState {
  return {
    status,
    user,
    notFound: false,
    errors: [],
    partial: false,
    forbidden: false,
    unauthorized: false,
    refreshing: false,
    refresh: reload,
    reload,
  }
}

function renderSecurityPage(detail: UserDetailState) {
  return renderWithLocale(
    <UserDetailContext value={detail}>
      <UserSecurityPage />
    </UserDetailContext>,
  )
}

describe('UserSecurityPage', () => {
  beforeEach(() => {
    mocks.subject = 'User:operator'
    mocks.permissions = permissions(['management.user.read', 'management.user.write'])
    mocks.sessions = [
      {
        id: 'Session:1',
        deviceName: null,
        deviceType: 'desktop',
        osName: 'Linux',
        osVersion: null,
        browserName: 'Firefox',
        browserVersion: '130',
        ipAddress: '198.51.100.10',
        lastActiveAt: '2026-11-24T10:00:00Z',
        createdAt: '2026-11-24T09:00:00Z',
      },
    ]
    mocks.refreshSessions.mockClear()
    mocks.resetPassword.mockReset()
    mocks.resetMfa.mockReset()
    mocks.revokeSessions.mockReset()
    mocks.update.mockReset()
  })

  it('shows where the invitation email stands and follows a queued one', async () => {
    const invited = (delivery: NonNullable<ProjectedUser['invitation']>['delivery']) =>
      makeUser({
        invitation: {
          sentAt: '2026-11-24T10:00:00Z',
          expiresAt: '2099-12-01T10:00:00Z',
          delivery,
        },
        authenticationMethods: {
          password: false,
          authenticatorApp: false,
          recoveryCodes: false,
          passkey: false,
        },
      })

    const failed = renderSecurityPage(
      makeDetail(
        invited({ status: 'FAILED', failure: 'INVALID_ADDRESS', updatedAt: '2026-11-24T10:00:05Z' }),
      ),
    )
    expect(screen.getByText(/could not be delivered.*the mail server refused the address/)).toBeTruthy()
    expect(screen.getByRole('button', { name: 'Send again' })).toBeTruthy()
    failed.unmount()

    const delivered = renderSecurityPage(
      makeDetail(invited({ status: 'DELIVERED', failure: null, updatedAt: '2026-11-24T10:00:01Z' })),
    )
    expect(screen.getByText(/The mail server accepted the invitation email/)).toBeTruthy()
    delivered.unmount()

    vi.useFakeTimers()
    try {
      const refresh = vi.fn().mockResolvedValue({ kind: 'ready', user: null })
      renderSecurityPage(
        makeDetail(
          invited({ status: 'QUEUED', failure: null, updatedAt: '2026-11-24T10:00:00Z' }),
          'ready',
          refresh,
        ),
      )
      expect(screen.getByText('The invitation email is being sent')).toBeTruthy()
      await vi.advanceTimersByTimeAsync(3_100)
      expect(refresh).toHaveBeenCalledTimes(1)
    } finally {
      vi.useRealTimers()
    }
  })

  it('renders loading skeleton before user detail arrives', () => {
    renderSecurityPage(makeDetail(null, 'loading'))
    expect(screen.getByRole('status', { name: 'Loading user details…' })).toBeTruthy()
  })

  it('disables Clear MFA and hides password-change toggle when user has no password', () => {
    renderSecurityPage(
      makeDetail(
        makeUser({
          requiredActions: ['CHANGE_PASSWORD'],
          authenticationMethods: {
            password: false,
            authenticatorApp: false,
            recoveryCodes: false,
            passkey: true,
          },
        }),
      ),
    )

    expect(screen.queryByText('Change password at next sign-in')).toBeNull()
    expect(
      (screen.getByRole('button', { name: 'Clear second factors' }) as HTMLButtonElement).disabled,
    ).toBe(true)
  })

  it('shows password-change toggle and disables Clear MFA when user has no second factors', () => {
    renderSecurityPage(
      makeDetail(
        makeUser({
          requiredActions: ['CHANGE_PASSWORD'],
          authenticationMethods: {
            password: true,
            authenticatorApp: false,
            recoveryCodes: false,
            passkey: false,
          },
        }),
      ),
    )

    expect(screen.getByText('On: the user must set a new password at the next sign-in.')).toBeTruthy()
    expect(screen.getByRole('button', { name: 'Stop requiring' })).toBeTruthy()
    expect(
      (screen.getByRole('button', { name: 'Clear second factors' }) as HTMLButtonElement).disabled,
    ).toBe(true)
  })

  it('adds and removes only the password change in the required actions', async () => {
    const ok = {
      data: { updateUser: { user: makeUser() } },
      errors: [],
      partial: false,
      forbidden: false,
      unauthorized: false,
    }
    mocks.update.mockResolvedValue(ok)
    const { unmount } = renderSecurityPage(makeDetail(makeUser({ requiredActions: [] })))
    await userEvent.click(screen.getByRole('button', { name: 'Require' }))
    await waitFor(() => {
      expect(mocks.update).toHaveBeenCalledWith({
        id: 'User:target',
        expectedVersion: '5e7f4626-1618-4ef5-b227-703e5802d10d',
        requiredActions: ['CHANGE_PASSWORD'],
      })
    })
    unmount()

    mocks.update.mockClear()
    renderSecurityPage(makeDetail(makeUser({ requiredActions: ['CHANGE_PASSWORD'] })))
    await userEvent.click(screen.getByRole('button', { name: 'Stop requiring' }))
    await waitFor(() => {
      expect(mocks.update).toHaveBeenCalledWith({
        id: 'User:target',
        expectedVersion: '5e7f4626-1618-4ef5-b227-703e5802d10d',
        requiredActions: [],
      })
    })
  })

  it('resets another user password, reveals temporary password once, and reloads immediately', async () => {
    const reload = vi.fn().mockResolvedValue({ kind: 'ready', user: makeUser() })
    mocks.resetPassword.mockResolvedValue({
      data: {
        resetUserPassword: {
          userId: 'User:target',
          version: 'v2',
          temporaryPassword: 'Ab9!xKmP2@qR7#wZ',
        },
      },
      errors: [],
      partial: false,
      forbidden: false,
      unauthorized: false,
    })
    renderSecurityPage(makeDetail(makeUser(), 'ready', reload))

    await userEvent.click(screen.getByRole('button', { name: 'Reset password' }))
    const dialog = await screen.findByRole('dialog', { name: 'Reset password' })
    await userEvent.click(within(dialog).getByRole('button', { name: 'Reset password' }))

    await waitFor(() => {
      expect(mocks.resetPassword).toHaveBeenCalledWith({
        id: 'User:target',
        expectedVersion: '5e7f4626-1618-4ef5-b227-703e5802d10d',
      })
    })
    expect(await screen.findByText('Ab9!xKmP2@qR7#wZ')).toBeTruthy()
    expect(reload).toHaveBeenCalledTimes(1)
    expect(mocks.refreshSessions).toHaveBeenCalledTimes(1)
  })

  it('directs own account credential actions to the account center instead of offering self reset or clear', () => {
    mocks.subject = 'User:target'
    renderSecurityPage(makeDetail(makeUser()))

    expect(screen.queryByRole('button', { name: 'Reset password' })).toBeNull()
    expect(screen.queryByRole('button', { name: 'Clear second factors' })).toBeNull()
    expect(screen.queryByRole('button', { name: 'Require' })).toBeNull()
    const link = screen.getByRole('link', { name: 'Manage in account center' })
    expect(link.getAttribute('href')).toBe('https://login.example.test/account')
  })

  it('revokes a single session and revokes all sessions', async () => {
    mocks.revokeSessions.mockResolvedValue({
      data: { revokeUserSessions: { userId: 'User:target', version: 'v2' } },
      errors: [],
      partial: false,
      forbidden: false,
      unauthorized: false,
    })
    renderSecurityPage(makeDetail(makeUser()))

    await userEvent.click(screen.getByRole('button', { name: 'Actions for Firefox 130 / Linux' }))
    await userEvent.click(await screen.findByRole('menuitem', { name: 'Revoke' }))
    const oneDialog = await screen.findByRole('dialog', { name: 'Revoke session' })
    await userEvent.click(within(oneDialog).getByRole('button', { name: 'Revoke' }))
    await waitFor(() => {
      expect(mocks.revokeSessions).toHaveBeenCalledWith({
        id: 'User:target',
        sessionIds: ['Session:1'],
      })
    })

    await userEvent.click(screen.getByRole('button', { name: 'Revoke all' }))
    const allDialog = await screen.findByRole('dialog', { name: 'Revoke all sessions' })
    await userEvent.click(within(allDialog).getByRole('button', { name: 'Revoke all' }))
    await waitFor(() => {
      expect(mocks.revokeSessions).toHaveBeenCalledWith({
        id: 'User:target',
        sessionIds: null,
      })
    })
  })
})
