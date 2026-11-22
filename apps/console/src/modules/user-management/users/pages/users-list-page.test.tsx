import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import type { ReactNode } from 'react'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import type { EffectivePermissions } from '#/lib/workspace'
import type { UserSummary } from '#/modules/user-management/users/hooks/use-users'
import { UsersListPage } from '#/modules/user-management/users/pages/users-list-page'
import { renderWithLocale } from '#/test/render'

const mocks = vi.hoisted(() => ({
  permissions: {} as EffectivePermissions,
  navigate: vi.fn(),
  users: [] as UserSummary[],
}))

vi.mock('@tanstack/react-router', () => ({
  useNavigate: () => mocks.navigate,
  Link: ({ children, to }: { children: ReactNode; to: string }) => <a href={to}>{children}</a>,
}))
vi.mock('#/lib/auth/context', () => ({
  useAuth: () => ({ claims: { sub: 'User:operator' } }),
}))
vi.mock('#/lib/workspace', () => ({
  useWorkspace: () => ({
    status: 'ready',
    data: { effectivePermissions: mocks.permissions },
    refresh: vi.fn(),
  }),
}))
vi.mock('#/modules/user-management/users/hooks/user-mutations', () => ({
  useUserMutations: () => ({ enable: vi.fn(), disable: vi.fn(), unlock: vi.fn() }),
}))
vi.mock('#/modules/user-management/users/hooks/use-users', () => ({
  useUsers: () => ({
    status: 'ready',
    data: {
      totalCount: mocks.users.length,
      pageInfo: { hasNextPage: false, hasPreviousPage: false, startCursor: null, endCursor: null },
      edges: mocks.users.map((node) => ({ cursor: node.id, node })),
    },
    errors: [],
    partial: false,
    forbidden: false,
    refreshing: false,
    refresh: vi.fn().mockResolvedValue(undefined),
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

function user(id: string, username: string, overrides: Partial<UserSummary> = {}): UserSummary {
  return {
    id,
    username,
    email: `${username}@example.test`,
    emailVerified: true,
    enabled: true,
    locked: false,
    lockedUntil: null,
    failedAttempts: 0,
    version: '00000000-0000-0000-0000-000000000001',
    createdAt: '2026-11-01T00:00:00Z',
    updatedAt: '2026-11-01T00:00:00Z',
    ...overrides,
  }
}

async function openMenu(username: string) {
  await userEvent.click(screen.getByRole('button', { name: `Actions for ${username}` }))
  const menu = await screen.findByRole('menu')
  return within(menu)
    .getAllByRole('menuitem')
    .map((item) => item.textContent)
}

describe('UsersListPage row actions', () => {
  beforeEach(() => {
    mocks.navigate.mockReset()
    mocks.users = [
      user('User:alice', 'alice'),
      user('User:operator', 'operator'),
      user('User:bob', 'bob', { enabled: false, locked: true }),
    ]
  })

  it('offers state changes in a fixed order and confirms before disabling', async () => {
    mocks.permissions = permissions(['management.user.read', 'management.user.write'])
    renderWithLocale(<UsersListPage search={{}} />)

    expect(await openMenu('alice')).toEqual(['View details', 'Edit profile', 'Copy ID', 'Disable'])
    await userEvent.click(screen.getByRole('menuitem', { name: 'Disable' }))
    expect(await screen.findByRole('dialog', { name: 'Disable this user?' })).toBeTruthy()
  })

  it('offers unlock and enable on a locked, disabled user', async () => {
    mocks.permissions = permissions(['management.user.read', 'management.user.write'])
    renderWithLocale(<UsersListPage search={{}} />)

    expect(await openMenu('bob')).toEqual([
      'View details',
      'Edit profile',
      'Copy ID',
      'Unlock',
      'Enable',
    ])
  })

  it('never offers disabling the signed-in user from the list', async () => {
    mocks.permissions = permissions(['management.user.read', 'management.user.write'])
    renderWithLocale(<UsersListPage search={{}} />)

    expect(await openMenu('operator')).not.toContain('Disable')
  })

  it('hides write actions from read-only operators', async () => {
    mocks.permissions = permissions(['management.user.read'])
    renderWithLocale(<UsersListPage search={{}} />)

    expect(await openMenu('alice')).toEqual(['View details', 'Copy ID'])
  })
})
