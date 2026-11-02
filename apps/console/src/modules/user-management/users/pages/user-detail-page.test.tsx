import { screen } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { EffectivePermissions } from '#/lib/workspace'
import { UserDetailLayout } from '#/modules/user-management/users/components/user-detail-layout'
import { UserDetailPage } from '#/modules/user-management/users/pages/user-detail-page'
import { renderWithLocale } from '#/test/render'

const mocks = vi.hoisted(() => ({ permissions: {} as EffectivePermissions }))
vi.mock('@tanstack/react-router', () => ({ useNavigate: () => vi.fn() }))
vi.mock('#/lib/auth/context', () => ({
  useAuth: () => ({ claims: { sub: 'operator' } }),
}))
vi.mock('#/lib/workspace', () => ({
  useWorkspace: () => ({
    status: 'ready',
    data: { effectivePermissions: mocks.permissions },
  }),
}))
vi.mock('#/modules/user-management/components/detail-tabs', () => ({
  UserDetailTabs: () => <nav />,
}))
vi.mock('#/components/step-up-panel', () => ({
  StepUpPanel: () => <div data-testid="step-up">Authentication required</div>,
}))
vi.mock(
  '#/modules/user-management/users/components/user-state-actions',
  () => ({
    UserStateActions: () => <button>More actions</button>,
  }),
)
vi.mock('#/modules/user-management/users/hooks/use-user-detail', () => ({
  useUserDetail: () => ({
    status: 'ready',
    partial: false,
    errors: [],
    user: {
      id: 'User:target',
      username: 'target',
      email: 'target@example.test',
      emailVerified: true,
      enabled: true,
      locked: false,
      lockedUntil: null,
      failedAttempts: 0,
      version: '5e7f4626-1618-4ef5-b227-703e5802d10d',
      givenName: null,
      familyName: null,
      nickname: null,
      middleName: null,
      profile: null,
      picture: null,
      website: null,
      birthdate: null,
      locale: null,
      theme: null,
      createdAt: '2026-10-26T00:00:00Z',
      updatedAt: null,
    },
  }),
}))
function permissions(
  effective: string[],
  requestable: string[] = [],
  aal2 = true,
): EffectivePermissions {
  return {
    role: null,
    effectiveScopes: effective,
    requestableScopes: requestable,
    grantedScopes: [],
    authentication: {
      acr: aal2 ? 'urn:identity:aal2' : 'urn:identity:aal1',
      authTime: null,
      aal2,
      recent: true,
    },
  }
}
beforeEach(() => {
  mocks.permissions = permissions(['management.user.read'])
})

describe('user detail action authority', () => {
  it('keeps identity before tabs and shows account fields without optimistic lock values', () => {
    renderWithLocale(
      <UserDetailLayout userId="User:target" current="/users/$userId">
        <UserDetailPage />
      </UserDetailLayout>,
    )
    const identity = screen.getByRole('heading', { level: 1, name: 'target' })
    const tabs = screen.getByRole('navigation')
    expect(
      identity.compareDocumentPosition(tabs) & Node.DOCUMENT_POSITION_FOLLOWING,
    ).toBeTruthy()
    expect(screen.getByRole('button', { name: 'Copy user ID' })).toBeTruthy()
    expect(screen.getByText('User:target')).toBeTruthy()
    expect(
      screen.queryByText('5e7f4626-1618-4ef5-b227-703e5802d10d'),
    ).toBeNull()
  })
  it('does not offer write controls to a reader with no requestable write permission', () => {
    renderWithLocale(
      <UserDetailLayout userId="User:target" current="/users/$userId">
        <UserDetailPage />
      </UserDetailLayout>,
    )
    expect(screen.queryByRole('button', { name: 'More actions' })).toBeNull()
    expect(screen.queryByTestId('step-up')).toBeNull()
  })
  it('offers requestable actions without starting authentication before an operation', () => {
    mocks.permissions = permissions(
      ['management.user.read'],
      ['management.user.state'],
      false,
    )
    renderWithLocale(
      <UserDetailLayout userId="User:target" current="/users/$userId">
        <UserDetailPage />
      </UserDetailLayout>,
    )
    expect(screen.queryByTestId('step-up')).toBeNull()
    expect(screen.getByRole('button', { name: 'More actions' })).toBeTruthy()
  })
  it('offers the state menu only after the state permission is effective', () => {
    mocks.permissions = permissions([
      'management.user.read',
      'management.user.state',
    ])
    renderWithLocale(
      <UserDetailLayout userId="User:target" current="/users/$userId">
        <UserDetailPage />
      </UserDetailLayout>,
    )
    expect(screen.getByRole('button', { name: 'More actions' })).toBeTruthy()
    expect(screen.queryByTestId('step-up')).toBeNull()
  })
})
