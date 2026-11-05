import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import type { ConsolePermissionQuery } from '#/generated/graphql'
import {
  clearAuthSession,
  setAuthSession,
  type AuthSession,
} from '#/lib/auth/session'
import { LocaleTestProvider } from '#/test/render'
import { readPendingPermissionStateConfirmation } from '#/modules/client-management/resources/permissions/lib/permissions-state-confirmation'
import { PermissionStateDialog } from './permission-detail-page'

const mutations = vi.hoisted(() => ({
  enable: vi.fn(),
  disable: vi.fn(),
  requireReauthentication: vi.fn(),
}))

vi.mock('#/lib/auth/context', () => ({
  useAuth: () => ({
    requireReauthentication: mutations.requireReauthentication,
    reauthenticationPopup: null,
  }),
}))

vi.mock(
  '#/modules/client-management/resources/permissions/hooks/permission-mutations',
  () => ({ usePermissionMutations: () => mutations }),
)

function session(subject = 'user-a'): AuthSession {
  return {
    accessToken: 'access-token-value',
    idToken: 'id-token-value',
    expiresAt: Date.now() + 60_000,
    scope: 'openid',
    grantedScopes: ['openid'],
    claims: {
      sub: subject,
      iss: 'https://identity.example.test',
      aud: 'console',
      exp: Math.floor(Date.now() / 1000) + 60,
    },
  }
}

function permission(): NonNullable<ConsolePermissionQuery['permission']> {
  return {
    id: 'permission-1',
    code: 'users.read',
    version: '76d4117a-fcd5-4609-b706-bd34bdbbdd46',
    enabled: false,
    builtIn: false,
    names: [{ locale: 'en-US', value: 'Read users' }],
    descriptions: [],
    createdAt: '2026-10-30T00:00:00.000Z',
    updatedAt: '2026-10-30T00:00:00.000Z',
    resource: null,
  } as unknown as NonNullable<ConsolePermissionQuery['permission']>
}

beforeEach(() => {
  setAuthSession(session())
  mutations.enable.mockReset()
  mutations.disable.mockReset()
  mutations.requireReauthentication.mockReset().mockResolvedValue(undefined)
})

afterEach(() => {
  clearAuthSession()
})

describe('permission state confirmation reauthentication survival', () => {
  it('retains a user-confirmed mutation across reauthentication and retries with its original CAS', async () => {
    const user = userEvent.setup()
    const target = permission()
    const onCommitted = vi.fn()
    mutations.enable
      .mockResolvedValueOnce({
        data: null,
        errors: [],
        forbidden: false,
        stepUp: { source: 'graphql', acrValues: 'aal2', maxAge: 300 },
      })
      .mockResolvedValueOnce({
        data: {
          enablePermission: { permissionId: target.id, version: 'committed' },
        },
        errors: [],
        forbidden: false,
      })
    const view = render(
      <LocaleTestProvider>
        <PermissionStateDialog
          action="enable"
          permission={target}
          onCommitted={onCommitted}
        />
      </LocaleTestProvider>,
    )
    expect(screen.queryByRole('dialog')).toBeNull()
    await user.click(screen.getByRole('button', { name: 'Enable permission' }))
    const confirmation = await screen.findByRole('dialog')
    await user.click(
      within(confirmation).getByRole('button', { name: 'Enable permission' }),
    )
    await waitFor(() =>
      expect(mutations.requireReauthentication).toHaveBeenCalledTimes(1),
    )
    expect(mutations.enable).toHaveBeenCalledWith({
      id: target.id,
      expectedVersion: target.version,
    })
    expect(readPendingPermissionStateConfirmation(target.id)).toEqual({
      permissionId: target.id,
      action: 'enable',
      expectedVersion: target.version,
    })
    view.unmount()

    // Authentication reloads the workspace; a concurrent read may return a
    // newer CAS, which must not silently replace the user's pending input.
    setAuthSession(session())
    render(
      <LocaleTestProvider>
        <PermissionStateDialog
          action="enable"
          permission={{
            ...target,
            version: '2d5eb0d1-e713-4537-b886-74ae673ad3bd',
          }}
          onCommitted={onCommitted}
        />
      </LocaleTestProvider>,
    )

    const restored = await screen.findByRole('dialog')
    expect(screen.getByText('Enable this permission?')).toBeTruthy()
    expect(screen.getByText('Read users')).toBeTruthy()
    expect(mutations.enable).toHaveBeenCalledTimes(1)
    expect(mutations.disable).not.toHaveBeenCalled()
    expect(onCommitted).not.toHaveBeenCalled()
    await user.click(
      within(restored).getByRole('button', { name: 'Enable permission' }),
    )
    await waitFor(() => expect(onCommitted).toHaveBeenCalledTimes(1))
    expect(mutations.enable).toHaveBeenNthCalledWith(2, {
      id: target.id,
      expectedVersion: target.version,
    })
    expect(readPendingPermissionStateConfirmation(target.id)).toBeNull()
  })
})
