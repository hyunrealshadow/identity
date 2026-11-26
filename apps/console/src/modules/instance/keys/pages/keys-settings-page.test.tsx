import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import type { ConsoleKeysQuery } from '#/generated/graphql'
import { KeysSettingsPage } from '#/modules/instance/keys/pages/keys-settings-page'
import { renderWithLocale } from '#/test/render'

const mocks = vi.hoisted(() => ({
  navigate: vi.fn(),
  signIn: vi.fn(),
  rotate: vi.fn(),
  rotateAndRevoke: vi.fn(),
  revoke: vi.fn(),
  createSigning: vi.fn(),
  refresh: vi.fn(),
  toastSuccess: vi.fn(),
}))

vi.mock('@tanstack/react-router', () => ({
  useNavigate: () => mocks.navigate,
}))

vi.mock('#/lib/auth/context', () => ({
  useAuth: () => ({
    signIn: mocks.signIn,
    requireReauthentication: vi.fn(),
    reauthenticationPopup: null,
  }),
}))

vi.mock('#/lib/toast', () => ({
  toast: {
    success: mocks.toastSuccess,
    error: vi.fn(),
    info: vi.fn(),
  },
}))

vi.mock('../../settings/components/instance-settings-context', () => ({
  useInstanceSettings: () => ({
    permissionsPending: false,
    keys: {
      read: true,
      create: true,
      rotate: true,
      rotateAndRevoke: true,
      revoke: true,
    },
  }),
}))

vi.mock('#/lib/graphql/use-console-query', () => ({
  useConsoleQuery: (_document: unknown, variables: Record<string, unknown> | null) => {
    if (variables && 'filter' in variables) {
      const data: ConsoleKeysQuery = {
        keys: {
          totalCount: 1,
          pageInfo: {
            hasNextPage: false,
            hasPreviousPage: false,
            startCursor: null,
            endCursor: null,
          },
          edges: [
            {
              cursor: 'cursor-1',
              node: {
                id: 'key-1',
                keyId: 'kid-signing-1',
                use: 'SIGNING',
                status: 'ACTIVE',
                inUse: true,
                algorithms: ['ES256'],
                createdAt: '2026-11-01T00:00:00Z',
                expiresAt: '2027-11-01T00:00:00Z',
              } as ConsoleKeysQuery['keys']['edges'][number]['node'],
            },
          ],
        },
      }
      return {
        status: 'ready',
        data,
        errors: [],
        partial: false,
        forbidden: false,
        unauthorized: false,
        refreshing: false,
        refresh: mocks.refresh,
        refetchResult: vi.fn(),
      }
    }
    return {
      status: 'ready',
      data: { instanceMetadata: { jwksUri: 'https://identity.example.test/.well-known/keys' } },
      errors: [],
      partial: false,
      forbidden: false,
      unauthorized: false,
      refreshing: false,
      refresh: vi.fn(),
      refetchResult: vi.fn(),
    }
  },
}))

vi.mock('../hooks/key-mutations', () => ({
  useKeyMutations: () => ({
    createSigning: mocks.createSigning,
    rotate: mocks.rotate,
    rotateAndRevoke: mocks.rotateAndRevoke,
    revoke: mocks.revoke,
  }),
}))

async function openRotateConfirmation() {
  const actionsButton = await screen.findByRole('button', { name: 'Actions for kid-signing-1' })
  await userEvent.click(actionsButton)
  const menu = await screen.findByRole('menu')
  await userEvent.click(within(menu).getByRole('menuitem', { name: 'Rotate key' }))
  return await screen.findByRole('dialog')
}

beforeEach(() => {
  mocks.navigate.mockReset()
  mocks.signIn.mockReset()
  mocks.rotate.mockReset()
  mocks.rotateAndRevoke.mockReset()
  mocks.revoke.mockReset()
  mocks.createSigning.mockReset()
  mocks.refresh.mockReset()
  mocks.toastSuccess.mockReset()
})

describe('keys confirmation dialog', () => {
  it('stays open and renders feedback when key rotation returns an error payload', async () => {
    mocks.rotate.mockResolvedValueOnce({
      data: null,
      errors: [{ message: 'Key rotation failed', fields: [] }],
      failure: {
        kind: 'graphql',
        code: 'key_rotation_failed',
        requestId: 'req-key-rotate-1',
        traceId: 'trace-key-rotate-1',
      },
      forbidden: false,
      requestId: 'req-key-rotate-1',
      traceId: 'trace-key-rotate-1',
    })

    renderWithLocale(<KeysSettingsPage use="SIGNING" search={{}} />)
    const dialog = await openRotateConfirmation()

    await userEvent.click(within(dialog).getByRole('button', { name: 'Rotate key' }))

    await waitFor(() => {
      expect(within(screen.getByRole('dialog')).queryByRole('alert')).not.toBeNull()
    })
    expect(screen.queryByRole('dialog')).not.toBeNull()
    expect(mocks.toastSuccess).not.toHaveBeenCalled()
    expect(mocks.signIn).not.toHaveBeenCalled()
  })

  it('stays open on network failure and closes after a successful retry', async () => {
    mocks.rotate
      .mockRejectedValueOnce(new Error('network down'))
      .mockResolvedValueOnce({
        data: { rotateKey: { id: 'key-1' } },
        errors: [],
        forbidden: false,
      })

    renderWithLocale(<KeysSettingsPage use="SIGNING" search={{}} />)
    const dialog = await openRotateConfirmation()

    await userEvent.click(within(dialog).getByRole('button', { name: 'Rotate key' }))

    await waitFor(() => {
      expect(within(screen.getByRole('dialog')).queryByRole('alert')).not.toBeNull()
    })
    expect(mocks.toastSuccess).not.toHaveBeenCalled()

    await userEvent.click(
      within(screen.getByRole('dialog')).getByRole('button', { name: 'Rotate key' }),
    )

    await waitFor(() => {
      expect(screen.queryByRole('dialog')).toBeNull()
    })
    expect(mocks.toastSuccess).toHaveBeenCalledTimes(1)
    expect(mocks.signIn).toHaveBeenCalledTimes(1)
  })
})
