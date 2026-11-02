// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'

const mocks = vi.hoisted(() => ({ execute: vi.fn(), invalidate: vi.fn() }))
vi.mock('@tanstack/react-start', () => ({ useServerFn: () => mocks.execute }))
vi.mock('@tanstack/react-router', () => ({
  useRouter: () => ({ invalidate: mocks.invalidate }),
}))
vi.mock('#/lib/account-actions', () => ({ runAccountAction: vi.fn() }))

import { UserMenu } from './user-menu'

const user = { name: 'Ada Lovelace', email: 'ada@example.test' }

beforeEach(() => {
  vi.clearAllMocks()
  mocks.execute.mockResolvedValue({ ok: true })
  mocks.invalidate.mockResolvedValue(undefined)
  vi.stubGlobal('ResizeObserver', class { observe() {} unobserve() {} disconnect() {} })
  vi.stubGlobal('matchMedia', () => ({
    matches: false,
    addEventListener() {},
    removeEventListener() {},
    addListener() {},
    removeListener() {},
  }))
})

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

it('keeps sign out and adds switch account to the same menu', async () => {
  render(
    <UserMenu
      user={user}
      menuLabel="Account menu"
      signOutLabel="Sign out"
      switchAccountLabel="Switch account"
      requestFailedLabel="Unable to save changes"
    />,
  )

  fireEvent.click(screen.getByRole('button', { name: 'Account menu' }))
  const items = await screen.findAllByRole('menuitem')
  expect(items.map((item) => item.textContent)).toEqual([
    'Switch account',
    'Sign out',
  ])
})

it('starts a normal switch-account sign-in action', async () => {
  render(
    <UserMenu
      user={user}
      menuLabel="Account menu"
      signOutLabel="Sign out"
      switchAccountLabel="Switch account"
      requestFailedLabel="Unable to save changes"
    />,
  )

  fireEvent.click(screen.getByRole('button', { name: 'Account menu' }))
  fireEvent.click(await screen.findByRole('menuitem', { name: 'Switch account' }))

  await waitFor(() => {
    expect(mocks.execute).toHaveBeenCalledWith({
      data: { action: 'switch-account', values: {} },
    })
  })
  expect(mocks.invalidate).toHaveBeenCalledOnce()
})
