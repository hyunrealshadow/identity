// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import type { ReactElement } from 'react'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'

const mocks = vi.hoisted(() => ({ execute: vi.fn(), invalidate: vi.fn(), navigate: vi.fn() }))
vi.mock('@tanstack/react-start', () => ({ useServerFn: () => mocks.execute }))
vi.mock('@tanstack/react-router', () => ({ useRouter: () => ({ invalidate: mocks.invalidate }), useNavigate: () => mocks.navigate }))
vi.mock('#/lib/account-actions', () => ({ runAccountAction: vi.fn() }))

import { MfaPriority } from './mfa-priority'

const queryClient = new QueryClient()

function renderWithQuery(ui: ReactElement) {
  return render(<QueryClientProvider client={queryClient}>{ui}</QueryClientProvider>)
}

beforeEach(() => {
  vi.clearAllMocks()
  mocks.execute.mockReset().mockResolvedValue({ ok: true })
  mocks.invalidate.mockResolvedValue(undefined)
  vi.stubGlobal('ResizeObserver', class { observe() {} unobserve() {} disconnect() {} })
  vi.stubGlobal('matchMedia', () => ({ matches: false, addEventListener() {}, removeEventListener() {}, addListener() {}, removeListener() {} }))
})
afterEach(() => { cleanup(); vi.unstubAllGlobals() })

it('opens HeroUI radios without reauthentication and saves the selected priority', async () => {
  renderWithQuery(<MfaPriority locale="en-US" preference="passkey" totpEnabled />)
  expect(screen.queryByRole('radio')).toBeNull()
  fireEvent.click(screen.getByRole('button', { name: 'Change' }))
  const dialog = await screen.findByRole('dialog')
  expect(mocks.execute).not.toHaveBeenCalled()
  expect(within(dialog).queryByRole('combobox')).toBeNull()
  fireEvent.click(within(dialog).getByRole('radio', { name: 'Password and authenticator app first' }))
  fireEvent.click(within(dialog).getByRole('button', { name: 'Save preference' }))
  await waitFor(() => expect(mocks.execute).toHaveBeenLastCalledWith({ data: {
    action: 'update-mfa-preference', values: { preferred_mfa_method: 'otp' },
  } }))
  await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
})

it('disables authenticator preference until TOTP has been enabled', async () => {
  renderWithQuery(<MfaPriority locale="en-US" preference="passkey" totpEnabled={false} />)
  fireEvent.click(screen.getByRole('button', { name: 'Change' }))
  const dialog = await screen.findByRole('dialog')
  expect(within(dialog).getByRole('radio', { name: 'Password and authenticator app first' }).getAttribute('aria-disabled')).toBe('true')
})

it('keeps the preference dialog open when saving fails', async () => {
  mocks.execute.mockResolvedValue({ ok: false })
  renderWithQuery(<MfaPriority locale="en-US" preference="passkey" totpEnabled />)
  fireEvent.click(screen.getByRole('button', { name: 'Change' }))
  const dialog = await screen.findByRole('dialog')
  expect(mocks.execute).not.toHaveBeenCalled()
  fireEvent.click(within(dialog).getByRole('button', { name: 'Save preference' }))
  await waitFor(() => expect(mocks.invalidate).toHaveBeenCalledTimes(1))
  expect(screen.getByRole('dialog')).toBeTruthy()
})
