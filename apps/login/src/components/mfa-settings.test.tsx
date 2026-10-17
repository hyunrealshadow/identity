// @vitest-environment jsdom
import { act, cleanup, render, screen, within } from '@testing-library/react'
import type { ComponentType } from 'react'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'

const fixture = vi.hoisted(() => ({
  search: {} as { setup?: string },
  passkeys: [] as Array<{ id: string; name: string }>,
  remaining: 0,
  enrollment: undefined as { secret: string; otp_auth_uri: string; enrollment_token: string; recovery_codes: Array<string> } | undefined,
  navigate: vi.fn(),
}))
vi.mock('@tanstack/react-router', async (original) => ({
  ...await original<typeof import('@tanstack/react-router')>(),
  createFileRoute: () => (options: unknown) => ({ options, useSearch: () => fixture.search }),
  useNavigate: () => fixture.navigate,
}))
vi.mock('#/routes/account/route', () => ({ useAccount: () => ({
  locale: 'en-US', flash: {}, mfa: { enrollment: fixture.enrollment },
  data: { viewer: { account: { username: 'person' }, passkeys: fixture.passkeys,
    security: { totpEnabled: false, preferredMfaMethod: 'passkey', recoveryCodesRemaining: fixture.remaining } } },
}) }))
vi.mock('#/components/passkey-settings', () => ({ PasskeySettings: () => null }))
vi.mock('#/components/mfa-priority', () => ({ MfaPriority: () => null }))
vi.mock('#/components/account-action-form', () => ({ AccountActionForm: ({ children }: { children: React.ReactNode }) => <form>{children}</form> }))
vi.mock('#/components/totp-qr-code', () => ({ TotpQrCode: () => <div data-testid="totp-qr" /> }))

import { Route } from '#/routes/account/security'
const Security = Route.options.component as ComponentType & { preload?: () => Promise<unknown> }
async function renderSecurity() {
  await Security.preload?.()
  await act(async () => { render(<Security />) })
}

beforeEach(() => {
  fixture.search = { setup: 'mfa' }
  fixture.passkeys = []
  fixture.remaining = 0
  fixture.enrollment = { secret: 'secret', otp_auth_uri: 'otpauth://totp/demo', enrollment_token: 'protected', recovery_codes: [] }
  vi.stubGlobal('ResizeObserver', class { observe() {} unobserve() {} disconnect() {} })
  vi.stubGlobal('matchMedia', () => ({ matches: false, addEventListener() {}, removeEventListener() {}, addListener() {}, removeListener() {} }))
})
afterEach(() => { cleanup(); vi.unstubAllGlobals() })

it('skips recovery-code saving when TOTP reuses the account recovery codes', async () => {
  await renderSecurity()
  const dialog = await screen.findByRole('dialog')
  expect(within(dialog).getByRole('button', { name: 'Scan QR code' })).toBeTruthy()
  expect(within(dialog).getByRole('heading', { name: 'Configure your authenticator' })).toBeTruthy()
  expect(within(dialog).getAllByRole('listitem')).toHaveLength(2)
  expect(within(dialog).queryByText('Save these recovery codes before adding a verification method')).toBeNull()
})

it('requires saving newly generated codes before configuring the authenticator', async () => {
  fixture.enrollment!.recovery_codes = ['ABCD-EFGH']
  await renderSecurity()
  const dialog = await screen.findByRole('dialog')
  expect(within(dialog).getByRole('heading', { name: 'Save your recovery codes' })).toBeTruthy()
  expect(within(dialog).queryByRole('button', { name: 'Scan QR code' })).toBeNull()
  expect(within(dialog).getAllByRole('listitem')).toHaveLength(3)
})

it('shows shared recovery-code management for passkey-only accounts', async () => {
  fixture.search = {}
  fixture.enrollment = undefined
  fixture.passkeys = [{ id: 'key', name: 'Laptop' }]
  fixture.remaining = 10
  await renderSecurity()
  expect(screen.getByText('Recovery codes')).toBeTruthy()
  expect(screen.getByText('10 recovery codes remaining')).toBeTruthy()
})
