// @vitest-environment jsdom
import { act, cleanup, render, screen } from '@testing-library/react'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import type { ComponentType, ReactNode } from 'react'

const fixture = vi.hoisted(() => ({ method: 'passkey', preferred: 'passkey', status: 'identifier_verified' }))
vi.mock('@tanstack/react-router', async (original) => ({
  ...await original<typeof import('@tanstack/react-router')>(),
  createFileRoute: () => (options: unknown) => ({
    options,
    useSearch: () => ({}),
    useParams: () => ({ method: fixture.method }),
    useLoaderData: () => ({
      loginId: 'login', csrfToken: 'csrf', locale: 'en-US', uiLocales: 'en-US',
      status: { status: fixture.status, preferred_credential_type: fixture.preferred, credential_types: ['password', 'otp', 'passkey', 'recovery_code'], requires_reauthentication: false },
    }),
  }),
}))
vi.mock('#/components/auth-shell', () => ({ AuthShell: ({ title, children }: { title: string; children: ReactNode }) => <main><h1>{title}</h1>{children}</main> }))
vi.mock('#/components/passkey-login', () => ({ PasskeyLogin: ({ primary }: { primary: boolean }) => <button data-primary={primary}>Passkey verification</button> }))

import { Route } from '#/routes/login.$method'
const Challenge = Route.options.component as ComponentType & { preload?: () => Promise<unknown> }
async function renderChallenge() {
  await Challenge.preload?.()
  let result: ReturnType<typeof render> | undefined
  await act(async () => { result = render(<Challenge />) })
  return result!
}

afterEach(cleanup)
beforeEach(() => { fixture.method = 'passkey'; fixture.preferred = 'passkey'; fixture.status = 'identifier_verified' })

it('opens the preferred passkey path without a password field or premature OTP links', async () => {
  const { container } = await renderChallenge()
  expect(screen.getByRole('button', { name: 'Passkey verification' }).getAttribute('data-primary')).toBe('true')
  expect(container.querySelector('input[name="credential"]')).toBeNull()
  expect(screen.queryByRole('link', { name: 'Use authenticator code' })).toBeNull()
  expect(screen.getByRole('link', { name: 'Use password' }).getAttribute('href')).toBe('/login/password?login_id=login&ui_locales=en-US')
})

it('uses the password path despite the saved passkey preference and links to the passkey path', async () => {
  fixture.method = 'password'
  const { container } = await renderChallenge()
  expect(container.querySelector('input[name="credential"][type="password"]')).not.toBeNull()
  expect(screen.queryByRole('button', { name: 'Passkey verification' })).toBeNull()
  expect(screen.getByRole('link', { name: 'Sign in with a passkey' }).getAttribute('href')).toBe('/login/passkey?login_id=login&ui_locales=en-US')
  expect(container.querySelector('form')?.getAttribute('action')).toBe('/login/password')
})

it('does not offer password re-entry after the password factor is complete', async () => {
  fixture.status = 'mfa_required'
  await renderChallenge()
  expect(screen.getByRole('button', { name: 'Passkey verification' })).toBeTruthy()
  expect(screen.queryByRole('link', { name: 'Use password' })).toBeNull()
})

it.each([
  ['otp', 'Enter verification code', '/login/recovery-code?login_id=login&ui_locales=en-US'],
  ['recovery-code', 'Enter recovery code', '/login/otp?login_id=login&ui_locales=en-US'],
])('renders the %s route and uses method paths for alternatives', async (method, title, alternative) => {
  fixture.method = method
  fixture.status = 'mfa_required'
  const { container } = await renderChallenge()
  expect(screen.getByRole('heading', { name: title })).toBeTruthy()
  expect(container.querySelector('form')?.getAttribute('action')).toBe(`/login/${method}`)
  expect(container.querySelector(`a[href="${alternative}"]`)).not.toBeNull()
})
