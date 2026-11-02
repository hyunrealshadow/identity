// @vitest-environment jsdom
import { cleanup, render, screen } from '@testing-library/react'
import { afterEach, expect, it } from 'vitest'

import { LoginMethodAlternatives } from './login-method-alternatives'
import type { LoginStatusResponse } from '#/lib/identity-types'

afterEach(cleanup)
const status: LoginStatusResponse = {
  id: 'login', status: 'mfa_required', prompt: '',
  requires_reauthentication: true,
  credential_types: ['password', 'otp', 'recovery_code', 'passkey'],
}

it('offers only other enrolled second factors during bound reauthentication', () => {
  render(<LoginMethodAlternatives currentMethod="otp" status={status} loginId="login" locale="en-US" />)
  expect(screen.queryByRole('link', { name: 'Use password' })).toBeNull()
  expect(screen.getByRole('link', { name: 'Use a recovery code' })).toBeTruthy()
  expect(screen.getByRole('link', { name: 'Sign in with a passkey' })).toBeTruthy()
})

it('does not offer password after the first factor has been verified', () => {
  render(<LoginMethodAlternatives currentMethod="otp" status={{ ...status, status: 'mfa_required', requires_reauthentication: false }} loginId="login" locale="en-US" />)
  expect(screen.queryByRole('link', { name: 'Use password' })).toBeNull()
})

it('retains password as an alternative during ordinary first-factor login', () => {
  render(<LoginMethodAlternatives currentMethod="passkey" status={{ ...status, status: 'identifier_verified', requires_reauthentication: false }} loginId="login" locale="en-US" />)
  expect(screen.getByRole('link', { name: 'Use password' })).toBeTruthy()
  expect(screen.queryByRole('link', { name: 'Use a recovery code' })).toBeNull()
})

it('does not treat a reauthentication flag as the MFA phase', () => {
  render(<LoginMethodAlternatives currentMethod="passkey" status={{ ...status, status: 'identifier_verified', requires_reauthentication: true }} loginId="login" locale="en-US" />)
  expect(screen.getByRole('link', { name: 'Use password' })).toBeTruthy()
  expect(screen.queryByRole('link', { name: 'Use a recovery code' })).toBeNull()
})
