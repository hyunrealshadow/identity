// @vitest-environment jsdom
import { cleanup, render, screen } from '@testing-library/react'
import { afterEach, expect, it } from 'vitest'
import { LoginClient } from './login-client'

afterEach(cleanup)

it('shows the registered logo and legal links to the person signing in', () => {
  render(<LoginClient locale="en-US" client={{
    name: 'Example app', logo_uri: 'https://rp.example/logo.png',
    policy_uri: 'https://rp.example/privacy', tos_uri: 'https://rp.example/terms',
  }} />)
  expect(screen.getByRole('img').getAttribute('src')).toBe('https://rp.example/logo.png')
  expect(screen.getByRole('link', { name: 'Privacy policy' }).getAttribute('href')).toBe('https://rp.example/privacy')
  expect(screen.getByRole('link', { name: 'Terms of service' }).getAttribute('href')).toBe('https://rp.example/terms')
})

it('rejects executable or malformed metadata URLs and escapes the client name', () => {
  const { container } = render(<LoginClient locale="en-US" client={{
    name: '<script>bad()</script>', logo_uri: 'data:image/svg+xml,bad',
    policy_uri: 'javascript:bad()', tos_uri: 'not a URL',
  }} />)
  expect(screen.queryByRole('img')).toBeNull()
  expect(screen.queryByRole('link')).toBeNull()
  expect(container.querySelector('script')).toBeNull()
  expect(screen.getByText('<script>bad()</script>')).toBeTruthy()
})

it('leaves ordinary login pages without client metadata empty', () => {
  const { container } = render(<LoginClient locale="zh-CN" />)
  expect(container.childElementCount).toBe(0)
})
