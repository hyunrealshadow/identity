// @vitest-environment jsdom
import { act, cleanup, render, screen } from '@testing-library/react'
import { afterEach, expect, it, vi } from 'vitest'
import type { ComponentType, ReactNode } from 'react'
import { defaultParseSearch } from '@tanstack/react-router'

const fixture = vi.hoisted(() => ({
  search: {} as Record<string, unknown>,
}))
vi.mock('@tanstack/react-router', async (original) => ({
  ...await original<typeof import('@tanstack/react-router')>(),
  useRouterState: () => '/login',
  createFileRoute: () => (options: { validateSearch: (search: Record<string, unknown>) => unknown }) => ({
    options,
    useSearch: () => options.validateSearch(fixture.search),
    useLoaderData: () => ({
      loginId: 'login', csrfToken: 'csrf', locale: 'en-US', uiLocales: '',
      formValues: {},
      accounts: [{ id: 'session', name: 'Existing account', email: 'existing@example.com' }],
    }),
  }),
}))
vi.mock('#/components/auth-shell', () => ({
  AuthShell: ({ title, children }: { title: string; children: ReactNode }) => <main><h1>{title}</h1>{children}</main>,
}))

import { Route } from '#/routes/login'
const Login = Route.options.component as ComponentType & { preload?: () => Promise<unknown> }

afterEach(cleanup)

it('opens the identifier form from the real Use another account URL with an existing session', async () => {
  fixture.search = defaultParseSearch('?login_id=login&no_accounts=1')
  await Login.preload?.()
  let container: HTMLElement | undefined
  await act(async () => { container = render(<Login />).container })
  expect(container!.querySelector('input[name="identifier"]')).not.toBeNull()
  expect(container!.querySelector('input[name="csrf_token"]')?.getAttribute('value')).toBe('csrf')
  expect(screen.queryByText('existing@example.com')).toBeNull()
})
