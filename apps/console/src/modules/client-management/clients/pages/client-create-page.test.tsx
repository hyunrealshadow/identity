import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { useState } from 'react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { renderWithLocale } from '#/test/render'
import type { CreateSearch } from '../lib/create-steps'
import { ClientCreatePage } from './client-create-page'

const harness = vi.hoisted(() => ({
  navigate: vi.fn(),
  setSearch: null as null | ((search: CreateSearch) => void),
  create: vi.fn(),
}))

vi.mock('@tanstack/react-router', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@tanstack/react-router')>()),
  useNavigate: () => harness.navigate,
}))
vi.mock('#/lib/workspace', () => ({ useWorkspace: () => ({ data: null }) }))
vi.mock('../lib/client-scope', () => ({
  clientScope: () => ({ create: true, secretCreate: true }),
}))
vi.mock('#/components/workspace-gate', () => ({
  ConsoleWorkspaceGate: ({ children }: { children: React.ReactNode }) => children,
}))
vi.mock('../hooks/client-mutations', () => ({
  useClientMutations: () => ({ create: harness.create }),
}))

function Harness() {
  const [search, setSearch] = useState<CreateSearch>({})
  harness.setSearch = setSearch
  return <ClientCreatePage search={search} />
}

/** The default-language name; the translation editor beside it has its own input. */
function nameInput() {
  return document.querySelector<HTMLInputElement>('input[name="name"]')!
}

function stepTitle() {
  return document.getElementById('client-create-step-title')?.textContent
}

beforeEach(() => {
  window.sessionStorage.clear()
  harness.create.mockReset()
  harness.navigate.mockReset().mockImplementation((options: { to: string; search?: CreateSearch }) => {
    if (options.to === '/clients/new') harness.setSearch?.(options.search ?? {})
  })
})

afterEach(() => {
  harness.setSearch = null
})

describe('client creation wizard', () => {
  it('holds a step until it is valid and keeps entries when going back', async () => {
    const user = userEvent.setup()
    renderWithLocale(<Harness />)

    expect(stepTitle()).toBe('Application type')
    await user.click(screen.getByRole('button', { name: 'Next' }))
    expect(stepTitle()).toBe('Details')

    await user.click(screen.getByRole('button', { name: 'Next' }))
    expect(stepTitle()).toBe('Details')
    expect(await screen.findByText('Enter a name.')).toBeTruthy()

    await user.type(nameInput(), 'Billing portal')
    await user.click(screen.getByRole('button', { name: 'Next' }))
    expect(stepTitle()).toBe('Redirect addresses')

    await user.click(screen.getByRole('button', { name: 'Back' }))
    expect(stepTitle()).toBe('Details')
    expect(nameInput().value).toBe('Billing portal')
  })

  it('leaves out redirect addresses for a machine client', async () => {
    const user = userEvent.setup()
    renderWithLocale(<Harness />)

    await user.click(screen.getByRole('radio', { name: /Machine to machine/ }))
    await user.click(screen.getByRole('button', { name: 'Next' }))
    await user.type(nameInput(), 'Nightly sync')
    await user.click(screen.getByRole('button', { name: 'Next' }))

    expect(stepTitle()).toBe('Authorization')
    const steps = screen.getByRole('navigation', { name: 'Creation steps' })
    expect(within(steps).queryByText('Redirect addresses')).toBeNull()
  })

  it('returns to the step that shows a field the server rejected', async () => {
    const user = userEvent.setup()
    harness.create.mockResolvedValue({
      data: null,
      errors: [
        {
          message: 'Invalid redirect URI',
          fields: [
            { path: 'input.settings.platforms.0.redirectUris.0', message: 'Use HTTPS.' },
          ],
        },
      ],
      failure: { kind: 'validation', code: 'invalid_input' },
      forbidden: false,
    })
    renderWithLocale(<Harness />)

    await user.click(screen.getByRole('button', { name: 'Next' }))
    await user.type(nameInput(), 'Billing portal')
    await user.click(screen.getByRole('button', { name: 'Next' }))
    await user.type(
      screen.getByRole('textbox', { name: 'Web redirect URIs' }),
      'http://app.example.test/callback',
    )
    await user.click(screen.getByRole('button', { name: 'Next' }))
    await user.click(screen.getByRole('button', { name: 'Next' }))
    expect(stepTitle()).toBe('Review')

    await user.click(screen.getByRole('button', { name: 'Create client' }))
    await waitFor(() => expect(stepTitle()).toBe('Redirect addresses'))
    expect(screen.getByText('Use HTTPS.')).toBeTruthy()
  })
})
