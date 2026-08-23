// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { ProgressiveForm } from './progressive-form'

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

describe('ProgressiveForm', () => {
  it('retains a native POST action when JavaScript is unavailable', () => {
    render(
      <ProgressiveForm action="/login" enhancementErrorMessage="Try again">
        <input name="identifier" defaultValue="alice" />
        <button type="submit">Continue</button>
      </ProgressiveForm>,
    )

    const form = screen.getByRole('button', { name: 'Continue' }).closest('form')
    expect(form?.getAttribute('method')).toBe('post')
    expect(form?.getAttribute('action')).toBe('/login')
  })

  it('can defer field validation to the server', () => {
    render(
      <ProgressiveForm
        action="/login/challenge"
        enhancementErrorMessage="Try again"
        noValidate
      >
        <input name="credential" required />
        <button type="submit">Continue</button>
      </ProgressiveForm>,
    )

    const form = screen.getByRole('button', { name: 'Continue' }).closest('form')
    expect(form?.noValidate).toBe(true)
  })

  it('includes the clicked submitter and request context in enhanced submissions', async () => {
    const fetch = vi.fn().mockRejectedValue(new Error('offline'))
    vi.stubGlobal('fetch', fetch)
    render(
      <ProgressiveForm action="/consent" enhancementErrorMessage="Navigation failed">
        <input name="login_id" defaultValue="login-123" />
        <button type="submit" name="decision" value="deny">Deny</button>
        <button type="submit" name="decision" value="approve">Allow</button>
      </ProgressiveForm>,
    )

    fireEvent.click(screen.getByRole('button', { name: 'Deny' }))

    await waitFor(() => expect(fetch).toHaveBeenCalledOnce())
    const [url, init] = fetch.mock.calls[0] as [string, RequestInit]
    const body = init.body as FormData
    expect(url).toBe('/consent')
    expect(init).toMatchObject({
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'x-enhanced-form': '1' },
    })
    expect(body.get('login_id')).toBe('login-123')
    expect(body.get('decision')).toBe('deny')
    expect(await screen.findByText('Navigation failed')).not.toBeNull()
    expect(screen.getByRole('button', { name: 'Deny' }).closest('form')?.getAttribute('aria-busy')).toBe('false')
  })
})
