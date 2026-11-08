// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { renderToString } from 'react-dom/server'

import { ProgressiveForm } from './progressive-form'
import { SubmitButton } from './submit-button'
import { TextField } from './text-field'

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

describe('ProgressiveForm', () => {
  it('clears a server field error after editing so the form can submit again', async () => {
    const fetch = vi.fn().mockRejectedValue(new Error('offline'))
    vi.stubGlobal('fetch', fetch)
    render(
      <ProgressiveForm
        action="/install"
        enhancementErrorMessage="Try again"
        validationErrors={{ email: '邮箱地址格式无效' }}
      >
        <TextField name="email" label="Email" defaultValue="old@example.test" required />
        <button type="submit">Install</button>
      </ProgressiveForm>,
    )
    const input = screen.getByRole('textbox', { name: 'Email' }) as HTMLInputElement
    await waitFor(() => expect(input.validity.customError).toBe(true))
    fireEvent.click(screen.getByRole('button', { name: 'Install' }))
    expect(fetch).not.toHaveBeenCalled()
    fireEvent.change(input, { target: { value: 'corrected@example.test' } })
    await waitFor(() => expect(input.validity.customError).toBe(false))
    expect(screen.queryByText('邮箱地址格式无效')).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: 'Install' }))
    await waitFor(() => expect(fetch).toHaveBeenCalledOnce())
    expect((fetch.mock.calls[0][1].body as FormData).get('email')).toBe('corrected@example.test')
  })

  it('retains a corrected password while clearing its server error', async () => {
    const fetch = vi.fn().mockRejectedValue(new Error('offline'))
    vi.stubGlobal('fetch', fetch)
    render(
      <ProgressiveForm
        action="/install"
        enhancementErrorMessage="Try again"
        validationErrors={{ confirm_password: '两次输入的密码不一致' }}
      >
        <TextField name="confirm_password" label="Confirm password" type="password" required />
        <button type="submit">Install</button>
      </ProgressiveForm>,
    )
    const input = screen.getByLabelText('Confirm password') as HTMLInputElement
    expect(await screen.findByText('两次输入的密码不一致')).not.toBeNull()
    fireEvent.input(input, { target: { value: 'corrected-test-password' } })
    await waitFor(() => expect(input.value).toBe('corrected-test-password'))
    await waitFor(() => expect(screen.queryByText('两次输入的密码不一致')).toBeNull())
    expect(input.validity.valueMissing).toBe(false)
    expect(input.validity.customError).toBe(false)
    fireEvent.click(screen.getByRole('button', { name: 'Install' }))
    await waitFor(() => expect(fetch).toHaveBeenCalledOnce())
    expect((fetch.mock.calls[0][1].body as FormData).get('confirm_password')).toBe('corrected-test-password')
  })

  it('signals enhancement only after hydration while preserving the native form', () => {
    const form = (
      <ProgressiveForm action="/login" enhancementErrorMessage="Try again">
        <input name="identifier" />
        <button type="submit">Continue</button>
      </ProgressiveForm>
    )
    expect(renderToString(form)).toContain('data-enhanced="false"')
    const view = render(form)
    expect(view.container.querySelector('form')?.getAttribute('data-enhanced')).toBe('true')
    expect(view.container.querySelector('form')?.getAttribute('method')).toBe('post')
  })

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
        action="/login/password"
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

  it('clears an in-flight submitter when the page is restored from the back/forward cache', async () => {
    vi.stubGlobal('fetch', vi.fn().mockReturnValue(new Promise(() => {})))
    render(
      <ProgressiveForm action="/login" enhancementErrorMessage="Navigation failed">
        <input name="intent" defaultValue="select" />
        <SubmitButton value="select">Use this account</SubmitButton>
      </ProgressiveForm>,
    )

    fireEvent.click(screen.getByRole('button', { name: 'Use this account' }))
    const form = screen.getByRole('button', { name: 'Use this account' }).closest('form')
    await waitFor(() => expect(form?.getAttribute('aria-busy')).toBe('true'))
    expect(screen.getByRole('button', { name: 'Use this account' }).hasAttribute('data-pending')).toBe(true)

    const restored = new Event('pageshow')
    Object.defineProperty(restored, 'persisted', { value: true })
    window.dispatchEvent(restored)

    await waitFor(() => expect(form?.getAttribute('aria-busy')).toBe('false'))
    expect(screen.getByRole('button', { name: 'Use this account' }).hasAttribute('data-pending')).toBe(false)
  })
})
