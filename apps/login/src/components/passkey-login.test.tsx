// @vitest-environment jsdom
import { act, cleanup, fireEvent, render, screen } from '@testing-library/react'
import { StrictMode } from 'react'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'

const mocks = vi.hoisted(() => ({ begin: vi.fn(), finish: vi.fn(), get: vi.fn(), supported: vi.fn() }))
vi.mock('@tanstack/react-start', () => ({
  createServerFn: vi.fn()
    .mockReturnValueOnce({ handler: () => mocks.begin, validator: () => ({ handler: () => mocks.begin }) })
    .mockReturnValueOnce({ handler: () => mocks.finish, validator: () => ({ handler: () => mocks.finish }) }),
}))
vi.mock('#/lib/passkey', () => ({ getPasskey: mocks.get, passkeysSupported: mocks.supported }))
import { PasskeyLogin } from './passkey-login'

const props = { loginId: 'identified-login', csrfToken: 'csrf', locale: 'en-US' as const }
const options = { challenge_id: 'challenge', public_key: {} }
async function startAutomaticAttempt() {
  await act(async () => { await vi.advanceTimersByTimeAsync(0) })
}

beforeEach(() => {
  vi.useFakeTimers()
  vi.clearAllMocks()
  mocks.supported.mockReturnValue(true)
  mocks.begin.mockReset().mockResolvedValue(JSON.stringify(options))
  mocks.get.mockReset().mockRejectedValue(new DOMException('Cancelled', 'NotAllowedError'))
  mocks.finish.mockReset().mockResolvedValue({ error: 'Verification failed' })
  vi.spyOn(document, 'hasFocus').mockReturnValue(true)
})
afterEach(() => { cleanup(); vi.useRealTimers(); vi.restoreAllMocks() })

it('starts once in Strict Mode and waits for an explicit retry after cancellation', async () => {
  const view = render(<StrictMode><PasskeyLogin {...props} primary /></StrictMode>)
  await startAutomaticAttempt()
  expect(mocks.begin).toHaveBeenCalledExactlyOnceWith({ data: { loginId: props.loginId, csrfToken: props.csrfToken } })
  expect(mocks.get).toHaveBeenCalledTimes(1)
  expect(screen.getByRole('alert')).toBeTruthy()
  view.rerender(<StrictMode><PasskeyLogin {...props} primary /></StrictMode>)
  await startAutomaticAttempt()
  expect(mocks.get).toHaveBeenCalledTimes(1)
  await act(async () => { fireEvent.click(screen.getByRole('button')) })
  expect(mocks.get).toHaveBeenCalledTimes(2)
})

it('keeps the alternative on the password page manual', async () => {
  render(<PasskeyLogin {...props} />)
  await startAutomaticAttempt()
  expect(mocks.begin).not.toHaveBeenCalled()
  await act(async () => { fireEvent.click(screen.getByRole('button')) })
  expect(mocks.get).toHaveBeenCalledTimes(1)
})

it('waits for page focus before automatically opening the prompt', async () => {
  const focus = vi.mocked(document.hasFocus).mockReturnValue(false)
  render(<PasskeyLogin {...props} primary />)
  await startAutomaticAttempt()
  expect(mocks.begin).not.toHaveBeenCalled()
  focus.mockReturnValue(true)
  fireEvent.focus(window)
  await startAutomaticAttempt()
  expect(mocks.get).toHaveBeenCalledTimes(1)
})

it('does not start on unsupported browsers', async () => {
  mocks.supported.mockReturnValue(false)
  render(<PasskeyLogin {...props} primary />)
  await startAutomaticAttempt()
  expect(mocks.begin).not.toHaveBeenCalled()
  expect((screen.getByRole('button') as HTMLButtonElement).disabled).toBe(true)
})

it('does not open a late prompt after leaving the page', async () => {
  let resolveOptions!: (options: string) => void
  mocks.begin.mockReturnValue(new Promise<string>((resolve) => { resolveOptions = resolve }))
  const view = render(<PasskeyLogin {...props} primary />)
  await startAutomaticAttempt()
  view.unmount()
  await act(async () => { resolveOptions(JSON.stringify(options)) })
  expect(mocks.get).not.toHaveBeenCalled()
  expect(mocks.finish).not.toHaveBeenCalled()
})

it('aborts the browser request when switching to password and allows a manual retry', async () => {
  let resolveAssertion!: (assertion: object) => void
  mocks.get.mockReturnValueOnce(new Promise<object>((resolve) => { resolveAssertion = resolve }))
  const view = render(<PasskeyLogin {...props} primary />)
  await startAutomaticAttempt()
  const signal = mocks.get.mock.calls[0][1] as AbortSignal
  expect(signal.aborted).toBe(false)
  view.rerender(<PasskeyLogin {...props} />)
  expect(signal.aborted).toBe(true)
  await act(async () => { resolveAssertion({ credential: 'late assertion' }) })
  expect(mocks.finish).not.toHaveBeenCalled()
  expect((screen.getByRole('button') as HTMLButtonElement).disabled).toBe(false)
  await act(async () => { fireEvent.click(screen.getByRole('button')) })
  expect(mocks.get).toHaveBeenCalledTimes(2)
})

it('submits the automatically obtained assertion to complete login', async () => {
  mocks.get.mockResolvedValue({ challenge_id: 'challenge', credential: { id: 'key' } })
  render(<PasskeyLogin {...props} primary />)
  await startAutomaticAttempt()
  expect(mocks.finish).toHaveBeenCalledExactlyOnceWith({ data: {
    ...props, assertion: JSON.stringify({ challenge_id: 'challenge', credential: { id: 'key' } }),
  } })
})
