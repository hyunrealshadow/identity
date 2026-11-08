// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import type { ReactElement } from 'react'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'

const mocks = vi.hoisted(() => ({ execute: vi.fn(), invalidate: vi.fn(), navigate: vi.fn(), success: vi.fn() }))
vi.mock('@tanstack/react-start', () => ({ useServerFn: () => mocks.execute }))
vi.mock('#/lib/account-actions', () => ({ runAccountAction: vi.fn() }))
const router = { invalidate: mocks.invalidate, navigate: mocks.navigate }
vi.mock('@tanstack/react-router', () => ({ useRouter: () => router, useNavigate: () => mocks.navigate }))

import { AccountReauthProvider, useAccountReauth } from './reauthentication-popup'
import { AccountActionForm } from './account-action-form'
import { useSecurityModal } from './use-security-modal'
import type { AccountAccessContext } from '#/lib/account-operations'
import { ACCOUNT_REAUTH_MESSAGE_TYPE } from '#/lib/popup-reauth'

const request = { url: 'https://issuer.example/oauth2/authorize', state: 'pending-state' }
const queryClient = new QueryClient()

function renderWithQuery(ui: ReactElement) {
  return render(<QueryClientProvider client={queryClient}>{ui}</QueryClientProvider>)
}

let child: Window
let replace: ReturnType<typeof vi.fn>
let close: ReturnType<typeof vi.fn>

function Controls({ action = 'prepare-change-password' }: { action?: string }) {
  const auth = useAccountReauth()
  return <>
    <button onClick={() => auth.requestReauth(request)}>verify</button>
    <AccountActionForm action={action} requestFailedMessage="Request failed" onSuccess={mocks.success}><input name="username" defaultValue="draft-user" /><button type="submit">prepare</button></AccountActionForm>
  </>
}
function setup(access?: AccountAccessContext, action?: string) { renderWithQuery(<AccountReauthProvider locale="zh-CN" access={access}><Controls action={action} /></AccountReauthProvider>) }
function send(source: Window, state = request.state, origin = window.location.origin) {
  const event = new MessageEvent('message', { origin, data: {
    type: ACCOUNT_REAUTH_MESSAGE_TYPE, state, result: 'success', returnTo: '/account/security?confirm=change-password',
  } })
  Object.defineProperty(event, 'source', { value: source })
  act(() => window.dispatchEvent(event))
}
beforeEach(() => {
  vi.clearAllMocks()
  replace = vi.fn()
  close = vi.fn()
  child = { closed: false, close, focus: vi.fn(), location: { replace } } as unknown as Window
  vi.spyOn(window, 'open').mockReturnValue(child)
  mocks.invalidate.mockResolvedValue(undefined)
  mocks.navigate.mockResolvedValue(undefined)
})
afterEach(() => { cleanup(); vi.restoreAllMocks() })

it('opens a real window and accepts one callback only from that window and origin', async () => {
  setup()
  fireEvent.click(screen.getByText('verify'))
  expect(replace).toHaveBeenCalledWith(request.url)
  expect(document.querySelector('iframe')).toBeNull()
  expect(document.querySelector('[role=dialog]')).toBeNull()
  send(child, request.state, 'https://untrusted.example')
  send({} as Window)
  send(child, 'other-state')
  expect(mocks.navigate).not.toHaveBeenCalled()
  send(child)
  send(child)
  await waitFor(() => expect(mocks.navigate).toHaveBeenCalledOnce())
  expect(close).toHaveBeenCalledOnce()
  expect(mocks.navigate).toHaveBeenCalledWith({ href: '/account/security?confirm=change-password' })
})

it('shows a blocked notice and opens a retry window only after the server confirms elevation', async () => {
  vi.mocked(window.open).mockReturnValueOnce(null)
  setup()
  fireEvent.click(screen.getByText('verify'))
  expect(screen.getByText('浏览器拦截了验证窗口，请点击继续验证')).toBeTruthy()
  const next = { ...request, state: 'retried-state' }
  mocks.execute.mockImplementation(async () => {
    expect(window.open).toHaveBeenCalledTimes(1)
    return { reauth: next }
  })
  fireEvent.click(screen.getByRole('button', { name: '继续验证' }))
  await waitFor(() => expect(replace).toHaveBeenCalledWith(next.url))
  send(child, request.state)
  expect(mocks.navigate).not.toHaveBeenCalled()
  send(child, next.state)
  await waitFor(() => expect(mocks.navigate).toHaveBeenCalledOnce())
})

function access(age = 0, scopes = ['account.read', 'account.update', 'password.change']) {
  const context = { scopes, user: true, acr: 'aal2', authTime: Math.floor(Date.now() / 1000) - age, mfaEnabled: true }
  return { default: context, elevated: context }
}

it('does not open a window while checking a fresh request or after success', async () => {
  let resolve!: (value: { ok: boolean }) => void
  mocks.execute.mockReturnValueOnce(new Promise((done) => { resolve = done }))
  setup(access())
  fireEvent.click(screen.getByText('prepare'))
  expect(window.open).not.toHaveBeenCalled()
  await act(async () => resolve({ ok: true }))
  await waitFor(() => expect(mocks.success).toHaveBeenCalledOnce())
  expect(window.open).not.toHaveBeenCalled()
  expect(close).not.toHaveBeenCalled()
  expect(mocks.execute).toHaveBeenCalledExactlyOnceWith({ data: { action: 'prepare-change-password', values: { username: 'draft-user' } } })
})

it('does not create a window on a failed request', async () => {
  mocks.execute.mockRejectedValueOnce(new Error('network unavailable'))
  setup(access())
  fireEvent.click(screen.getByText('prepare'))
  await waitFor(() => expect(screen.getByText('Request failed')).toBeTruthy())
  expect(window.open).not.toHaveBeenCalled()
})

it('defers a local scope denial to the server instead of blocking the action', async () => {
  mocks.execute.mockResolvedValueOnce({ ok: false })
  setup(access(0, []))
  fireEvent.click(screen.getByText('prepare'))
  await waitFor(() => expect(mocks.execute).toHaveBeenCalledExactlyOnceWith({ data: {
    action: 'prepare-change-password', values: { username: 'draft-user' },
  } }))
  expect(window.open).not.toHaveBeenCalled()
  expect(mocks.success).not.toHaveBeenCalled()
})

it('prepares an expired request without submitting the draft, then opens only for the real challenge', async () => {
  mocks.execute.mockResolvedValueOnce({ reauth: request })
  setup(access(400), 'update-username')
  fireEvent.click(screen.getByText('prepare'))
  await waitFor(() => expect(replace).toHaveBeenCalledWith(request.url))
  expect(mocks.execute).toHaveBeenCalledExactlyOnceWith({ data: {
    action: 'update-username', values: {}, preflightOnly: true,
  } })
  expect(window.open).toHaveBeenCalledOnce()
  send(child)
  await waitFor(() => expect(mocks.navigate).toHaveBeenCalledOnce())
  expect(mocks.execute).toHaveBeenCalledOnce()
  expect(mocks.success).not.toHaveBeenCalled()
})

function PasskeysControl() {
  const state = useSecurityModal({ action: 'prepare-manage-passkeys', locale: 'zh-CN', loginHint: 'user' })
  return <><button onClick={() => void state.prepare()}>passkeys</button>{state.modal.isOpen ? <span>editor open</span> : null}</>
}
it('opens the passkey editor with no browser window when access is fresh', async () => {
  mocks.execute.mockResolvedValueOnce({ ok: true })
  renderWithQuery(<AccountReauthProvider locale="zh-CN" access={access()}><PasskeysControl /></AccountReauthProvider>)
  fireEvent.click(screen.getByText('passkeys'))
  await waitFor(() => expect(screen.getByText('editor open')).toBeTruthy())
  expect(window.open).not.toHaveBeenCalled()
})

it.each([0, 400])('passes ordinary sign-in through without a new popup at authentication age %i', async (age) => {
  const redirect = 'https://issuer.example/oauth2/authorize?state=signin'
  mocks.execute.mockResolvedValueOnce({ redirect })
  let outcome: unknown
  function Recover() {
    const auth = useAccountReauth()
    return <button onClick={() => { void auth.executeAction({ action: 'update-username', values: { username: 'draft' } }).then(result => { outcome = result }) }}>recover</button>
  }
  renderWithQuery(<AccountReauthProvider locale="zh-CN" access={access(age)}><Controls /><Recover /></AccountReauthProvider>)
  fireEvent.click(screen.getByText('verify'))
  fireEvent.click(screen.getByText('recover'))
  await waitFor(() => expect(outcome).toEqual({ redirect }))
  expect(mocks.execute).toHaveBeenCalledOnce()
  expect(window.open).toHaveBeenCalledOnce()
  expect(close).toHaveBeenCalledOnce()
  send(child)
  expect(mocks.navigate).not.toHaveBeenCalled()
  expect(mocks.invalidate).not.toHaveBeenCalled()
})

it('does not pre-open a retry window while the server checks an expired session', async () => {
  vi.mocked(window.open).mockReturnValueOnce(null)
  setup()
  fireEvent.click(screen.getByText('verify'))
  let complete!: (result: { ok: boolean }) => void
  mocks.execute.mockReturnValueOnce(new Promise(resolve => { complete = resolve }))
  fireEvent.click(screen.getByRole('button', { name: '继续验证' }))
  expect(window.open).toHaveBeenCalledOnce()
  await act(async () => complete({ ok: false }))
  expect(window.open).toHaveBeenCalledOnce()
})
