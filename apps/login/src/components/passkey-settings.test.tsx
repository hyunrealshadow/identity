// @vitest-environment jsdom
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'

const mocks = vi.hoisted(() => ({ action: vi.fn(), create: vi.fn(), supported: vi.fn(), invalidate: vi.fn(), prepare: vi.fn(), navigate: vi.fn() }))
vi.mock('@tanstack/react-start', () => {
  const builder = { handler: () => mocks.action, validator: () => builder }
  return { createServerFn: () => builder, useServerFn: () => mocks.prepare }
})
vi.mock('@tanstack/react-router', () => ({ useRouter: () => ({ invalidate: mocks.invalidate }), useNavigate: () => mocks.navigate }))
vi.mock('#/lib/account-actions', () => ({ runAccountAction: vi.fn() }))
vi.mock('#/lib/passkey-account.server', () => ({ passkeyAccountAction: vi.fn() }))
vi.mock('#/lib/passkey', async (original) => ({
  ...await original<typeof import('#/lib/passkey')>(), createPasskey: mocks.create, passkeysSupported: mocks.supported,
}))

import { PasskeySettings } from './passkey-settings'

const options = { challenge_id: 'challenge', public_key: {} }
const storedKeys = Array.from({ length: 5 }, (_, index) => ({ id: String(index), name: `Key ${index + 1}` }))

beforeEach(() => {
  vi.clearAllMocks()
  mocks.supported.mockReturnValue(true)
  mocks.create.mockReset().mockResolvedValue({ id: 'registered-key' })
  mocks.action.mockReset().mockResolvedValue({ ok: true })
  mocks.invalidate.mockResolvedValue(undefined)
  mocks.prepare.mockReset().mockResolvedValue({ ok: true })
  vi.stubGlobal('ResizeObserver', class { observe() {} unobserve() {} disconnect() {} })
  vi.stubGlobal('matchMedia', () => ({ matches: false, addEventListener() {}, removeEventListener() {}, addListener() {}, removeListener() {} }))
})

afterEach(() => { cleanup(); vi.restoreAllMocks(); vi.unstubAllGlobals() })

async function openRegistration(keys = storedKeys.slice(0, 4)) {
  render(<PasskeySettings loginHint="person" locale="en-US" keys={keys} />)
  expect(screen.queryByRole('textbox', { name: /Passkey name/ })).toBeNull()
  fireEvent.click(screen.getByRole('button', { name: 'Manage passkeys' }))
  return await screen.findByRole('dialog', { name: 'Manage passkeys' })
}

it('uses an MFA-style dialog and waits for a nonblank name before starting registration', async () => {
  const dialog = await openRegistration()
  expect(mocks.action).not.toHaveBeenCalled()
  expect(mocks.create).not.toHaveBeenCalled()
  const submit = within(dialog).getByRole('button', { name: 'Add passkey' }) as HTMLButtonElement
  expect(submit.disabled).toBe(true)
  fireEvent.change(within(dialog).getByRole('textbox', { name: /Passkey name/ }), { target: { value: '   ' } })
  expect(submit.disabled).toBe(true)
  fireEvent.click(within(dialog).getAllByRole('button', { name: 'Close' }).at(-1)!)
  await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
  expect(mocks.action).not.toHaveBeenCalled()
})

it('allows a fifth passkey, trims its name, refreshes the account and keeps management open on success', async () => {
  mocks.action.mockResolvedValueOnce({ optionsJson: JSON.stringify(options) }).mockResolvedValueOnce({ ok: true })
  const dialog = await openRegistration()
  fireEvent.change(within(dialog).getByRole('textbox', { name: /Passkey name/ }), { target: { value: '  Work laptop  ' } })
  fireEvent.click(within(dialog).getByRole('button', { name: 'Add passkey' }))
  await waitFor(() => expect(mocks.invalidate).toHaveBeenCalledTimes(1))
  expect(mocks.create).toHaveBeenCalledWith(options, expect.any(AbortSignal))
  expect(mocks.action).toHaveBeenLastCalledWith({ data: {
    action: 'finish', id: 'challenge', name: 'Work laptop', credential: '{"id":"registered-key"}',
  } })
  expect(screen.getByRole('dialog')).toBeTruthy()
  expect((within(dialog).getByRole('textbox') as HTMLInputElement).value).toBe('')
})

it('keeps cancellation in the dialog and allows an explicit retry', async () => {
  mocks.action.mockResolvedValue({ optionsJson: JSON.stringify(options) })
  mocks.create.mockRejectedValue(new DOMException('Cancelled', 'NotAllowedError'))
  const dialog = await openRegistration([])
  fireEvent.change(within(dialog).getByRole('textbox', { name: /Passkey name/ }), { target: { value: 'Laptop' } })
  fireEvent.click(within(dialog).getByRole('button', { name: 'Add passkey' }))
  expect(await within(dialog).findByRole('alert')).toHaveProperty('textContent', 'Passkey verification was cancelled or timed out, try again')
  expect(mocks.action).toHaveBeenCalledTimes(1)
  fireEvent.click(within(dialog).getByRole('button', { name: 'Add passkey' }))
  await waitFor(() => expect(mocks.create).toHaveBeenCalledTimes(2))
})

it('keeps keys inside management and permits deletion at the five-key limit', async () => {
  const view = render(<PasskeySettings loginHint="person" locale="zh-CN" keys={storedKeys} />)
  expect(screen.queryByText('Key 1')).toBeNull()
  expect(screen.queryByRole('button', { name: '添加通行密钥' })).toBeNull()
  fireEvent.click(screen.getByRole('button', { name: '管理通行密钥' }))
  const dialog = await screen.findByRole('dialog')
  expect((within(dialog).getByRole('button', { name: '添加通行密钥' }) as HTMLButtonElement).disabled).toBe(true)
  expect(within(dialog).getByText('最多可添加 5 个通行密钥，请删除一个后再添加')).toBeTruthy()
  fireEvent.click(within(dialog).getByRole('button', { name: '删除 Key 1' }))
  expect(mocks.action).not.toHaveBeenCalled()
  fireEvent.click(within(dialog).getByRole('button', { name: '确认删除' }))
  await waitFor(() => expect(mocks.invalidate).toHaveBeenCalledTimes(1))
  expect(mocks.action).toHaveBeenCalledWith({ data: { action: 'delete', id: '0' } })
  view.rerender(<PasskeySettings loginHint="person" locale="zh-CN" keys={storedKeys.slice(1)} />)
  const name = within(dialog).getByRole('textbox') as HTMLInputElement
  await waitFor(() => expect(name.disabled).toBe(false))
  fireEvent.change(name, { target: { value: 'Replacement' } })
  expect((within(dialog).getByRole('button', { name: '添加通行密钥' }) as HTMLButtonElement).disabled).toBe(false)
})

it('waits for server authorization before opening management without creating a challenge', async () => {
  let resolve!: (value: { ok: boolean }) => void
  mocks.prepare.mockReturnValue(new Promise((r) => { resolve = r }))
  render(<PasskeySettings loginHint="person" locale="en-US" keys={storedKeys} />)
  fireEvent.click(screen.getByRole('button', { name: 'Manage passkeys' }))
  expect(mocks.prepare).toHaveBeenCalledWith({ data: { action: 'prepare-manage-passkeys', values: { login_hint: 'person' } } })
  expect(screen.queryByRole('dialog')).toBeNull()
  expect(mocks.action).not.toHaveBeenCalled()
  await act(async () => { resolve({ ok: true }) })
  expect(await screen.findByRole('dialog')).toBeTruthy()
})

it('does not open management when authorization fails', async () => {
  mocks.prepare.mockResolvedValue({ ok: false })
  render(<PasskeySettings loginHint="person" locale="en-US" keys={[]} />)
  fireEvent.click(screen.getByRole('button', { name: 'Manage passkeys' }))
  await waitFor(() => expect(mocks.invalidate).toHaveBeenCalledTimes(1))
  expect(screen.queryByRole('dialog')).toBeNull()
  expect(mocks.action).not.toHaveBeenCalled()
})

it('rechecks authorization on continuation and clears the continuation after opening', async () => {
  render(<PasskeySettings loginHint="person" locale="en-US" keys={storedKeys} openRequested />)
  expect(await screen.findByRole('dialog')).toBeTruthy()
  expect(mocks.prepare).toHaveBeenCalledTimes(1)
  expect(mocks.navigate).toHaveBeenCalledWith({ to: '/account/security', replace: true })
})

it('blocks duplicate submissions and aborts a pending browser request on unmount', async () => {
  mocks.action.mockResolvedValue({ optionsJson: JSON.stringify(options) })
  let resolveCredential!: (value: object) => void
  mocks.create.mockReturnValue(new Promise<object>((resolve) => { resolveCredential = resolve }))
  const dialog = await openRegistration()
  fireEvent.change(within(dialog).getByRole('textbox', { name: /Passkey name/ }), { target: { value: 'Laptop' } })
  fireEvent.click(within(dialog).getByRole('button', { name: 'Add passkey' }))
  await waitFor(() => expect(mocks.create).toHaveBeenCalledTimes(1))
  fireEvent.submit(within(dialog).getByRole('textbox', { name: /Passkey name/ }).closest('form')!)
  expect(mocks.action).toHaveBeenCalledTimes(1)
  expect((within(dialog).getAllByRole('button', { name: 'Close' }).at(-1)! as HTMLButtonElement).disabled).toBe(true)
  const signal = mocks.create.mock.calls[0][1] as AbortSignal
  cleanup()
  expect(signal.aborted).toBe(true)
  await act(async () => { resolveCredential({ id: 'late-key' }) })
  expect(mocks.action).toHaveBeenCalledTimes(1)
})
