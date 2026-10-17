// @vitest-environment jsdom
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'

const mocks = vi.hoisted(() => ({ action: vi.fn(), create: vi.fn(), supported: vi.fn(), invalidate: vi.fn() }))
vi.mock('@tanstack/react-start', () => {
  const builder = { handler: () => mocks.action, validator: () => builder }
  return { createServerFn: () => builder }
})
vi.mock('@tanstack/react-router', () => ({ useRouter: () => ({ invalidate: mocks.invalidate }) }))
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
  vi.stubGlobal('ResizeObserver', class { observe() {} unobserve() {} disconnect() {} })
  vi.stubGlobal('matchMedia', () => ({ matches: false, addEventListener() {}, removeEventListener() {}, addListener() {}, removeListener() {} }))
})

afterEach(() => { cleanup(); vi.restoreAllMocks(); vi.unstubAllGlobals() })

async function openRegistration(keys = storedKeys.slice(0, 4)) {
  render(<PasskeySettings locale="en-US" keys={keys} />)
  expect(screen.queryByRole('textbox', { name: /Passkey name/ })).toBeNull()
  fireEvent.click(screen.getByRole('button', { name: 'Add passkey' }))
  return await screen.findByRole('dialog', { name: 'Add passkey' })
}

it('uses an MFA-style dialog and waits for a nonblank name before starting registration', async () => {
  const dialog = await openRegistration()
  expect(mocks.action).not.toHaveBeenCalled()
  expect(mocks.create).not.toHaveBeenCalled()
  const submit = within(dialog).getByRole('button', { name: 'Add passkey' }) as HTMLButtonElement
  expect(submit.disabled).toBe(true)
  fireEvent.change(within(dialog).getByRole('textbox', { name: /Passkey name/ }), { target: { value: '   ' } })
  expect(submit.disabled).toBe(true)
  fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }))
  await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
  expect(mocks.action).not.toHaveBeenCalled()
})

it('allows a fifth passkey, trims its name, refreshes the account and closes on success', async () => {
  mocks.action.mockResolvedValueOnce({ optionsJson: JSON.stringify(options) }).mockResolvedValueOnce({ ok: true })
  const dialog = await openRegistration()
  fireEvent.change(within(dialog).getByRole('textbox', { name: /Passkey name/ }), { target: { value: '  Work laptop  ' } })
  fireEvent.click(within(dialog).getByRole('button', { name: 'Add passkey' }))
  await waitFor(() => expect(mocks.invalidate).toHaveBeenCalledTimes(1))
  expect(mocks.create).toHaveBeenCalledWith(options, expect.any(AbortSignal))
  expect(mocks.action).toHaveBeenLastCalledWith({ data: {
    action: 'finish', id: 'challenge', name: 'Work laptop', credential: '{"id":"registered-key"}',
  } })
  await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
})

it('keeps cancellation in the dialog and allows an explicit retry', async () => {
  mocks.action.mockResolvedValue({ optionsJson: JSON.stringify(options) })
  mocks.create.mockRejectedValue(new DOMException('Cancelled', 'NotAllowedError'))
  const dialog = await openRegistration([])
  fireEvent.change(within(dialog).getByRole('textbox', { name: /Passkey name/ }), { target: { value: 'Laptop' } })
  fireEvent.click(within(dialog).getByRole('button', { name: 'Add passkey' }))
  expect(await within(dialog).findByRole('alert')).toHaveProperty('textContent', 'Passkey verification was cancelled or timed out. You can try again.')
  expect(mocks.action).toHaveBeenCalledTimes(1)
  fireEvent.click(within(dialog).getByRole('button', { name: 'Add passkey' }))
  await waitFor(() => expect(mocks.create).toHaveBeenCalledTimes(2))
})

it('shows the five-key limit and allows adding again after a key is deleted', async () => {
  const view = render(<PasskeySettings locale="zh-CN" keys={storedKeys} />)
  expect((screen.getByRole('button', { name: '添加通行密钥' }) as HTMLButtonElement).disabled).toBe(true)
  expect(screen.getByText('已添加 5/5 个通行密钥')).toBeTruthy()
  expect(screen.getByText('最多可添加 5 个通行密钥，请删除一个后再添加。')).toBeTruthy()
  vi.spyOn(window, 'confirm').mockReturnValue(true)
  fireEvent.click(screen.getByRole('button', { name: '删除 Key 1' }))
  await waitFor(() => expect(mocks.invalidate).toHaveBeenCalledTimes(1))
  expect(mocks.action).toHaveBeenCalledWith({ data: { action: 'delete', id: '0' } })
  view.rerender(<PasskeySettings locale="zh-CN" keys={storedKeys.slice(1)} />)
  await waitFor(() => expect((screen.getByRole('button', { name: '添加通行密钥' }) as HTMLButtonElement).disabled).toBe(false))
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
  expect((within(dialog).getByRole('button', { name: 'Cancel' }) as HTMLButtonElement).disabled).toBe(true)
  const signal = mocks.create.mock.calls[0][1] as AbortSignal
  cleanup()
  expect(signal.aborted).toBe(true)
  await act(async () => { resolveCredential({ id: 'late-key' }) })
  expect(mocks.action).toHaveBeenCalledTimes(1)
})
