// @vitest-environment jsdom

import { act, cleanup, render } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { RecoveryCodeInput, TotpInput } from './totp-input'

beforeEach(() => {
  vi.stubGlobal(
    'ResizeObserver',
    class {
      observe() {}
      disconnect() {}
    },
  )
})

describe('RecoveryCodeInput', () => {
  it('normalizes pasted codes and renders a separator after four characters', () => {
    const { container } = render(<RecoveryCodeInput name="credential" />)
    const input = container.querySelector<HTMLInputElement>('[data-input-otp]')!

    act(() => {
      input.value = 'abcd-efgh'
      input.dispatchEvent(new Event('input', { bubbles: true }))
    })

    const slots = Array.from(
      container.querySelectorAll('[data-slot="input-otp-slot"]'),
      (slot) => slot.textContent,
    )
    expect(slots).toEqual(['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H'])
    expect(input.value).toBe('ABCDEFGH')
    expect(container.textContent).toContain('ABCD-EFGH')
  })
})

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

describe('TotpInput', () => {
  it('synchronizes a value inserted through a native password-manager event', () => {
    const { container } = render(<TotpInput name="totp" />)
    const input = container.querySelector<HTMLInputElement>('[data-input-otp]')

    expect(input).not.toBeNull()
    act(() => {
      input!.value = '794 364'
      input!.dispatchEvent(new Event('input', { bubbles: true }))
    })

    const slots = Array.from(
      container.querySelectorAll('[data-slot="input-otp-slot"]'),
      (slot) => slot.textContent,
    )
    expect(slots).toEqual(['7', '9', '4', '3', '6', '4'])
    expect(input!.value).toBe('794364')
  })

  it('exposes the stable semantics expected by authenticator extensions', () => {
    const { container } = render(<TotpInput name="totp" />)
    const input = container.querySelector<HTMLInputElement>('[data-input-otp]')

    expect(input?.name).toBe('totp')
    expect(input?.hasAttribute('id')).toBe(false)
    expect(input?.autocomplete).toBe('one-time-code')
    expect(input?.inputMode).toBe('numeric')
    expect(input?.maxLength).toBe(6)
  })

  it('does not synthesize input events when the field gains or loses focus', async () => {
    const { container } = render(<TotpInput name="totp" />)
    const input = container.querySelector<HTMLInputElement>('[data-input-otp]')!
    const inputListener = vi.fn()
    input.addEventListener('input', inputListener)

    act(() => input.focus())
    act(() => input.blur())
    await act(() => new Promise((resolve) => setTimeout(resolve, 75)))

    expect(inputListener).not.toHaveBeenCalled()
  })
})
