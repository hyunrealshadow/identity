// @vitest-environment jsdom

import { act, cleanup, render } from '@testing-library/react'
import { renderToString } from 'react-dom/server'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { useState } from 'react'

import { GroupedCodeInput, SegmentedCodeInput, TotpInput } from './totp-input'

beforeEach(() => {
  vi.stubGlobal(
    'ResizeObserver',
    class {
      observe() {}
      disconnect() {}
    },
  )
})

describe('GroupedCodeInput', () => {
  it('normalizes a pasted device code and renders a separator after four characters', () => {
    const { container } = render(<GroupedCodeInput name="user_code" />)
    const input = container.querySelector<HTMLInputElement>('[data-input-otp]')!

    act(() => {
      input.value = 'wdjb-mjht'
      input.dispatchEvent(new Event('input', { bubbles: true }))
    })

    const slots = Array.from(
      container.querySelectorAll('[data-slot="input-otp-slot"]'),
      (slot) => slot.textContent,
    )
    expect(slots).toEqual(['W', 'D', 'J', 'B', 'M', 'J', 'H', 'T'])
    expect(input.value).toBe('WDJBMJHT')
    expect(container.textContent).toContain('WDJB-MJHT')
  })

  it('does not let repeated separators consume the native input limit', () => {
    const { container } = render(<GroupedCodeInput name="user_code" />)
    const input = container.querySelector<HTMLInputElement>('[data-input-otp]')!

    act(() => {
      input.value = 'WDJBM'
      input.dispatchEvent(new Event('input', { bubbles: true }))
    })
    for (let index = 0; index < 10; index++) {
      act(() => {
        input.value += '-'
        input.dispatchEvent(new Event('input', { bubbles: true }))
      })
      expect(input.value).toBe('WDJBM')
    }

    act(() => {
      input.value += 'J'
      input.dispatchEvent(new Event('input', { bubbles: true }))
    })
    expect(input.value).toBe('WDJBMJ')
    expect(container.textContent).toContain('WDJB-MJ')
  })

  it('renders eight slots with a separator for the server-rendered form', () => {
    const html = renderToString(<GroupedCodeInput name="user_code" />)

    expect(html.match(/data-slot="input-otp-slot"/g)).toHaveLength(8)
  })
})

describe('SegmentedCodeInput', () => {
  it('renders the shape a caller describes', () => {
    const { container } = render(
      <SegmentedCodeInput
        name="pin"
        length={4}
        inputMode="numeric"
        pattern="^\d+$"
        autoComplete="off"
        normalize={(value) => value.replace(/\D/g, '').slice(0, 4)}
      />,
    )

    expect(container.querySelectorAll('[data-slot="input-otp-slot"]')).toHaveLength(4)
    expect(container.textContent).not.toContain('-')
  })
})

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

describe('TotpInput', () => {
  it('does not let invalid characters block the sixth digit', () => {
    const { container } = render(<TotpInput name="totp" />)
    const input = container.querySelector<HTMLInputElement>('[data-input-otp]')!

    act(() => {
      input.value = '79436'
      input.dispatchEvent(new Event('input', { bubbles: true }))
    })
    for (let index = 0; index < 10; index++) {
      act(() => {
        input.value += '-'
        input.dispatchEvent(new Event('input', { bubbles: true }))
      })
      expect(input.value).toBe('79436')
    }

    act(() => {
      input.value += '4'
      input.dispatchEvent(new Event('input', { bubbles: true }))
    })
    expect(input.value).toBe('794364')
    expect(container.textContent).toContain('794-364')
  })

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
    const root = container.querySelector<HTMLElement>('[data-slot="input-otp"]')
    const group = container.querySelector<HTMLElement>('[data-input-otp-group]')
    const firstSlot = container.querySelector<HTMLElement>('[data-slot="input-otp-slot"]')

    expect(container.querySelector('[data-input-otp-group]')).not.toBeNull()
    expect(root?.classList).toContain('w-fit')
    expect(group?.className).toBe('input-otp__group pointer-events-none items-center')
    expect(firstSlot?.className).toBe('input-otp__slot')
    expect(input?.name).toBe('totp')
    expect(input?.hasAttribute('id')).toBe(false)
    expect(input?.autocomplete).toBe('one-time-code')
    expect(input?.inputMode).toBe('numeric')
    expect(input?.maxLength).toBe(6)
    expect(container.textContent).toContain('-')
  })

  it('focuses the native input after hydration when requested', () => {
    const { container } = render(<TotpInput name="totp" autoFocus />)
    const input = container.querySelector<HTMLInputElement>('[data-input-otp]')!
    const firstSlot = container.querySelector<HTMLElement>('[data-slot="input-otp-slot"]')!

    expect(document.activeElement).toBe(input)
    expect(firstSlot.dataset.active).toBe('true')
    expect(firstSlot.dataset.current).toBe('true')
    expect(firstSlot.querySelector('[data-slot="input-otp-caret"]')).not.toBeNull()
  })

  it('server-renders the pending autofocus state for the first paint', () => {
    const html = renderToString(<TotpInput name="totp" autoFocus />)

    expect(html).toContain('data-autofocus="true"')
    expect(html).toContain('data-active="true"')
    expect(html).toContain('data-current="true"')
    expect(html).toContain('data-slot="input-otp-caret"')
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

  it('keeps a password-manager value written after focus across the focus re-render', () => {
    const { container } = render(<TotpInput name="totp" />)
    const input = container.querySelector<HTMLInputElement>('[data-input-otp]')!

    // Bitwarden focuses the field (React schedules a state update from
    // onFocus) and then assigns the code straight to the DOM node before the
    // input event arrives. A React-controlled value would restore the old
    // empty value on the focus re-render and wipe the code.
    act(() => {
      input.focus()
      input.value = '794364'
    })
    act(() => {})

    expect(input.value).toBe('794364')

    act(() => {
      input.dispatchEvent(new Event('input', { bubbles: true }))
    })
    const slots = Array.from(
      container.querySelectorAll('[data-slot="input-otp-slot"]'),
      (slot) => slot.textContent,
    )
    expect(slots).toEqual(['7', '9', '4', '3', '6', '4'])
  })

  it('renders a code supplied as the initial value (server-rendered fill)', () => {
    const { container } = render(<TotpInput name="totp" defaultValue="123456" />)
    const input = container.querySelector<HTMLInputElement>('[data-input-otp]')!

    const slots = Array.from(
      container.querySelectorAll('[data-slot="input-otp-slot"]'),
      (slot) => slot.textContent,
    )
    expect(slots).toEqual(['1', '2', '3', '4', '5', '6'])
    expect(input.value).toBe('123456')
  })

  it('reflects an external controlled value into the real input', () => {
    let setExternal: (value: string) => void = () => {}
    function Harness() {
      const [code, setCode] = useState('')
      setExternal = setCode
      return <TotpInput name="code" value={code} onChange={setCode} />
    }
    const { container } = render(<Harness />)
    const input = container.querySelector<HTMLInputElement>('[data-input-otp]')!

    act(() => {
      setExternal('246813')
    })
    expect(input.value).toBe('246813')
  })
})
