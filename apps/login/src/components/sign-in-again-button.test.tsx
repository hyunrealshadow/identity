// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { SignInAgainButton } from './sign-in-again-button'

function pageShow(persisted: boolean) {
  const event = new Event('pageshow')
  Object.defineProperty(event, 'persisted', { value: persisted })
  window.dispatchEvent(event)
}

afterEach(() => {
  cleanup()
  window.history.replaceState({}, '', '/')
})

describe('SignInAgainButton', () => {
  it('becomes usable again when Back restores the page from the back/forward cache', async () => {
    // A hash-only target keeps jsdom on this document, like a frozen page.
    const begin = vi.fn().mockResolvedValue('#authorize')
    render(<SignInAgainButton label="Sign in again" begin={begin} />)
    const button = screen.getByRole('button', { name: 'Sign in again' })

    fireEvent.click(button)
    await waitFor(() => expect(button.hasAttribute('disabled')).toBe(true))
    expect(begin).toHaveBeenCalledTimes(1)

    pageShow(false)
    expect(button.hasAttribute('disabled')).toBe(true)

    pageShow(true)
    await waitFor(() => expect(button.hasAttribute('disabled')).toBe(false))
  })

  it('stays usable when the authorization request cannot be started', async () => {
    const begin = vi.fn().mockRejectedValue(new Error('unavailable'))
    render(<SignInAgainButton label="Sign in again" begin={begin} />)
    const button = screen.getByRole('button', { name: 'Sign in again' })

    fireEvent.click(button)

    await waitFor(() => expect(begin).toHaveBeenCalledTimes(1))
    await waitFor(() => expect(button.hasAttribute('disabled')).toBe(false))
  })
})
