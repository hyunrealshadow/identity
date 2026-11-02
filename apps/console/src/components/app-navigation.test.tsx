import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'

import { MobileNavigation, NavigationLinks } from '#/components/app-navigation'
import { renderWithLocale } from '#/test/render'

vi.mock('@tanstack/react-router', async () => {
  const React = await import('react')
  return {
    Link: ({
      children,
      to,
      className,
    }: {
      children?: import('react').ReactNode
      to: string
      className?: string
    }) => React.createElement('a', { href: to, className }, children),
  }
})

describe('navigation accessibility', () => {
  it('opens resource management without offering a standalone permission catalogue', () => {
    renderWithLocale(<NavigationLinks collapsed={false} />)
    expect(
      screen.getByRole('link', { name: 'Resources' }).getAttribute('href'),
    ).toBe('/resources')
    expect(screen.queryByRole('link', { name: 'Permissions' })).toBeNull()
    expect(screen.getByRole('link', { name: 'Roles' })).toBeTruthy()
  })

  it('opens the mobile Drawer, closes on Escape, and returns focus to the trigger', async () => {
    const user = userEvent.setup()
    renderWithLocale(<MobileNavigation displayName="Identity Console" />)

    const trigger = screen.getByRole('button', { name: 'Open navigation' })
    await user.click(trigger)

    const dialog = await screen.findByRole('dialog', {
      name: 'Console navigation',
    })
    expect(dialog).toBeTruthy()

    await user.keyboard('{Escape}')
    await waitFor(() => {
      expect(screen.queryByRole('dialog')).toBeNull()
    })
    await waitFor(() => {
      expect(document.activeElement).toBe(trigger)
    })
  })
})
