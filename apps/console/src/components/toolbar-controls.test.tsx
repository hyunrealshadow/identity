import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it } from 'vitest'

import { AccountMenu } from '#/components/toolbar-controls'
import { renderWithLocale } from '#/test/render'

const accountUrl = 'https://login.example.test/account'

describe('account center boundary', () => {
  it('links to the configured account center without local self-service items', async () => {
    const user = userEvent.setup()
    renderWithLocale(
      <AccountMenu
        name="Ada Lovelace"
        email="ada@example.test"
        accountUrl={accountUrl}
        onSignOut={() => undefined}
      />,
    )

    await user.click(
      screen.getByRole('button', { name: 'Account menu for Ada Lovelace' }),
    )

    const accountCenter = await screen.findByRole('menuitem', {
      name: 'Account center',
    })
    expect(accountCenter.getAttribute('href')).toBe(accountUrl)
    expect(accountCenter.getAttribute('href')).not.toMatch(/[?#]/)

    expect(screen.queryByRole('menuitem', { name: 'Profile' })).toBeNull()
    expect(screen.queryByRole('menuitem', { name: 'Sessions' })).toBeNull()
    expect(screen.queryByRole('menuitem', { name: 'Security' })).toBeNull()
    expect(screen.getByRole('menuitem', { name: 'Sign out' })).toBeTruthy()
  })
})
