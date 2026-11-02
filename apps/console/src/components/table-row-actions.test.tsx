import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import { TableRowActions } from './table-row-actions'
import { renderWithLocale } from '#/test/render'

describe('table row actions', () => {
  it('supports keyboard selection, disabled items and restoring trigger focus', async () => {
    const view = vi.fn(),
      forbidden = vi.fn()
    const parentKeyDown = vi.fn()
    const user = userEvent.setup()
    renderWithLocale(
      <div onKeyDown={parentKeyDown}>
        <TableRowActions
          subject="Example"
          actions={[
            { id: 'view', label: 'View', onAction: view },
            {
              id: 'blocked',
              label: 'Blocked',
              onAction: forbidden,
              isDisabled: true,
            },
          ]}
        />
      </div>,
    )
    const trigger = screen.getByRole('button', { name: 'Actions for Example' })
    trigger.focus()
    await user.keyboard('{ArrowDown}')
    expect(
      screen
        .getByRole('menuitem', { name: 'Blocked' })
        .getAttribute('aria-disabled'),
    ).toBe('true')
    await user.click(screen.getByRole('menuitem', { name: 'Blocked' }))
    expect(forbidden).not.toHaveBeenCalled()
    await user.keyboard('{Escape}')
    await waitFor(() => expect(document.activeElement).toBe(trigger))
    await user.click(trigger)
    await user.click(screen.getByRole('menuitem', { name: 'View' }))
    expect(view).toHaveBeenCalledTimes(1)
    await waitFor(() => expect(screen.queryByRole('menu')).toBeNull())
    expect(parentKeyDown).not.toHaveBeenCalled()
  })
})
