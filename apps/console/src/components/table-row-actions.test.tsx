import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import { TableRowActions, copyIdAction } from './table-row-actions'
import { renderWithLocale } from '#/test/render'

const toast = vi.hoisted(() => ({ success: vi.fn(), error: vi.fn() }))
vi.mock('#/lib/toast', () => ({ toast }))

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
            { id: 'view', label: 'View', section: 'open', onAction: view },
            {
              id: 'blocked',
              label: 'Blocked',
              section: 'state',
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
    await user.keyboard('{ArrowDown}')
    await user.click(screen.getByRole('menuitem', { name: 'View' }))
    expect(view).toHaveBeenCalledTimes(1)
    await waitFor(() => expect(screen.queryByRole('menu')).toBeNull())
    expect(parentKeyDown).not.toHaveBeenCalled()
  })

  it('orders actions by section, separates sections, and marks danger items', async () => {
    const user = userEvent.setup()
    renderWithLocale(
      <TableRowActions
        subject="Example"
        actions={[
          { id: 'delete', label: 'Delete', section: 'danger', onAction: vi.fn() },
          { id: 'disable', label: 'Disable', section: 'state', onAction: vi.fn() },
          { id: 'view', label: 'View', section: 'open', onAction: vi.fn() },
          { id: 'members', label: 'Members', section: 'navigate', onAction: vi.fn() },
        ]}
      />,
    )
    await user.click(screen.getByRole('button', { name: 'Actions for Example' }))
    const menu = await screen.findByRole('menu')
    expect(within(menu).getAllByRole('menuitem').map((item) => item.textContent)).toEqual([
      'View',
      'Members',
      'Disable',
      'Delete',
    ])
    expect(within(menu).getAllByRole('separator')).toHaveLength(3)
    expect(
      within(menu).getByRole('menuitem', { name: 'Delete' }).getAttribute('data-variant'),
    ).toBe('destructive')
  })

  it('copies an ID and reports the result', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined)
    Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true })
    const action = copyIdAction('VXNlcjox', (key) => key)
    action.onAction()
    await waitFor(() => expect(toast.success).toHaveBeenCalledWith('valueCopied'))
    expect(writeText).toHaveBeenCalledWith('VXNlcjox')
    expect(action.section).toBe('copy')
  })
})
