import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { useState } from 'react'
import { describe, expect, it, vi } from 'vitest'

import { RolePermissionTable } from './role-permission-table'
import type { PermissionNode } from '../hooks/use-role-membership'
import { renderWithLocale } from '#/test/render'

const permission: PermissionNode = {
  id: 'scope-one',
  resourceId: null,
  code: 'report.read',
  name: 'Read reports',
  description: 'View reports',
  builtIn: false,
  enabled: true,
  version: 'lock',
  createdAt: '2026-01-01T00:00:00Z',
  updatedAt: null,
  names: [],
  descriptions: [],
  resource: null,
}

describe('role permission table', () => {
  it('preserves staged removal and undo actions through the common table', async () => {
    const onToggle = vi.fn()
    function Fixture() {
      const [selected, setSelected] = useState(new Set([permission.id]))
      return (
        <RolePermissionTable
          items={[permission]}
          initial={new Set([permission.id])}
          selected={selected}
          staged={new Map()}
          disabled={false}
          onToggle={(id) => {
            onToggle(id)
            setSelected(selected.has(id) ? new Set() : new Set([id]))
          }}
        />
      )
    }
    const user = userEvent.setup()
    renderWithLocale(<Fixture />)
    screen.getByRole('button', { name: 'Actions for report.read' }).focus()
    await user.keyboard('{ArrowDown}')
    await user.click(
      screen.getByRole('menuitem', { name: 'Remove' }),
    )
    expect(onToggle).toHaveBeenLastCalledWith(permission.id)
    expect(screen.getByRole('rowheader', { name: /Read reports/ })).toBeTruthy()
    screen.getByRole('button', { name: 'Actions for report.read' }).focus()
    await user.keyboard('{ArrowDown}')
    await user.click(
      screen.getByRole('menuitem', { name: 'Undo removal' }),
    )
    expect(onToggle).toHaveBeenCalledTimes(2)
    expect(
      screen.getByRole('button', { name: 'Actions for report.read' }),
    ).toBeTruthy()
  })
})

it('keeps pending assignments intact when the resource filter changes', () => {
  const assigned = { ...permission, resourceId: 'api-one' }
  const staged = {
    id: 'scope-two',
    code: 'report.write',
    name: 'Write reports',
    description: null,
    enabled: true,
    resourceId: 'api-two',
    resourceName: 'Reports',
    resourceUri: 'urn:reports',
  }
  const selected = new Set([assigned.id, staged.id])
  const props = {
    items: [assigned],
    initial: new Set([assigned.id]),
    selected,
    staged: new Map([[staged.id, staged]]),
    disabled: false,
    onToggle: vi.fn(),
  }
  const view = renderWithLocale(
    <RolePermissionTable {...props} resourceId="api-one" />,
  )
  expect(screen.getByText('report.read')).toBeTruthy()
  expect(screen.queryByText('report.write')).toBeNull()
  view.rerender(<RolePermissionTable {...props} resourceId="api-two" />)
  expect(screen.getByText('report.write')).toBeTruthy()
  expect(props.onToggle).not.toHaveBeenCalled()
  expect([...selected]).toEqual([assigned.id, staged.id])
})
