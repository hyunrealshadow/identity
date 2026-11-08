import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { useState } from 'react'
import { describe, expect, it, vi } from 'vitest'

import { ResourceTable } from '#/components/resource-table'
import { renderWithLocale } from '#/test/render'

const rows = [{ id: 'one', name: 'Ada', updated: 'Yesterday' }]
const columns = [
  {
    id: 'name',
    label: 'Name',
    primary: true,
    sort: 'NAME',
    render: (row: (typeof rows)[number]) => row.name,
  },
  {
    id: 'updated',
    label: 'Updated',
    sort: 'UPDATED_AT',
    render: (row: (typeof rows)[number]) => row.updated,
  },
]

function Fixture({
  id = 'test',
  onOrderChange = () => {},
  onRefresh = () => {},
  initialOrder,
}: {
  id?: string
  onOrderChange?: (order: string | undefined) => void
  onRefresh?: () => void
  initialOrder?: string
}) {
  const [order, setOrder] = useState(initialOrder)
  return (
    <ResourceTable
      id={id}
      label="Directory"
      items={rows}
      columns={columns}
      order={order}
      onOrderChange={(value) => {
        setOrder(value)
        onOrderChange(value)
      }}
      onRefresh={onRefresh}
      pagination={null}
    />
  )
}

describe('resource table interactions', () => {
  it('cycles server sorting through ascending, descending, and default order', async () => {
    const onOrderChange = vi.fn()
    const onRefresh = vi.fn()
    const user = userEvent.setup()
    renderWithLocale(
      <Fixture onOrderChange={onOrderChange} onRefresh={onRefresh} />,
    )
    const name = screen.getByRole('columnheader', { name: /Name/ })
    const nameButton = screen.getByRole('button', { name: /Name/ })
    expect([null, 'none']).toContain(name.getAttribute('aria-sort'))
    await user.click(nameButton)
    expect(onOrderChange).toHaveBeenLastCalledWith('NAME_ASC')
    expect(name.getAttribute('aria-sort')).toBe('ascending')
    await user.click(nameButton)
    expect(onOrderChange).toHaveBeenLastCalledWith('NAME_DESC')
    expect(name.getAttribute('aria-sort')).toBe('descending')
    await user.click(nameButton)
    expect(onOrderChange).toHaveBeenLastCalledWith(undefined)
    expect([null, 'none']).toContain(name.getAttribute('aria-sort'))
    await user.click(nameButton)
    expect(onOrderChange).toHaveBeenLastCalledWith('NAME_ASC')
    await user.click(screen.getByRole('button', { name: 'Refresh table' }))
    expect(onRefresh).toHaveBeenCalledOnce()
  })

  it('starts a different column in ascending order and clears a restored sort with the keyboard', async () => {
    const onOrderChange = vi.fn()
    const user = userEvent.setup()
    renderWithLocale(
      <Fixture initialOrder="NAME_DESC" onOrderChange={onOrderChange} />,
    )
    const updated = screen.getByRole('columnheader', { name: /Updated/ })
    const updatedButton = screen.getByRole('button', { name: /Updated/ })
    await user.click(updatedButton)
    expect(onOrderChange).toHaveBeenLastCalledWith('UPDATED_AT_ASC')
    expect(updated.getAttribute('aria-sort')).toBe('ascending')
    await user.keyboard('{Enter}')
    expect(onOrderChange).toHaveBeenLastCalledWith('UPDATED_AT_DESC')
    await user.keyboard('{Enter}')
    expect(onOrderChange).toHaveBeenLastCalledWith(undefined)
    expect([null, 'none']).toContain(updated.getAttribute('aria-sort'))
  })

  it('applies display preferences explicitly, persists them per table, and keeps the primary column', async () => {
    const user = userEvent.setup()
    const first = renderWithLocale(<Fixture />)
    await user.click(screen.getByRole('button', { name: 'Table preferences' }))
    const dialog = screen.getByRole('dialog')
    expect(
      within(dialog)
        .getByRole('checkbox', { name: 'Name' })
        .getAttribute('aria-disabled') === 'true',
    ).toBe(true)
    await user.click(within(dialog).getByRole('checkbox', { name: 'Updated' }))
    await user.click(
      within(dialog).getByRole('checkbox', { name: 'Compact rows' }),
    )
    await user.click(within(dialog).getByRole('button', { name: 'Apply' }))
    expect(screen.queryByRole('columnheader', { name: 'Updated' })).toBeNull()
    expect(screen.getByRole('grid').getAttribute('data-density')).toBe(
      'compact',
    )
    first.unmount()
    const second = renderWithLocale(<Fixture />)
    expect(screen.queryByRole('columnheader', { name: 'Updated' })).toBeNull()
    second.unmount()
    renderWithLocale(<Fixture id="another-table" />)
    expect(screen.getByRole('columnheader', { name: 'Updated' })).toBeTruthy()
  })

  it('cancels draft changes and provides localized controls', async () => {
    const user = userEvent.setup()
    renderWithLocale(<Fixture />, { locale: 'zh-CN' })
    await user.click(screen.getByRole('button', { name: '表格设置' }))
    await user.click(screen.getByRole('checkbox', { name: 'Updated' }))
    await user.click(
      within(screen.getByRole('dialog')).getByRole('button', { name: '取消' }),
    )
    expect(screen.getByRole('columnheader', { name: 'Updated' })).toBeTruthy()
    await user.click(screen.getByRole('button', { name: '表格设置' }))
    expect(
      screen.getByRole('checkbox', { name: 'Updated' }).getAttribute('aria-checked') === 'true',
    ).toBe(true)
    expect(screen.getByRole('checkbox', { name: '内容换行' })).toBeTruthy()
  })
})
