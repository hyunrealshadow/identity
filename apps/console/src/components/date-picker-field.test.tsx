import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { useState } from 'react'
import { describe, expect, it, vi } from 'vitest'

import { DatePickerField } from '#/components/date-picker-field'
import { DatePickerField as SharedDatePickerField } from '@identity/ui/date-picker-field'
import { renderWithLocale } from '#/test/render'

function Fixture({
  onChange = () => {},
}: {
  onChange?: (value: string) => void
}) {
  const [value, setValue] = useState('2026-02-01')
  return (
    <form aria-label="Filter">
      <DatePickerField
        name="createdBefore"
        label="Created before"
        value={value}
        onChange={(next) => {
          setValue(next)
          onChange(next)
        }}
      />
    </form>
  )
}

describe('date picker field', () => {
  it('selects a calendar day and clears the controlled ISO date without a time-zone conversion', async () => {
    const onChange = vi.fn()
    const user = userEvent.setup()
    renderWithLocale(<Fixture onChange={onChange} />)

    await user.click(screen.getByRole('button'))
    const calendar = screen.getByRole('dialog')
    await user.click(
      within(calendar).getByRole('button', { name: /February 2, 2026/ }),
    )
    expect(onChange).toHaveBeenLastCalledWith('2026-02-02')
    expect(
      new FormData(screen.getByRole('form') as HTMLFormElement).get(
        'createdBefore',
      ),
    ).toBe('2026-02-02')

    await user.click(screen.getByRole('button'))
    await user.click(screen.getByRole('button', { name: 'Clear' }))
    expect(onChange).toHaveBeenLastCalledWith('')
    expect(screen.queryByRole('dialog')).toBeNull()
    expect(
      new FormData(screen.getByRole('form') as HTMLFormElement).get(
        'createdBefore',
      ),
    ).toBe('')
  })

  it('supports an uncontrolled profile form and an explicit account locale', async () => {
    const user = userEvent.setup()
    renderWithLocale(
      <form aria-label="Profile">
        <SharedDatePickerField
          name="birthdate"
          label="出生日期"
          defaultValue="2000-02-01"
          locale="zh-CN"
          timeZone="America/Los_Angeles"
          clearLabel="清除"
        />
      </form>,
    )
    await user.click(screen.getByRole('button'))
    expect(screen.getByRole('grid').getAttribute('aria-label')).toContain(
      '2000年2月',
    )
    await user.click(screen.getByRole('button', { name: /2000年2月2日/ }))
    const form = screen.getByRole('form') as HTMLFormElement
    expect(new FormData(form).get('birthdate')).toBe('2000-02-02')
    await user.click(screen.getByRole('button'))
    await user.click(screen.getByRole('button', { name: '清除' }))
    expect(new FormData(form).get('birthdate')).toBe('')
  })
})
