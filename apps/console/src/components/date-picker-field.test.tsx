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
        name="createdTo"
        label="Created to"
        value={value}
        onChange={(next) => {
          setValue(next)
          onChange(next)
        }}
      />
    </form>
  )
}

function posted(name: string) {
  return new FormData(screen.getByRole('form') as HTMLFormElement).get(name)
}

describe('date picker field', () => {
  it('selects a calendar day and clears the controlled ISO date without a time-zone conversion', async () => {
    const onChange = vi.fn()
    const user = userEvent.setup()
    renderWithLocale(<Fixture onChange={onChange} />)
    const input = screen.getByRole('textbox', { name: 'Created to' })
    expect((input as HTMLInputElement).placeholder).toBe('MM/DD/YYYY')
    expect((input as HTMLInputElement).value).toBe('02/01/2026')

    await user.click(screen.getByRole('button', { name: 'Choose date' }))
    const calendar = screen.getByRole('dialog')
    const day = within(calendar)
      .getAllByRole('button', { name: /February 2/ })
      .find((button) => button.textContent?.trim() === '2')
    if (!day) throw new Error('February 2 button is missing')
    await user.click(day)
    expect(onChange).toHaveBeenLastCalledWith('2026-02-02')
    expect(posted('createdTo')).toBe('2026-02-02')
    expect((input as HTMLInputElement).value).toBe('02/02/2026')

    await user.click(screen.getByRole('button', { name: 'Clear' }))
    expect(onChange).toHaveBeenLastCalledWith('')
    expect(screen.queryByRole('dialog')).toBeNull()
    expect(posted('createdTo')).toBe('')
    expect((input as HTMLInputElement).value).toBe('')
    // The clear control is gone; focus returns to the date input itself.
    expect(document.activeElement).toBe(input)
  })

  it('accepts a typed date and keeps the last valid day for unrecognised text', async () => {
    const onChange = vi.fn()
    const user = userEvent.setup()
    renderWithLocale(<Fixture onChange={onChange} />)
    const input = screen.getByRole('textbox', {
      name: 'Created to',
    }) as HTMLInputElement

    await user.clear(input)
    await user.type(input, '2026-03-04')
    expect(onChange).toHaveBeenLastCalledWith('2026-03-04')
    await user.tab()
    expect(input.value).toBe('03/04/2026')
    expect(posted('createdTo')).toBe('2026-03-04')

    // Without a leading year, the locale's own order applies (month first).
    await user.clear(input)
    await user.type(input, '4/5/2026')
    await user.tab()
    expect(posted('createdTo')).toBe('2026-04-05')

    onChange.mockClear()
    await user.clear(input)
    await user.type(input, 'not a date')
    await user.tab()
    expect(input.value).toBe('04/05/2026')
    expect(posted('createdTo')).toBe('2026-04-05')
    // Editing through unrecognised text never replaces the committed day.
    expect(onChange).not.toHaveBeenCalled()

    // Leaving the box empty is how a typed value is cleared.
    await user.clear(input)
    await user.tab()
    expect(onChange).toHaveBeenLastCalledWith('')
    expect(posted('createdTo')).toBe('')
  })

  it('opens the calendar from the keyboard', async () => {
    const user = userEvent.setup()
    renderWithLocale(<Fixture />)
    await user.click(screen.getByRole('textbox', { name: 'Created to' }))
    await user.keyboard('{ArrowDown}')
    expect(screen.getByRole('dialog')).toBeTruthy()
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
          calendarLabel="选择日期"
        />
      </form>,
    )
    const input = screen.getByRole('textbox', {
      name: '出生日期',
    }) as HTMLInputElement
    expect(input.value).toBe('2000/02/01')
    expect(input.placeholder).toBe('YYYY/MM/DD')

    await user.click(screen.getByRole('button', { name: '选择日期' }))
    const calendar = screen.getByRole('dialog')
    expect(within(calendar).getByRole('grid')).toBeTruthy()
    await user.click(
      within(calendar).getByRole('button', { name: /2000年2月2日/ }),
    )
    expect(posted('birthdate')).toBe('2000-02-02')

    await user.clear(input)
    await user.type(input, '2001/3/4')
    expect(posted('birthdate')).toBe('2001-03-04')

    await user.click(screen.getByRole('button', { name: '清除' }))
    expect(posted('birthdate')).toBe('')
  })
})
