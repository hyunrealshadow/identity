import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { LuceneInput } from './LuceneInput'
import type { LuceneField } from './lib/types'

const fields: LuceneField[] = [
  {
    name: 'action',
    type: 'keyword',
    search: async (query) =>
      [
        { label: 'user.create', value: 'user.create', detail: 'User creation' },
        { label: 'user.delete', value: 'user.delete', detail: 'User deletion' },
      ].filter((option) => option.label.includes(query)),
  },
  {
    name: 'occurredAt',
    type: 'datetime',
  },
]

describe('LuceneInput (React)', () => {
  it('renders controlled value and emits diagnostics', async () => {
    const onChange = vi.fn()
    const onDiagnostics = vi.fn()

    render(
      <LuceneInput
        value="badField:test"
        onChange={onChange}
        onDiagnostics={onDiagnostics}
        fields={fields}
        disallowUnknownFields
        locale="en"
        ariaLabel="Audit filter"
      />,
    )

    const editor = screen.getByRole('combobox', { name: 'Audit filter' })
    expect(editor.textContent).toContain('badField:test')

    await waitFor(() => {
      expect(onDiagnostics).toHaveBeenCalled()
    })
    const lastCall = onDiagnostics.mock.calls.at(-1)?.[0]
    expect(lastCall).toHaveLength(1)
    expect(lastCall?.[0]?.code).toBe('unknownField')
  })

  it('calls onSubmit on Enter when completion menu is closed', async () => {
    const onSubmit = vi.fn()
    const onChange = vi.fn()

    render(
      <LuceneInput
        value="action:user.create"
        onChange={onChange}
        onSubmit={onSubmit}
        fields={fields}
        locale="en"
        ariaLabel="Audit query"
      />,
    )

    const editor = screen.getByRole('combobox', { name: 'Audit query' })
    fireEvent.keyDown(editor, { key: 'Enter', code: 'Enter' })

    expect(onSubmit).toHaveBeenCalledWith('action:user.create')
  })

  it('opens completion options on focus/edit, inserts selection on click, and syncs disabled state', async () => {
    const onChange = vi.fn()
    const onSubmit = vi.fn()

    const { rerender } = render(
      <LuceneInput
        value=""
        onChange={onChange}
        onSubmit={onSubmit}
        fields={fields}
        locale="zh-CN"
        timeZone="Asia/Shanghai"
        ariaLabel="查询输入框"
      />,
    )

    const editor = screen.getByRole('combobox', { name: '查询输入框' })
    await act(async () => {
      editor.focus()
      fireEvent.focus(editor)
    })

    // Updating to partial field value triggers field-value completions
    rerender(
      <LuceneInput
        value="action:user."
        onChange={onChange}
        onSubmit={onSubmit}
        fields={fields}
        locale="zh-CN"
        timeZone="Asia/Shanghai"
        ariaLabel="查询输入框"
      />,
    )

    await act(async () => {
      editor.focus()
      fireEvent.focus(editor)
    })

    await waitFor(() => {
      expect(screen.getByRole('listbox')).toBeTruthy()
    })

    const option = screen.getByRole('option', { name: /user\.create/ })
    fireEvent.click(option)

    await waitFor(() => {
      expect(onChange).toHaveBeenCalled()
    })
    expect(onChange.mock.calls.some(([val]) => String(val).includes('action:user.create'))).toBe(true)

    rerender(
      <LuceneInput
        value="action:user.create"
        onChange={onChange}
        onSubmit={onSubmit}
        fields={fields}
        disabled
        ariaLabel="查询输入框"
      />,
    )
    expect(editor.getAttribute('aria-disabled')).toBe('true')
  })
})
