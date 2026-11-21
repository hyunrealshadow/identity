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
  {
    name: 'targetType',
    type: 'keyword',
    search: async (query) =>
      ['user_group', 'user', 'user_role']
        .filter((value) => value.startsWith(query))
        .map((value) => ({ label: value, value })),
  },
]

async function openCompletions(value: string) {
  const onChange = vi.fn()
  const onSubmit = vi.fn()
  const props = { onChange, onSubmit, fields, locale: 'en', ariaLabel: 'Query' }
  const view = render(<LuceneInput value="" {...props} />)
  const editor = screen.getByRole('combobox', { name: 'Query' })
  await act(async () => {
    editor.focus()
    fireEvent.focus(editor)
  })
  view.rerender(<LuceneInput value={value} {...props} />)
  await act(async () => {
    editor.focus()
    fireEvent.focus(editor)
  })
  await waitFor(() => {
    expect(screen.getByRole('listbox')).toBeTruthy()
  })
  onChange.mockClear()
  return { editor, onChange, onSubmit }
}

const optionLabels = () =>
  screen
    .getAllByRole('option')
    .map((option) => option.querySelector('.lucene-completion-label')?.textContent)

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

  it('submits on Enter while suggestions are open but none was chosen', async () => {
    const { editor, onChange, onSubmit } = await openCompletions('targetType:user')

    expect(screen.getAllByRole('option').every((o) => o.getAttribute('aria-selected') === 'false')).toBe(true)
    fireEvent.keyDown(editor, { key: 'Enter', code: 'Enter' })

    expect(onSubmit).toHaveBeenCalledWith('targetType:user')
    expect(onChange).not.toHaveBeenCalled()
    await waitFor(() => {
      expect(screen.queryByRole('listbox')).toBeNull()
    })
  })

  it('accepts an option chosen with the arrow keys on Enter', async () => {
    const { editor, onChange, onSubmit } = await openCompletions('targetType:user')

    fireEvent.keyDown(editor, { key: 'ArrowDown', code: 'ArrowDown' })
    fireEvent.keyDown(editor, { key: 'ArrowDown', code: 'ArrowDown' })
    fireEvent.keyDown(editor, { key: 'Enter', code: 'Enter' })

    expect(onSubmit).not.toHaveBeenCalled()
    expect(onChange).toHaveBeenCalledWith('targetType:user_group')
  })

  it('ranks an exact match first and accepts the first option on Tab', async () => {
    const { editor, onChange } = await openCompletions('targetType:us')
    expect(optionLabels()).toEqual(['user_group', 'user', 'user_role'])

    fireEvent.keyDown(editor, { key: 'Tab', code: 'Tab' })
    expect(onChange).toHaveBeenCalledWith('targetType:user_group')
  })

  it('keeps a complete value listed first instead of replacing it', async () => {
    await openCompletions('targetType:user')

    expect(optionLabels()).toEqual(['user', 'user_group', 'user_role'])
  })

  it('shows value suggestions right after accepting a field name', async () => {
    const { editor } = await openCompletions('targetT')

    fireEvent.keyDown(editor, { key: 'Tab', code: 'Tab' })

    await waitFor(() => {
      expect(optionLabels()).toContain('user_group')
    })
  })

  it('offers recent searches and every field when focused empty', async () => {
    const props = {
      onChange: vi.fn(),
      fields,
      locale: 'en',
      ariaLabel: 'Query',
      history: ['action:user.create', 'targetType:user'],
    }
    render(<LuceneInput value="" {...props} />)
    const editor = screen.getByRole('combobox', { name: 'Query' })
    await act(async () => {
      editor.focus()
      fireEvent.focus(editor)
    })

    await waitFor(() => {
      expect(optionLabels()).toEqual([
        'action:user.create',
        'targetType:user',
        'action:',
        'occurredAt:',
        'targetType:',
      ])
    })
    expect(screen.getByText('Recent searches')).toBeTruthy()
    expect(screen.getByText('Narrow your search')).toBeTruthy()
    expect(screen.getByText('to cycle through history')).toBeTruthy()

    fireEvent.click(screen.getByRole('option', { name: /targetType:user/ }))
    expect(props.onChange).toHaveBeenCalledWith('targetType:user')
  })

  it('cycles through history with Shift+Up and Shift+Down and restores the draft', async () => {
    const onChange = vi.fn()
    render(
      <LuceneInput
        value="act"
        onChange={onChange}
        fields={fields}
        ariaLabel="Query"
        history={['newest', 'oldest']}
      />,
    )
    const editor = screen.getByRole('combobox', { name: 'Query' })

    fireEvent.keyDown(editor, { key: 'ArrowUp', code: 'ArrowUp', shiftKey: true })
    expect(onChange).toHaveBeenLastCalledWith('newest')
    fireEvent.keyDown(editor, { key: 'ArrowUp', code: 'ArrowUp', shiftKey: true })
    expect(onChange).toHaveBeenLastCalledWith('oldest')
    fireEvent.keyDown(editor, { key: 'ArrowDown', code: 'ArrowDown', shiftKey: true })
    fireEvent.keyDown(editor, { key: 'ArrowDown', code: 'ArrowDown', shiftKey: true })
    expect(onChange).toHaveBeenLastCalledWith('act')
  })
})
