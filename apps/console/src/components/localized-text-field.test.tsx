import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { useState, type FormEvent } from 'react'
import { describe, expect, it, vi } from 'vitest'

import { LocalizedTextField } from '#/components/localized-text-field'
import type { LocalizedValues } from '#/lib/localized-values'
import { renderWithLocale } from '#/test/render'

function Harness({
  initial,
  isReadOnly = false,
  isDisabled = false,
}: {
  initial: LocalizedValues
  isReadOnly?: boolean
  isDisabled?: boolean
}) {
  const [value, setValue] = useState(initial)
  const [defaultValue, setDefaultValue] = useState('Default name')
  return (
    <>
      <LocalizedTextField
        name="names"
        label="Names"
        defaultValue={defaultValue}
        onDefaultValueChange={setDefaultValue}
        value={value}
        onChange={setValue}
        isRequired
        isReadOnly={isReadOnly}
        isDisabled={isDisabled}
        maxLength={256}
      />
      <output data-testid="draft">{JSON.stringify(value)}</output>
    </>
  )
}

function draft(): LocalizedValues {
  return JSON.parse(screen.getByTestId('draft').textContent ?? '{}')
}

function translationInput(): HTMLInputElement {
  return screen.getByRole('textbox', { name: /Names/ }) as HTMLInputElement
}

async function chooseLanguage(
  user: ReturnType<typeof userEvent.setup>,
  tag: string,
) {
  await user.click(screen.getByRole('button', { name: 'Add translation' }))
  await user.type(
    screen.getByRole('combobox', { name: 'Choose language' }),
    tag,
  )
  const options = await screen.findByRole('listbox')
  await user.click(
    within(options).getByRole('option', {
      name: new RegExp('\\(' + tag + '\\)$'),
    }),
  )
}

describe('localized text field', () => {
  it('shows only the active language and switches between translations', async () => {
    const user = userEvent.setup()
    renderWithLocale(
      <Harness
        initial={{ 'en-US': 'English name', 'fr-CA': 'Nom français' }}
      />,
    )

    expect(translationInput().getAttribute('name')).toBe('names.en-US')
    expect(translationInput().value).toBe('English name')
    expect(screen.getAllByRole('textbox')).toHaveLength(2)

    await user.click(screen.getByRole('combobox', { name: /Language/ }))
    const frenchOptions = await screen.findByRole('listbox')
    await user.click(
      within(frenchOptions).getByRole('option', { name: /fr-CA/ }),
    )

    expect(translationInput().getAttribute('name')).toBe('names.fr-CA')
    expect(translationInput().value).toBe('Nom français')
    expect(screen.getAllByRole('textbox')).toHaveLength(2)
  })

  it('edits the independent default without inventing or overwriting translations', async () => {
    const user = userEvent.setup()
    renderWithLocale(<Harness initial={{ 'fr-CA': 'Lecteurs' }} />)
    const fallback = screen.getByRole('textbox', {
      name: 'Default',
    }) as HTMLInputElement
    await user.clear(fallback)
    await user.type(fallback, 'Independent default')
    expect(draft()).toEqual({ 'fr-CA': 'Lecteurs' })
    await user.clear(translationInput())
    await user.type(translationInput(), 'Nouvelle traduction')
    expect(fallback.value).toBe('Independent default')
    await user.click(screen.getByRole('button', { name: /Remove translation/ }))
    expect(draft()).toEqual({})
    expect(fallback.value).toBe('Independent default')
  })

  it('adds a canonical locale and removes it with a visible undo', async () => {
    const user = userEvent.setup()
    renderWithLocale(<Harness initial={{ 'en-US': 'English name' }} />)

    await chooseLanguage(user, 'de-AT')

    expect(translationInput().getAttribute('name')).toBe('names.de-AT')
    expect(draft()).toEqual({ 'en-US': 'English name', 'de-AT': '' })
    expect(screen.queryByRole('alert')).toBeNull()

    await user.type(translationInput(), 'Deutscher Name')
    expect(draft()['de-AT']).toBe('Deutscher Name')

    await user.click(screen.getByRole('button', { name: /Remove translation/ }))
    expect(draft()).toEqual({ 'en-US': 'English name' })
    expect(screen.getByText('Removed de-AT.').getAttribute('role')).toBe(
      'status',
    )

    await user.click(screen.getByRole('button', { name: 'Undo' }))
    expect(draft()).toEqual({
      'en-US': 'English name',
      'de-AT': 'Deutscher Name',
    })
    expect(translationInput().getAttribute('name')).toBe('names.de-AT')
    expect(translationInput().value).toBe('Deutscher Name')
  })

  it('keeps language switching available while read-only without editing', async () => {
    const user = userEvent.setup()
    renderWithLocale(
      <Harness
        initial={{ 'en-US': 'English name', 'zh-CN': '中文名称' }}
        isReadOnly
      />,
    )

    expect(translationInput().readOnly).toBe(true)
    expect(screen.queryByRole('button', { name: 'Add translation' })).toBeNull()
    expect(
      screen.queryByRole('button', { name: /Remove translation/ }),
    ).toBeNull()

    await user.click(screen.getByRole('combobox', { name: /Language/ }))
    const chineseOptions = await screen.findByRole('listbox')
    await user.click(
      within(chineseOptions).getByRole('option', { name: /zh-CN/ }),
    )

    expect(translationInput().getAttribute('name')).toBe('names.zh-CN')
    expect(translationInput().value).toBe('中文名称')
  })

  it('does not submit the surrounding form from field actions', async () => {
    const user = userEvent.setup()
    const onSubmit = vi.fn((event: FormEvent<HTMLFormElement>) =>
      event.preventDefault(),
    )
    renderWithLocale(
      <form onSubmit={onSubmit}>
        <Harness initial={{ 'en-US': 'English name' }} />
      </form>,
    )

    await chooseLanguage(user, 'ja-JP')
    await user.type(translationInput(), '日本語の名前')
    await user.click(screen.getByRole('button', { name: /Remove translation/ }))
    await user.click(screen.getByRole('button', { name: 'Undo' }))
    await user.click(screen.getByRole('combobox', { name: /Language/ }))
    const englishOptions = await screen.findByRole('listbox')
    await user.click(
      within(englishOptions).getByRole('option', { name: /en-US/ }),
    )

    expect(onSubmit).not.toHaveBeenCalled()
  })

  it('shows an existing translation with its real language when the UI language is absent', () => {
    renderWithLocale(<Harness initial={{ 'fr-CA': 'Lecteurs' }} />)
    expect(translationInput().name).toBe('names.fr-CA')
    expect(translationInput().value).toBe('Lecteurs')
    expect(draft()).toEqual({ 'fr-CA': 'Lecteurs' })
    expect(screen.getByTitle('1 of 1 translations filled')).toBeTruthy()
  })

  it('cannot undo a removal beyond the language limit after adding a replacement', async () => {
    const user = userEvent.setup()
    const initial = Object.fromEntries(
      Array.from({ length: 20 }, (_, index) => [
        `de-${100 + index}`,
        `Name ${index}`,
      ]),
    )
    renderWithLocale(<Harness initial={initial} />)
    await user.click(screen.getByRole('button', { name: /Remove translation/ }))
    expect(Object.keys(draft())).toHaveLength(19)
    await chooseLanguage(user, 'fr-CA')
    expect(Object.keys(draft())).toHaveLength(20)
    const undo = screen.getByRole('button', { name: 'Undo' })
    expect(
      undo.hasAttribute('disabled') ||
        undo.getAttribute('aria-disabled') === 'true',
    ).toBe(true)
    await user.click(undo)
    expect(Object.keys(draft())).toHaveLength(20)
  })
  it('keeps the search and latest draft when the parent updates text', async () => {
    const user = userEvent.setup()
    const onChange = vi.fn()
    const props = {
      name: 'names',
      label: 'Names',
      defaultValue: 'Default',
      onDefaultValueChange: vi.fn(),
      onChange,
    }
    const { rerender } = renderWithLocale(
      <LocalizedTextField {...props} value={{ 'en-US': 'Original' }} />,
    )
    await user.click(screen.getByRole('button', { name: 'Add translation' }))
    const search = screen.getByRole('combobox', { name: 'Choose language' })
    await user.type(search, 'ja-JP')
    rerender(
      <LocalizedTextField
        {...props}
        defaultValue="Latest default"
        value={{ 'en-US': 'Latest translation' }}
      />,
    )
    expect((search as HTMLInputElement).value).toBe('ja-JP')
    await user.keyboard('{ArrowDown}{Enter}')
    expect(onChange).toHaveBeenCalledWith({
      'en-US': 'Latest translation',
      'ja-JP': '',
    })
  })

  it('filters out existing languages and never treats search text as a new language', async () => {
    const user = userEvent.setup()
    const onSubmit = vi.fn((event: FormEvent<HTMLFormElement>) =>
      event.preventDefault(),
    )
    renderWithLocale(
      <form onSubmit={onSubmit}>
        <Harness initial={{ 'en-US': 'Name' }} />
      </form>,
    )
    await user.click(screen.getByRole('button', { name: 'Add translation' }))
    const search = screen.getByRole('combobox', { name: 'Choose language' })
    await user.type(search, 'en-US')
    expect(screen.queryByRole('option', { name: /en-US/ })).toBeNull()
    await user.clear(search)
    await user.type(search, 'not-a-language{Enter}')
    expect(draft()).toEqual({ 'en-US': 'Name' })
    expect(onSubmit).not.toHaveBeenCalled()
    await user.clear(search)
    await user.type(search, 'ja-JP{ArrowDown}{Enter}')
    expect(draft()).toEqual({ 'en-US': 'Name', 'ja-JP': '' })
    expect(translationInput().name).toBe('names.ja-JP')
    expect(onSubmit).not.toHaveBeenCalled()
    expect(screen.queryByLabelText('Language tag')).toBeNull()
  })
})
