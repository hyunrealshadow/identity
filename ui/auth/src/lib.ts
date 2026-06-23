import './style.css'

export const SPINNER_HTML = '<span class="loading loading-spinner loading-xs"></span>'

export interface FieldFormOptions {
  formId: string
  inputId: string
  errorBoxId: string
  errorTextId: string
  submitBtnId: string
  submitLabelId?: string
  /** Returns an error message when invalid, or null when valid. */
  validate?: (value: string, input: HTMLInputElement) => string | null
}

function requiredValidator(input: HTMLInputElement) {
  return (value: string): string | null =>
    value ? null : input.getAttribute('data-error-required') || 'Required field'
}

/** Progressively enhance a single-field auth form with validation + loading state. */
export function enhanceFieldForm(opts: FieldFormOptions): void {
  const form = document.getElementById(opts.formId) as HTMLFormElement | null
  const input = document.getElementById(opts.inputId) as HTMLInputElement | null
  const errorBox = document.getElementById(opts.errorBoxId) as HTMLElement | null
  const errorText = document.getElementById(opts.errorTextId) as HTMLElement | null
  const submitBtn = document.getElementById(opts.submitBtnId) as HTMLButtonElement | null
  const submitLabel = opts.submitLabelId
    ? (document.getElementById(opts.submitLabelId) as HTMLElement | null)
    : null

  if (!form || !input || !errorBox || !errorText || !submitBtn) return

  const validate = opts.validate ?? requiredValidator(input)

  const showError = (msg: string) => {
    errorText.textContent = msg
    errorBox.classList.add('visible')
    input.classList.add('error')
    input.focus()
  }

  const clearError = () => {
    input.classList.remove('error', 'error-static')
    errorBox.classList.remove('visible')
  }

  form.addEventListener('submit', (e) => {
    clearError()
    const error = validate(input.value.trim(), input)
    if (error) {
      e.preventDefault()
      showError(error)
      return
    }
    submitBtn.disabled = true
    ;(submitLabel ?? submitBtn).innerHTML = SPINNER_HTML
  })

  input.addEventListener('input', clearError)
}

/** Wire a button to toggle password visibility and swap its eye icon. */
export function enhancePasswordToggle(inputId: string, btnId: string): void {
  const input = document.getElementById(inputId) as HTMLInputElement | null
  const btn = document.getElementById(btnId) as HTMLButtonElement | null
  if (!input || !btn) return

  const eyeOpen = btn.innerHTML
  const eyeClosed =
    '<svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">' +
    '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24" />' +
    '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M1 1l22 22" />' +
    '</svg>'

  btn.addEventListener('click', () => {
    const willShow = input.type === 'password'
    input.type = willShow ? 'text' : 'password'
    btn.innerHTML = willShow ? eyeClosed : eyeOpen
  })
}

export interface AccountSwitcherOptions {
  useAnotherBtnId: string
  backBtnId: string
  accountPickerId: string
  identifierSectionId: string
  focusInputId: string
  pickerHeaderId: string
  signinHeaderId: string
}

/** Wire the "use another account" / "back" buttons to switch between the
 *  account picker and the identifier form. */
export function enhanceAccountSwitcher(opts: AccountSwitcherOptions): void {
  const useAnotherBtn = document.getElementById(opts.useAnotherBtnId)
  const backBtn = document.getElementById(opts.backBtnId)
  const accountPicker = document.getElementById(opts.accountPickerId)
  const identifierSection = document.getElementById(opts.identifierSectionId)
  const focusInput = document.getElementById(opts.focusInputId) as HTMLInputElement | null
  const pickerHeader = document.getElementById(opts.pickerHeaderId)
  const signinHeader = document.getElementById(opts.signinHeaderId)
  if (!accountPicker || !identifierSection) return

  const showIdentifier = () => {
    accountPicker.classList.add('auth-section-hidden')
    identifierSection.classList.remove('auth-section-hidden')
    pickerHeader?.classList.add('auth-section-hidden')
    signinHeader?.classList.remove('auth-section-hidden')
    focusInput?.focus()
  }

  const showPicker = () => {
    identifierSection.classList.add('auth-section-hidden')
    accountPicker.classList.remove('auth-section-hidden')
    signinHeader?.classList.add('auth-section-hidden')
    pickerHeader?.classList.remove('auth-section-hidden')
  }

  useAnotherBtn?.addEventListener('click', showIdentifier)
  backBtn?.addEventListener('click', showPicker)
}
