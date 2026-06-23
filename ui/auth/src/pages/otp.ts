import { enhanceFieldForm } from '../lib.ts'

document.addEventListener('DOMContentLoaded', () => {
  const otpInput = document.getElementById('otp-input') as HTMLInputElement | null

  enhanceFieldForm({
    formId: 'otp-form',
    inputId: 'otp-input',
    errorBoxId: 'otp-error',
    errorTextId: 'otp-error-text',
    submitBtnId: 'submit-btn',
    submitLabelId: 'submit-btn-text',
    validate: (value, input) =>
      value.length >= 6
        ? null
        : input.getAttribute('data-error-required') || 'Please enter the 6-digit code',
  })

  otpInput?.addEventListener('keypress', (e) => {
    if (!/[0-9]/.test(e.key)) e.preventDefault()
  })
})
