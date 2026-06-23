import { enhanceFieldForm, enhancePasswordToggle } from '../lib.ts'

document.addEventListener('DOMContentLoaded', () => {
  enhanceFieldForm({
    formId: 'password-form',
    inputId: 'password-input',
    errorBoxId: 'password-error',
    errorTextId: 'password-error-text',
    submitBtnId: 'submit-btn',
    submitLabelId: 'submit-btn-text',
  })

  enhancePasswordToggle('password-input', 'toggle-password')
})
