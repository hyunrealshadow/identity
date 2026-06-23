import { enhanceAccountSwitcher, enhanceFieldForm } from '../lib.ts'

document.addEventListener('DOMContentLoaded', () => {
  enhanceFieldForm({
    formId: 'identifier-form',
    inputId: 'identifier-input',
    errorBoxId: 'identifier-error',
    errorTextId: 'identifier-error-text',
    submitBtnId: 'submit-btn',
    submitLabelId: 'submit-btn-text',
  })

  enhanceAccountSwitcher({
    useAnotherBtnId: 'use-another-account-btn',
    backBtnId: 'back-to-accounts-btn',
    accountPickerId: 'account-picker',
    identifierSectionId: 'identifier-section',
    focusInputId: 'identifier-input',
    pickerHeaderId: 'picker-header',
    signinHeaderId: 'signin-header',
  })
})
