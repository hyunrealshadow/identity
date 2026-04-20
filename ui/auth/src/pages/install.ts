import '../lib.ts'

document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('install-form') as HTMLFormElement | null
  const submitBtn = document.getElementById('install-submit-btn') as HTMLButtonElement | null
  const submitLabel = document.getElementById('install-submit-label') as HTMLElement | null
  const requiredError = form?.getAttribute('data-error-required') || 'Required field'
  const requiredFields = Array.from(
    document.querySelectorAll<HTMLInputElement | HTMLSelectElement>('[data-install-required="true"]'),
  )

  if (!form || !submitBtn) {
    return
  }

  form.addEventListener('submit', (event) => {
    let firstInvalidField: HTMLInputElement | HTMLSelectElement | null = null

    for (const field of requiredFields) {
      const isEmpty = field.value.trim() === ''
      field.classList.toggle('error', isEmpty)
      field.classList.toggle('error-static', false)

      if (isEmpty) {
        field.setAttribute('aria-invalid', 'true')
        field.setCustomValidity(requiredError)
      } else {
        field.removeAttribute('aria-invalid')
        field.setCustomValidity('')
      }

      if (isEmpty && !firstInvalidField) {
        firstInvalidField = field
      }
    }

    if (firstInvalidField) {
      event.preventDefault()
      firstInvalidField.reportValidity()
      firstInvalidField.focus()
      return
    }

    submitBtn.disabled = true
    if (submitLabel) {
      submitLabel.innerHTML = '<span class="loading loading-spinner loading-xs"></span>'
    }
  })

  for (const field of requiredFields) {
    const clearError = () => {
      if (field.value.trim() !== '') {
        field.classList.remove('error', 'error-static')
        field.removeAttribute('aria-invalid')
        field.setCustomValidity('')
      }
    }

    field.addEventListener('input', clearError)
    field.addEventListener('change', clearError)
  }
})
