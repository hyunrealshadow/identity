import '../lib.ts'

document.addEventListener('DOMContentLoaded', () => {
  const identifierForm = document.getElementById('identifier-form') as HTMLFormElement | null;
  const identifierInput = document.getElementById('identifier-input') as HTMLInputElement | null;
  const identifierError = document.getElementById('identifier-error') as HTMLElement | null;
  const identifierErrorText = document.getElementById('identifier-error-text') as HTMLElement | null;
  const submitBtn = document.getElementById('submit-btn') as HTMLButtonElement | null;
  const submitBtnText = document.getElementById('submit-btn-text') as HTMLElement | null;

  if (identifierForm && identifierInput && identifierError && identifierErrorText && submitBtn) {
    identifierForm.addEventListener('submit', (e) => {
      const value = identifierInput.value.trim();
      
      // Reset errors
      identifierInput.classList.remove('error', 'error-static');
      identifierError.classList.remove('visible');

      if (!value) {
        e.preventDefault();
        const errorMsg = identifierInput.getAttribute('data-error-required') || 'Required field';
        identifierErrorText.textContent = errorMsg;
        identifierError.classList.add('visible');
        identifierInput.classList.add('error');
        identifierInput.focus();
        return;
      }

      // Show loading state
      submitBtn.disabled = true;
      if (submitBtnText) {
        submitBtnText.innerHTML = '<span class="loading loading-spinner loading-xs"></span>';
      } else {
        submitBtn.innerHTML = '<span class="loading loading-spinner loading-xs"></span>';
      }
    });

    // Remove error class on input
    identifierInput.addEventListener('input', () => {
      identifierInput.classList.remove('error', 'error-static');
      identifierError.classList.remove('visible');
    });
  }
});
