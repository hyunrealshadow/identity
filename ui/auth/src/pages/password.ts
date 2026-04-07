import '../lib.ts'

document.addEventListener('DOMContentLoaded', () => {
  const passwordForm = document.getElementById('password-form') as HTMLFormElement | null;
  const passwordInput = document.getElementById('password-input') as HTMLInputElement | null;
  const passwordError = document.getElementById('password-error') as HTMLElement | null;
  const passwordErrorText = document.getElementById('password-error-text') as HTMLElement | null;
  const submitBtn = document.getElementById('submit-btn') as HTMLButtonElement | null;
  const submitBtnText = document.getElementById('submit-btn-text') as HTMLElement | null;

  if (passwordForm && passwordInput && passwordError && passwordErrorText && submitBtn) {
    passwordForm.addEventListener('submit', (e) => {
      const value = passwordInput.value.trim();
      
      // Reset errors
      passwordInput.classList.remove('error');
      passwordError.classList.remove('visible');

      if (!value) {
        e.preventDefault();
        const errorMsg = passwordInput.getAttribute('data-error-required') || 'Required field';
        passwordErrorText.textContent = errorMsg;
        passwordError.classList.add('visible');
        passwordInput.classList.add('error');
        passwordInput.focus();
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
    passwordInput.addEventListener('input', () => {
      passwordInput.classList.remove('error');
      passwordError.classList.remove('visible');
    });
  }
});
