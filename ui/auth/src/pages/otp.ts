import '../lib.ts'

document.addEventListener('DOMContentLoaded', () => {
  const otpForm = document.getElementById('otp-form') as HTMLFormElement | null;
  const otpInput = document.getElementById('otp-input') as HTMLInputElement | null;
  const otpError = document.getElementById('otp-error') as HTMLElement | null;
  const otpErrorText = document.getElementById('otp-error-text') as HTMLElement | null;
  const submitBtn = document.getElementById('submit-btn') as HTMLButtonElement | null;
  const submitBtnText = document.getElementById('submit-btn-text') as HTMLElement | null;

  if (otpForm && otpInput && otpError && otpErrorText && submitBtn) {
    otpForm.addEventListener('submit', (e) => {
      const value = otpInput.value.trim();
      
      // Reset errors
      otpInput.classList.remove('error');
      otpError.classList.remove('visible');

      if (!value || value.length < 6) {
        e.preventDefault();
        const errorMsg = otpInput.getAttribute('data-error-required') || 'Please enter the 6-digit code';
        otpErrorText.textContent = errorMsg;
        otpError.classList.add('visible');
        otpInput.classList.add('error');
        otpInput.focus();
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
    otpInput.addEventListener('input', () => {
      otpInput.classList.remove('error');
      otpError.classList.remove('visible');
    });

    // Handle numeric input only
    otpInput.addEventListener('keypress', (e) => {
      if (!/[0-9]/.test(e.key)) {
        e.preventDefault();
      }
    });
  }
});
