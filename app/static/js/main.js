/**
 * SecureWeb - Client-side Security & UX Controller
 * Implements real-time password complexity evaluation, toggle visibility,
 * and accessible confirmation dialogs.
 */

document.addEventListener("DOMContentLoaded", () => {
  initPasswordStrengthMeter();
  initPasswordToggles();
  initAutoDismissAlerts();
  initActionConfirmations();
});

/**
 * Real-time password complexity calculation & checklist feedback.
 */
function initPasswordStrengthMeter() {
  const passwordInput = document.getElementById("password") || document.getElementById("new_password");
  const meterBar = document.getElementById("passwordMeterBar");
  
  if (!passwordInput || !meterBar) return;

  const reqLength = document.getElementById("reqLength");
  const reqUpper = document.getElementById("reqUpper");
  const reqLower = document.getElementById("reqLower");
  const reqNumber = document.getElementById("reqNumber");
  const reqSpecial = document.getElementById("reqSpecial");

  passwordInput.addEventListener("input", () => {
    const val = passwordInput.value;
    let score = 0;

    // Check conditions
    const hasLength = val.length >= 8;
    const hasUpper = /[A-Z]/.test(val);
    const hasLower = /[a-z]/.test(val);
    const hasNumber = /[0-9]/.test(val);
    const hasSpecial = /[!@#$%^&*()_\-+=\[\]{}|:;"'<>,.?/~`]/.test(val);

    if (hasLength) score++;
    if (hasUpper) score++;
    if (hasLower) score++;
    if (hasNumber) score++;
    if (hasSpecial) score++;

    // Update checklist icons if elements exist
    updateChecklistItem(reqLength, hasLength);
    updateChecklistItem(reqUpper, hasUpper);
    updateChecklistItem(reqLower, hasLower);
    updateChecklistItem(reqNumber, hasNumber);
    updateChecklistItem(reqSpecial, hasSpecial);

    // Update strength meter bar
    meterBar.className = "password-meter-bar";
    if (val.length === 0) {
      meterBar.style.width = "0%";
    } else {
      meterBar.classList.add(`strength-${score}`);
    }
  });
}

function updateChecklistItem(el, isValid) {
  if (!el) return;
  const icon = el.querySelector("i");
  if (isValid) {
    el.classList.add("valid");
    if (icon) {
      icon.className = "bi bi-check-circle-fill";
    }
  } else {
    el.classList.remove("valid");
    if (icon) {
      icon.className = "bi bi-circle";
    }
  }
}

/**
 * Toggle password field visibility securely.
 */
function initPasswordToggles() {
  const toggleButtons = document.querySelectorAll(".toggle-password-btn");
  toggleButtons.forEach(btn => {
    btn.addEventListener("click", () => {
      const targetId = btn.getAttribute("data-target");
      const targetInput = document.getElementById(targetId);
      const icon = btn.querySelector("i");
      
      if (!targetInput) return;

      if (targetInput.type === "password") {
        targetInput.type = "text";
        if (icon) {
          icon.className = "bi bi-eye-slash";
        }
      } else {
        targetInput.type = "password";
        if (icon) {
          icon.className = "bi bi-eye";
        }
      }
    });
  });
}

/**
 * Auto-dismiss non-critical flash messages after delay.
 */
function initAutoDismissAlerts() {
  const alerts = document.querySelectorAll(".alert-auto-dismiss");
  alerts.forEach(alert => {
    setTimeout(() => {
      alert.style.transition = "opacity 0.6s ease, transform 0.6s ease";
      alert.style.opacity = "0";
      alert.style.transform = "translateY(-10px)";
      setTimeout(() => alert.remove(), 600);
    }, 6000);
  });
}

/**
 * Wire confirmation modal triggers for destructive administrative actions.
 */
function initActionConfirmations() {
  const confirmForms = document.querySelectorAll("form.action-confirm");
  confirmForms.forEach(form => {
    form.addEventListener("submit", (e) => {
      const actionName = form.getAttribute("data-action-name") || "perform this action";
      const confirmed = window.confirm(`Security Confirmation: Are you sure you wish to ${actionName}?`);
      if (!confirmed) {
        e.preventDefault();
      }
    });
  });
}
