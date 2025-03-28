// Authentication Pages JavaScript
document.addEventListener('DOMContentLoaded', function() {
  // DOM Elements
  const authTabs = document.querySelectorAll('.auth-tab');
  const authForms = document.querySelectorAll('.auth-form');
  const loginForm = document.getElementById('login-form');
  const registerForm = document.getElementById('register-form');
  const togglePasswordButtons = document.querySelectorAll('.toggle-password');
  const passwordInput = document.getElementById('register-password');
  const confirmPasswordInput = document.getElementById('register-confirm');
  const strengthProgress = document.querySelector('.strength-progress');
  const strengthText = document.querySelector('.strength-text');
  const guestLoginBtn = document.getElementById('guest-login-btn');
  const notification = document.getElementById('notification');
  const notificationMessage = document.getElementById('notification-message');

  // Tab switching
  authTabs.forEach(tab => {
    tab.addEventListener('click', () => {
      // Remove active class from all tabs and forms
      authTabs.forEach(t => t.classList.remove('active'));
      authForms.forEach(f => f.classList.remove('active'));
      
      // Add active class to clicked tab and corresponding form
      tab.classList.add('active');
      const formId = tab.dataset.tab;
      document.getElementById(formId).classList.add('active');
    });
  });

  // Toggle password visibility
  togglePasswordButtons.forEach(button => {
    button.addEventListener('click', () => {
      const input = button.previousElementSibling;
      const icon = button.querySelector('i');
      
      if (input.type === 'password') {
        input.type = 'text';
        icon.classList.remove('fa-eye');
        icon.classList.add('fa-eye-slash');
      } else {
        input.type = 'password';
        icon.classList.remove('fa-eye-slash');
        icon.classList.add('fa-eye');
      }
    });
  });

  // Password strength meter
  if (passwordInput) {
    passwordInput.addEventListener('input', checkPasswordStrength);
  }

  function checkPasswordStrength() {
    const password = passwordInput.value;
    let strength = 0;
    
    // Length check
    if (password.length >= 8) {
      strength += 1;
    }
    
    // Lowercase and uppercase check
    if (password.match(/[a-z]/) && password.match(/[A-Z]/)) {
      strength += 1;
    }
    
    // Number check
    if (password.match(/\d/)) {
      strength += 1;
    }
    
    // Special character check
    if (password.match(/[^a-zA-Z\d]/)) {
      strength += 1;
    }
    
    // Update strength indicator
    strengthProgress.className = 'strength-progress';
    
    if (strength === 0) {
      strengthProgress.style.width = '0%';
      strengthText.textContent = 'Password strength';
    } else if (strength === 1) {
      strengthProgress.classList.add('weak');
      strengthText.textContent = 'Weak';
    } else if (strength === 2) {
      strengthProgress.classList.add('medium');
      strengthText.textContent = 'Medium';
    } else if (strength === 3) {
      strengthProgress.classList.add('strong');
      strengthText.textContent = 'Strong';
    } else {
      strengthProgress.classList.add('very-strong');
      strengthText.textContent = 'Very Strong';
    }
  }

  // Form Submissions
  if (loginForm) {
    loginForm.addEventListener('submit', handleLogin);
  }

  if (registerForm) {
    registerForm.addEventListener('submit', handleRegister);
  }

  async function handleLogin(e) {
    e.preventDefault();
    
    const email = document.getElementById('login-email').value;
    const password = document.getElementById('login-password').value;
    
    try {
      const response = await fetch('/api/auth/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ email, password })
      });
      
      const data = await response.json();
      
      if (!response.ok) {
        throw new Error(data.error || 'Login failed');
      }
      
      // Store token in localStorage
      localStorage.setItem('authToken', data.token);
      localStorage.setItem('user', JSON.stringify(data.user));
      
      showNotification('Login successful! Redirecting...', 'success');
      
      // Redirect to main app after 1 second
      setTimeout(() => {
        window.location.href = '/index.html';
      }, 1000);
    } catch (error) {
      showNotification(error.message, 'error');
    }
  }

  async function handleRegister(e) {
    e.preventDefault();
    
    const username = document.getElementById('register-username').value;
    const email = document.getElementById('register-email').value;
    const password = document.getElementById('register-password').value;
    const confirmPassword = document.getElementById('register-confirm').value;
    const termsAgreed = document.getElementById('terms-agree').checked;
    
    // Validation
    if (password !== confirmPassword) {
      showNotification('Passwords do not match', 'error');
      return;
    }
    
    if (!termsAgreed) {
      showNotification('You must agree to the Terms of Service and Privacy Policy', 'error');
      return;
    }
    
    try {
      const response = await fetch('/api/auth/register', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ username, email, password })
      });
      
      const data = await response.json();
      
      if (!response.ok) {
        throw new Error(data.error || 'Registration failed');
      }
      
      // Store token in localStorage
      localStorage.setItem('authToken', data.token);
      localStorage.setItem('user', JSON.stringify(data.user));
      
      showNotification('Account created successfully! Redirecting...', 'success');
      
      // Redirect to main app after 1 second
      setTimeout(() => {
        window.location.href = '/index.html';
      }, 1000);
    } catch (error) {
      showNotification(error.message, 'error');
    }
  }

  // Guest login
  if (guestLoginBtn) {
    guestLoginBtn.addEventListener('click', () => {
      // Clear any stored authentication
      localStorage.removeItem('authToken');
      localStorage.removeItem('user');
      
      // Redirect to main app
      window.location.href = '/index.html';
    });
  }

  // Show notification
  function showNotification(message, type = 'success') {
    notificationMessage.textContent = message;
    
    // Update icon
    const iconElement = notification.querySelector('.notification-icon');
    if (iconElement) {
      iconElement.className = 'notification-icon ' + type;
      
      if (type === 'success') {
        iconElement.innerHTML = '<i class="fas fa-check-circle"></i>';
      } else {
        iconElement.innerHTML = '<i class="fas fa-exclamation-circle"></i>';
      }
    }
    
    // Show notification
    notification.classList.add('show');
    
    // Hide after 3 seconds
    setTimeout(() => {
      notification.classList.remove('show');
    }, 3000);
  }

  // Check if user is already logged in
  function checkAuthStatus() {
    const token = localStorage.getItem('authToken');
    
    if (token) {
      // Redirect to main app if already logged in
      window.location.href = '/index.html';
    }
  }

  // Check auth status on page load
  checkAuthStatus();
});
