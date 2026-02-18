document.addEventListener('DOMContentLoaded', () => {
  const authForm = document.getElementById('authForm');
  const submitBtn = document.getElementById('submitBtn');
  const toggleAuthLink = document.getElementById('toggleAuthLink');
  const displayNameGroup = document.getElementById('displayNameGroup');
  const authTitle = document.getElementById('authTitle');
  const toggleText = document.getElementById('toggleText');
  const errorMessage = document.getElementById('errorMessage');
  let isLogin = true;

  // Check for existing token and redirect if valid
  const token = localStorage.getItem('fun-chat-token');
  if (token) {
    window.location.href = '/';
  }

  function toggleAuthMode() {
    isLogin = !isLogin;
    authTitle.textContent = isLogin ? 'Login' : 'Register';
    submitBtn.textContent = isLogin ? 'Login' : 'Create Account';
    toggleText.textContent = isLogin ? 'Need an account?' : 'Already have an account?';
    toggleAuthLink.textContent = isLogin ? 'Register here' : 'Login here';
    displayNameGroup.style.display = isLogin ? 'none' : 'block';
    errorMessage.textContent = '';
    authForm.reset();
  }

  toggleAuthLink.addEventListener('click', (e) => {
    e.preventDefault();
    toggleAuthMode();
  });

  authForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    errorMessage.textContent = '';
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;
    const endpoint = isLogin ? '/login' : '/register';
    
    const body = { email, password };
    if (!isLogin) {
      body.displayName = document.getElementById('displayName').value;
    }

    try {
      const res = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });

      const data = await res.json();

      if (res.ok && data.ok) {
        // Store token and user info
        localStorage.setItem('fun-chat-token', data.token);
        localStorage.setItem('fun-chat-email', data.email);
        localStorage.setItem('fun-chat-displayName', data.displayName);
        localStorage.setItem('fun-chat-isAdmin', data.isAdmin);
        localStorage.setItem('fun-chat-userId', data.id);
        
        // Redirect to chat page
        window.location.href = '/';
      } else {
        errorMessage.textContent = data.error || 'Something went wrong.';
      }
    } catch (err) {
      errorMessage.textContent = 'Network error. Please try again.';
    }
  });
});
