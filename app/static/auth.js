async function authApiFetch(url, options = {}) {
  const response = await fetch(url, {
    credentials: 'include',
    ...options,
    headers: {
      Accept: 'application/json',
      ...(options.headers || {}),
    },
  });

  if (response.status === 401) {
    window.location.href = '/login';
    throw new Error('Authentication required');
  }

  return response;
}

async function ensureAuthenticated() {
  try {
    const response = await authApiFetch('/me');
    if (!response.ok) {
      throw new Error('Not authenticated');
    }
    const payload = await response.json();
    return payload.user || null;
  } catch (error) {
    window.location.href = '/login';
    return null;
  }
}

async function logoutCurrentUser() {
  try {
    await fetch('/logout', {
      method: 'POST',
      credentials: 'include',
      headers: { Accept: 'application/json' },
    });
  } finally {
    window.location.href = '/login';
  }
}

function bindLogoutButton() {
  const button = document.getElementById('logoutBtn');
  if (!button) return;
  button.addEventListener('click', () => {
    logoutCurrentUser();
  });
}

window.authApiFetch = authApiFetch;
window.ensureAuthenticated = ensureAuthenticated;
window.bindLogoutButton = bindLogoutButton;
window.logoutCurrentUser = logoutCurrentUser;
