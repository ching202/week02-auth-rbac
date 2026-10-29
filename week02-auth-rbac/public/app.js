const $ = (id) => document.getElementById(id);
let mode = 'login';
let csrfToken = null;
let currentUser = null;

function feedback(message, bad = false) {
  $('auth-message').textContent = message;
  $('auth-message').classList.toggle('error', bad);
}

function setMode(next) {
  mode = next;
  $('login-tab').setAttribute('aria-pressed', String(mode === 'login'));
  $('register-tab').setAttribute('aria-pressed', String(mode === 'register'));
  $('submit-auth').textContent = mode === 'login' ? 'Sign in ↗' : 'Create account ↗';
  $('password').autocomplete = mode === 'login' ? 'current-password' : 'new-password';
  feedback('');
}

function renderIdentity(user) {
  currentUser = user;
  $('auth-area').hidden = Boolean(user);
  $('signed-in-area').hidden = !user;
  $('session-status').textContent = user ? `${user.username} · ${user.role}` : 'Signed out';
  $('session-detail').textContent = user ? '30-minute server session' : 'Public access is available';
  $('identity-title').textContent = user ? "You're through." : 'Start with you.';
  $('identity-description').textContent = user ? 'Your identity has been verified.' : 'Create an account or pick up where you left off.';
  if (user) {
    $('account-name').textContent = user.username;
    $('account-role').textContent = user.role;
    $('avatar').textContent = user.username[0].toUpperCase();
  }
}

function clearEvidence() {
  $('response-result').hidden = true;
  $('response-empty').hidden = false;
  $('response-body').textContent = '';
  $('directory').hidden = true;
  $('directory-rows').replaceChildren();
}

function showResponse(path, method, status, body) {
  $('response-empty').hidden = true;
  $('response-result').hidden = false;
  $('response-endpoint').textContent = `${method} ${path}`;
  const labels = { 200: 'OK', 201: 'Created', 400: 'Bad Request', 401: 'Unauthorized', 403: 'Forbidden', 409: 'Conflict', 429: 'Too Many Requests' };
  $('response-status').textContent = `${status} ${labels[status] || 'Response'}`;
  $('response-status').dataset.kind = status < 300 ? 'success' : status === 401 ? 'warning' : 'error';
  $('response-body').textContent = JSON.stringify(body, null, 2);
  $('request-announcement').textContent = `${method} ${path} returned HTTP ${status}. ${body.error || body.message || ''}`;
  $('directory').hidden = true;
  $('directory-rows').replaceChildren();
  if (status === 200 && path === '/api/admin/users') {
    $('directory').hidden = false;
    for (const user of body.users) {
      const tr = document.createElement('tr');
      for (const value of [user.username, user.role, new Date(user.createdAt).toLocaleDateString()]) {
        const td = document.createElement('td');
        td.textContent = value;
        tr.append(td);
      }
      $('directory-rows').append(tr);
    }
    $('directory-total').textContent = `Showing ${body.users.length} of ${body.total} accounts. Password hashes are never included.`;
  }
}

async function request(path, { method = 'GET', body, inspect = true } = {}) {
  const options = { method, credentials: 'same-origin', headers: { Accept: 'application/json' } };
  if (method === 'POST') {
    options.headers['Content-Type'] = 'application/json';
    options.headers['X-CSRF-Token'] = csrfToken || '';
    options.body = JSON.stringify(body || {});
  }
  const response = await fetch(path, options);
  const data = await response.json();
  if (inspect) showResponse(path, method, response.status, data);
  return { ok: response.ok, status: response.status, data };
}

async function refreshSession() {
  const result = await request('/api/session', { inspect: false });
  if (!result.ok) throw new Error(result.data.error || 'Unable to load your session.');
  csrfToken = result.data.csrfToken;
  renderIdentity(result.data.user);
}

async function safely(button, action) {
  if (button) button.disabled = true;
  try { await action(); }
  catch (error) { feedback(error.message || 'Could not reach the server. Please try again.', true); }
  finally { if (button) button.disabled = false; }
}

$('login-tab').addEventListener('click', () => setMode('login'));
$('register-tab').addEventListener('click', () => setMode('register'));
$('toggle-password').addEventListener('click', () => {
  const show = $('password').type === 'password';
  $('password').type = show ? 'text' : 'password';
  $('toggle-password').textContent = show ? 'Hide' : 'Show';
  $('toggle-password').setAttribute('aria-pressed', String(show));
});

$('auth-form').addEventListener('submit', (event) => {
  event.preventDefault();
  const action = mode;
  safely($('submit-auth'), async () => {
    if (!csrfToken) await refreshSession();
    const result = await request(`/api/${action}`, { method: 'POST', body: { username: $('username').value, password: $('password').value } });
    if (!result.ok) {
      feedback(result.data.error, true);
      if (result.status === 403) await refreshSession();
      return;
    }
    $('password').value = '';
    if (action === 'register') {
      setMode('login');
      $('password').focus();
    } else {
      csrfToken = result.data.csrfToken;
      renderIdentity(result.data.user);
    }
    feedback(result.data.message);
  });
});

$('logout').addEventListener('click', () => safely($('logout'), async () => {
  const result = await request('/api/logout', { method: 'POST' });
  if (result.ok || result.status === 401) {
    csrfToken = null;
    renderIdentity(null);
    clearEvidence();
    showResponse('/api/logout', 'POST', result.status, result.data);
    await refreshSession();
    feedback(result.ok ? result.data.message : 'Your session has expired. Sign in again.');
  } else feedback(result.data.error, true);
}));

for (const button of document.querySelectorAll('[data-endpoint]')) {
  button.addEventListener('click', () => safely(button, async () => {
    const result = await request(button.dataset.endpoint);
    if (result.status === 401 && currentUser) {
      await refreshSession();
      feedback('Your session has expired. Sign in again.', true);
    }
  }));
}

safely(null, refreshSession);
