'use strict';
const $ = id => document.getElementById(id);
let csrf = '', version = '', busy = false;
function message(text = '', error = '') { $('status').textContent = text; $('error').textContent = error; }
function view(authenticated) {
  $('login').hidden = authenticated; $('profile').hidden = !authenticated;
  (authenticated ? $('profile-title') : $('login-title')).focus();
}
function showUser(user) {
  version = user.version;
  $('name').textContent = user.name; $('account').textContent = user.username;
  $('current-phone').textContent = user.phone || 'Not set'; $('phone').value = user.phone || '';
}
async function api(path, method = 'GET', body) {
  const response = await fetch(path, { method, credentials: 'same-origin', cache: 'no-store',
    headers: { Accept: 'application/json', ...(body ? {'Content-Type': 'application/json'} : {}),
      ...(method !== 'GET' ? {'X-CSRF-Token': csrf} : {}) },
    ...(body ? {body: JSON.stringify(body)} : {}) });
  const data = await response.json();
  if (data.csrfToken) csrf = data.csrfToken;
  if (!response.ok) {
    if (response.status === 401) { csrf = data.csrfToken || ''; $('password').value = ''; $('phone').value = ''; version = '';
      ['name', 'account', 'current-phone'].forEach(id => $(id).textContent = ''); view(false); }
    throw new Error(data.error || 'The request failed. Please try again.');
  }
  return data;
}
async function action(form, pending, work) {
  if (busy) return;
  busy = true; document.querySelectorAll('button').forEach(button => button.disabled = true);
  form.setAttribute('aria-busy', 'true'); message(pending);
  try { await work(); } catch (error) { message('', error.message || 'Unable to connect. Please try again.'); }
  finally { busy = false; form.removeAttribute('aria-busy'); document.querySelectorAll('button').forEach(button => button.disabled = false); }
}
$('login-form').addEventListener('submit', event => {
  event.preventDefault();
  action(event.currentTarget, 'Signing in…', async () => {
    try {
      const data = await api('/api/login', 'POST', {username: $('username').value.trim(), password: $('password').value});
      showUser(data.user); view(true); message('Signed in.');
    } finally { $('password').value = ''; }
  });
});
$('phone-form').addEventListener('submit', event => {
  event.preventDefault();
  const phone = $('phone').value.trim();
  if (!/^[+0-9(). -]{3,32}$/.test(phone) || (phone.match(/[0-9]/g) || []).length < 3) {
    message('', 'Enter a phone number with at least 3 digits using the allowed characters.'); $('phone').focus(); return;
  }
  action(event.currentTarget, 'Updating the directory…', async () => {
    const data = await api('/api/me/phone', 'PUT', {phone, version});
    showUser(data.user); message('Your phone number was updated in Active Directory.');
  });
});
$('logout').addEventListener('click', () => action($('profile'), 'Signing out…', async () => {
  await api('/api/logout', 'POST');
  ['name', 'account', 'current-phone'].forEach(id => $(id).textContent = ''); $('phone').value = '';
  view(false); message('Signed out.');
}));
action(document.querySelector('main'), 'Loading your session…', async () => {
  const data = await api('/api/me'); showUser(data.user); view(true); message();
});
