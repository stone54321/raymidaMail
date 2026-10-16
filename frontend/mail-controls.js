// Folder navigation and account controls shared by the current and Linux UI.
for (const folder of ['inbox', 'sent']) {
  document.getElementById(`folder-${folder}`).onclick = () => {
    currentFolder = folder;
    document.getElementById('search-input').value = '';
    for (const value of ['inbox', 'sent']) document.getElementById(`folder-${value}`).setAttribute('aria-pressed', String(value === folder));
    loadEmailList();
  };
}
const passwordDialog = document.getElementById('password-dialog');
const passwordForm = document.getElementById('password-form');
document.getElementById('password-open').onclick = () => {
  passwordForm.reset();
  document.getElementById('password-error').textContent = '';
  passwordDialog.showModal();
};
document.getElementById('password-cancel').onclick = () => passwordDialog.close();
passwordDialog.addEventListener('close', () => passwordForm.reset());
passwordForm.onsubmit = async event => {
  event.preventDefault();
  const button = document.getElementById('password-save');
  const error = document.getElementById('password-error');
  const next = document.getElementById('password-new').value;
  if (next !== document.getElementById('password-confirm').value) {
    error.textContent = 'Новые пароли не совпадают.';
    return;
  }
  button.disabled = true;
  try {
    await api('/api/password', {old_password: document.getElementById('password-old').value, new_password: next});
    passwordDialog.close();
    document.getElementById('account-status').textContent = 'Пароль изменён. Остальные сеансы завершены.';
  } catch (failure) {
    error.textContent = failure.message || 'Не удалось изменить пароль.';
  } finally {
    button.disabled = false;
  }
};
document.getElementById('logout').onclick = async () => {
  try { await api('/api/logout', {}); } finally {
    passwordDialog.close();
    document.getElementById('auth-pass').value = '';
    showLogin();
  }
};
document.getElementById('reply-form').addEventListener('input', () => { pendingSendId = null; });
