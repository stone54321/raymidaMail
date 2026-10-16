const $ = (id) => document.getElementById(id);
let currentMailbox = 'ray', openedEmailId = null, currentFolder = 'inbox', pendingSendId = null;

async function api(path, body) {
  const response = await fetch(path, body
  ? { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Raymida-Send-ID': pendingSendId || '' }, body: JSON.stringify(body) }
  : {});

  if (response.status === 403 && path !== '/api/login') {
    showLogin();
    throw new Error('session expired');
  }

  let data = {};
  try {
    data = await response.json();
  } catch (err) {
    data = {};
  }

  if (!response.ok && path !== '/api/login') {
    throw new Error(data.error || `server error ${response.status}`);
  }
  return data;
}

function showLogin() {
  $('login-screen').classList.remove('hidden');
  $('main-screen').classList.add('hidden');
  anime({ targets: '#login-form', opacity: [0, 1], translateY: [30, 0], easing: 'easeOutExpo', duration: 800 });
}

function showMail() {
  anime({
    targets: '#login-screen', opacity: 0, translateY: -20, duration: 400, easing: 'easeInQuad',
    complete: () => {
      $('login-screen').classList.add('hidden');
      $('main-screen').classList.remove('hidden');
      anime({ targets: ['header', '#email-list'], opacity: [0, 1], translateY: [15, 0], delay: anime.stagger(100), easing: 'easeOutExpo', duration: 600 });
    }
  });
}

$('login-form').onsubmit = async (e) => {
  e.preventDefault();
  const user = $('auth-user').value.trim().toLowerCase();
  const pass = $('auth-pass').value;
  $('login-error').textContent = 'checking...';

  try {
    const response = await api('/api/login', { username: user, password: pass });
    if (response.ok) {
      $('login-error').textContent = '';
      currentMailbox = response.username; // Устанавливаем текущий ящик равным имени пользователя
      showMail();
      startApp();
    } else {
      $('login-error').textContent = response.error || 'access denied';
      anime({ targets: '#login-form', translateX: [-5, 5, -5, 5, 0], duration: 400 });
    }
  } catch (err) {
    $('login-error').textContent = 'Network error.';
  }
};

$('back-btn').onclick = (e) => {
  e.preventDefault();
  openedEmailId = null;
  anime({
    targets: '#email-view > *', opacity: 0, translateX: 20, duration: 300, easing: 'easeInQuad',
    complete: () => {
      $('email-view').classList.add('hidden');
      $('email-list').classList.remove('hidden');
      loadEmailList();
      anime({ targets: '#email-list', opacity: [0, 1], translateX: [-20, 0], easing: 'easeOutExpo', duration: 400 });
    }
  });
};

const dropZone = $('drop-zone');
const fileInput = $('file-input');
const attachmentsPreview = $('attachments-preview');
let pendingAttachments = [];

dropZone.addEventListener('click', () => fileInput.click());

dropZone.addEventListener('dragover', (e) => {
  e.preventDefault();
  dropZone.classList.add('dragover');
});

dropZone.addEventListener('dragleave', () => {
  dropZone.classList.remove('dragover');
});

dropZone.addEventListener('drop', (e) => {
  e.preventDefault();
  dropZone.classList.remove('dragover');
  handleFiles(e.dataTransfer.files);
});

fileInput.addEventListener('change', (e) => {
  handleFiles(e.target.files);
});

function handleFiles(files) {
  pendingSendId = null;
  for (const file of files) {
    const reader = new FileReader();
    reader.onload = (e) => {
      pendingAttachments.push({
        filename: file.name,
        content: e.target.result.split(',')[1]
      });
      renderAttachments();
    };
    reader.readAsDataURL(file);
  }
}

function renderAttachments() {
  attachmentsPreview.innerHTML = pendingAttachments.map((att, idx) => `
  <div class="attachment-preview-item">
  <span>📎 ${escapeHtml(att.filename)}</span>
  <button type="button" class="attachment-remove-btn" onclick="removeAttachment(${idx})">✕</button>
  </div>
  `).join('');
}

window.removeAttachment = (idx) => {
  pendingSendId = null;
  pendingAttachments.splice(idx, 1);
  renderAttachments();
};

$('reply-form').onsubmit = async (e) => {
  e.preventDefault();
  const btn = e.target.querySelector('button[type="submit"]');
  if (btn.disabled) return;
  btn.disabled = true;
  pendingSendId ||= crypto.randomUUID();
  const originalText = btn.textContent;
  btn.textContent = 'sending…';
  $('reply-error').textContent = '';

  try {
    if (pendingAttachments.length > 0) {
      const formData = new FormData();
      formData.append('id', openedEmailId);
      formData.append('subject', $('reply-subject').value);
      formData.append('text', $('reply-text').value);

      pendingAttachments.forEach(att => {
        const blob = base64ToBlob(att.content, 'application/octet-stream');
        formData.append('attachments', blob, att.filename);
      });

      const response = await fetch('/api/send', {
        method: 'POST',
        headers: { 'X-Raymida-Send-ID': pendingSendId },
        body: formData
      });

      let data = {};
      try {
        data = await response.json();
      } catch (jsonErr) {
        data = {};
      }

      if (response.ok && data.ok) {
        $('reply-text').value = '';
        pendingSendId = null;
        pendingAttachments = [];
        renderAttachments();
        $('reply-error').textContent = 'sent with attachments';
        $('reply-error').style.color = '#8f8';
        setTimeout(() => { $('reply-error').textContent = ''; }, 2000);
      } else {
        $('reply-error').style.color = '';
        $('reply-error').textContent = 'failed: ' + (data.error || `error ${response.status}`);
      }
    } else {
      // Обычная отправка без вложений
      const response = await fetch('/api/send', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Raymida-Send-ID': pendingSendId || '' },
        body: JSON.stringify({
          id: openedEmailId,
          subject: $('reply-subject').value,
          text: $('reply-text').value
        })
      });

      let data = {};
      try {
        data = await response.json();
      } catch (jsonErr) {
        data = {};
      }

      if (response.ok && data.ok) {
        $('reply-text').value = '';
        pendingSendId = null;
        $('reply-error').textContent = 'sent';
        $('reply-error').style.color = '#8f8';
        setTimeout(() => { $('reply-error').textContent = ''; }, 2000);
      } else {
        $('reply-error').style.color = '';
        $('reply-error').textContent = 'failed: ' + (data.error || `error ${response.status}`);
      }
    }
  } catch (err) {
    $('reply-error').style.color = '';
    $('reply-error').textContent = 'failed: ' + (err.message || 'Network error while sending');
  } finally {
    btn.textContent = originalText;
    btn.disabled = false;
  }
};

// Helper: base64 to Blob
function base64ToBlob(base64, mimeType) {
  const byteCharacters = atob(base64);
  const byteNumbers = new Array(byteCharacters.length);
  for (let i = 0; i < byteCharacters.length; i++) {
    byteNumbers[i] = byteCharacters.charCodeAt(i);
  }
  const byteArray = new Uint8Array(byteNumbers);
  return new Blob([byteArray], { type: mimeType });
}

async function startApp() {
  try {
    const boxes = await api('/api/boxes');
    currentMailbox = boxes[0] || currentMailbox;
    $('mailboxes-list').innerHTML = boxes.map(y =>
      `<a href="#" data-y="${encodeURIComponent(y)}" class="${y === currentMailbox ? 'active' : ''}">${escapeHtml(y)}</a>`
    ).join('');

    $('mailboxes-list').querySelectorAll('a').forEach(a => a.onclick = (e) => {
      e.preventDefault();
      currentMailbox = decodeURIComponent(a.dataset.y);
      anime({ targets: '#mailboxes-list a', opacity: [0.5, 1], duration: 300, delay: anime.stagger(50) });
      $('mailboxes-list').querySelectorAll('a').forEach(link => {
        link.classList.toggle('active', decodeURIComponent(link.dataset.y) === currentMailbox);
      });
      loadEmailList();
    });

    await loadEmailList();
  } catch (err) {
    console.error('Error loading mailboxes:', err);
  }
}

async function loadEmailList() {
  $('email-view').classList.add('hidden');
  $('email-list').classList.remove('hidden');
  $('email-list').style.opacity = '0';

  try {
    // 🔒 Больше не передаем ?y=, сервер сам знает, чей это ящик
    const emails = await api('/api/list?folder=' + currentFolder);

    $('email-list').innerHTML = emails.length ? emails.map(p => `
    <a class="email-item" href="#" data-id="${encodeURIComponent(p.id)}">
    <div class="card ${p.isNew ? 'new-email' : ''}">
    <div class="subject">${escapeHtml(p.subject)}</div>
    <div class="muted">${escapeHtml(currentFolder === 'sent' ? p.to : p.from)} · ${new Date(p.mtime * 1000).toLocaleString()} ${p.attachments?.length ? '📎' : ''}</div>
    </div>
    </a>`).join('') : '<div class="card">no emails</div>';

    $('email-list').querySelectorAll('a.email-item').forEach(a => a.onclick = (e) => {
      e.preventDefault();
      openEmail(decodeURIComponent(a.dataset.id));
    });

    animateEmailList();
    $('email-list').style.opacity = '1';
  } catch (err) {
    $('email-list').innerHTML = '<div class="card">load error</div>';
    $('email-list').style.opacity = '1';
  }
}

let searchTimeout = null;
$('search-input').addEventListener('input', (e) => {
  clearTimeout(searchTimeout);
  const query = e.target.value.trim();

  if (!query) {
    loadEmailList();
    return;
  }

  searchTimeout = setTimeout(async () => {
    try {
      const results = await api(`/api/search?q=${encodeURIComponent(query)}&folder=${currentFolder}`);

      $('email-list').innerHTML = results.length ? results.map(p => `
      <a class="email-item" href="#" data-id="${encodeURIComponent(p.id)}">
      <div class="card ${p.isNew ? 'new-email' : ''}">
      <div class="subject">${escapeHtml(p.subject)}</div>
      <div class="muted">${escapeHtml(currentFolder === 'sent' ? p.to : p.from)} · ${new Date(p.mtime * 1000).toLocaleString()}</div>
      </div>
      </a>`).join('') : '<div class="card">no results</div>';

      $('email-list').querySelectorAll('a.email-item').forEach(a => a.onclick = (e) => {
        e.preventDefault();
        openEmail(decodeURIComponent(a.dataset.id));
      });
    } catch (err) {
      console.error('Search error:', err);
    }
  }, 300); // Debounce 300ms
});

async function openEmail(id) {
  try {
    const p = await api(`/api/mail?id=${encodeURIComponent(id)}`);
    openedEmailId = id;
    pendingSendId = null;
    pendingAttachments = [];
    renderAttachments();
    $('reply-form').classList.toggle('hidden', p.folder === 'sent');

    const emailCard = document.querySelector(`a.email-item[data-id="${encodeURIComponent(id)}"] .card`);
    if (emailCard) {
      emailCard.classList.remove('new-email');
    }

    const setText = (elementId, text) => {
      const el = document.getElementById(elementId);
      if (el && text !== undefined && text !== null) el.textContent = text;
    };

    let formattedDate = '';
    try {
      const d = new Date(p.mtime * 1000);
      if (!isNaN(d.getTime())) {
        formattedDate = d.toLocaleString('ru-RU', { day: '2-digit', month: '2-digit', year: '2-digit', hour: '2-digit', minute: '2-digit' });
      }
    } catch (e) {}

    setText('email-subject', p.subject || '(no subject)');
    setText('email-from', `${p.folder === 'sent' ? 'To' : 'From'}: ${p.folder === 'sent' ? (p.to || 'unknown') : (p.from || 'unknown')} · ${formattedDate}`);

    const bodyEl = document.getElementById('email-body');
    if (bodyEl) {
      if (p.isHtml) {
        bodyEl.innerHTML = DOMPurify.sanitize(p.text || '', {
          USE_PROFILES: { html: true },
          ALLOWED_TAGS: ['p', 'br', 'b', 'i', 'em', 'strong', 'a', 'img', 'ul', 'ol', 'li', 'blockquote', 'pre', 'code', 'table', 'tr', 'td', 'th', 'thead', 'tbody', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'div', 'span', 'hr', 'sub', 'sup'],
          ALLOWED_ATTR: ['href', 'src', 'alt', 'title', 'class', 'style', 'width', 'height', 'target', 'rel'],
          FORBID_TAGS: ['script', 'iframe', 'object', 'embed', 'form', 'input', 'button', 'textarea', 'select'],
          FORBID_ATTR: ['onerror', 'onload', 'onclick', 'onmouseover', 'onfocus', 'onblur'],
          ADD_ATTR: ['target'],
        });

        bodyEl.querySelectorAll('a').forEach(a => {
          a.target = '_blank';
          a.rel = 'noopener noreferrer';
        });
      } else {
        bodyEl.textContent = p.text || '(empty)';
      }
    }

    const attachContainer = $('attachments-container');
    const attachList = $('attachments-list');
    attachList.innerHTML = '';
    if (p.attachments && p.attachments.length > 0) {
      attachContainer.classList.remove('hidden');
      p.attachments.forEach((att, idx) => {
        const link = document.createElement('a');
        link.href = `/api/attachment?id=${encodeURIComponent(id)}&idx=${idx}`;
        link.textContent = `📎 ${att.filename}`;
        link.className = 'attachment-link';
        link.style.color = '#4a9eff';
        link.style.textDecoration = 'none';
        link.style.fontSize = '14px';
        attachList.appendChild(link);
      });
    } else {
      attachContainer.classList.add('hidden');
    }

    const MAIL_DOMAIN = 'raymida.com'; // 🔧 Измени на свой домен
    setText('email-to', `Reply from ${currentMailbox}@${MAIL_DOMAIN} to ${p.replyTo || p.from || 'unknown'}`);
    const replySubject = $('reply-subject');
    if (replySubject) replySubject.value = /^re:/i.test(p.subject || '') ? p.subject : 'Re: ' + p.subject;
    const replyText = $('reply-text');
    if (replyText) replyText.value = '';
    setText('reply-error', '');

    showEmailView();
  } catch (err) {
    console.error('❌ Error opening email:', err);
  }
}

function escapeHtml(s) {
  return (s || '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function animateEmailList() {
  const newCards = document.querySelectorAll('#email-list .card:not(.is-animated)');
  if (newCards.length > 0) {
    anime({
      targets: newCards, opacity: [0, 1], translateY: [10, 0], easing: 'easeOutQuad', duration: 350, delay: anime.stagger(25, {start: 0}),
      complete: () => newCards.forEach(card => card.classList.add('is-animated'))
    });
  }
}

function showEmailView() {
  anime({
    targets: '#email-list', opacity: 0, translateX: -20, duration: 300, easing: 'easeInQuad',
    complete: () => {
      $('email-list').classList.add('hidden');
      $('email-view').classList.remove('hidden');
      anime({ targets: '#email-view > *', opacity: [0, 1], translateY: [15, 0], delay: anime.stagger(60), easing: 'easeOutExpo', duration: 500 });
    }
  });
}

document.addEventListener('mousedown', (e) => {
  if (e.target.tagName === 'BUTTON') {
    anime({ targets: e.target, scale: [1, 0.96, 1], duration: 300, easing: 'easeInOutQuad' });
  }
});

console.log('🚀 Starting app...');
api('/api/boxes')
.then(() => { console.log('✅ Auto-login successful'); showMail(); startApp(); })
.catch(() => { console.log('ℹ Auto-login failed, showing login form'); showLogin(); });
