/**
 * admin-ui.js — Admin Panel DOM Controller
 * Depends on: crypto.js (window.ZTCrypto), admin.js (window.ZTAdmin)
 */
'use strict';

let _sessionTimerInterval = null;

document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('admin-key-input').addEventListener('change', handleKeyLoad);
  document.getElementById('refresh-queue-btn').addEventListener('click', loadQueue);
  document.getElementById('lock-btn').addEventListener('click', lockSession);
});

async function handleKeyLoad(e) {
  const file = e.target.files?.[0];
  if (!file) return;

  const statusEl = document.getElementById('unlock-status');
  statusEl.textContent = 'Decrypting...';

  const result = await ZTAdmin.unlockAdminSession(file);

  if (result.success) {
    statusEl.textContent = `Unlocked as: ${DOMPurify.sanitize(result.username, { ALLOWED_TAGS: [] })}`;
    setSessionUI(true);
    startSessionTimer();
    await loadQueue();
    toast('Admin session unlocked.', 'success');
  } else {
    statusEl.textContent = `Failed: ${result.error}`;
    toast(result.error, 'error');
  }

  e.target.value = '';
}

function setSessionUI(unlocked) {
  const badge     = document.getElementById('session-badge');
  const modPanel  = document.getElementById('mod-panel');
  const dangerPan = document.getElementById('danger-panel');
  const timerEl   = document.getElementById('session-timer');

  badge.textContent = unlocked ? 'SESSION ACTIVE' : 'SESSION LOCKED';
  badge.classList.toggle('active', unlocked);
  modPanel.style.display  = unlocked ? 'block' : 'none';
  dangerPan.style.display = unlocked ? 'block' : 'none';
  timerEl.style.display   = unlocked ? 'block' : 'none';
}

function startSessionTimer() {
  clearInterval(_sessionTimerInterval);
  const start = Date.now();
  const TIMEOUT = 30 * 60 * 1000;

  _sessionTimerInterval = setInterval(() => {
    const elapsed   = Date.now() - start;
    const remaining = Math.max(0, TIMEOUT - elapsed);
    const mins      = Math.floor(remaining / 60000);
    const secs      = Math.floor((remaining % 60000) / 1000);

    document.getElementById('session-timer').textContent =
      `Session auto-locks in: ${mins}:${secs.toString().padStart(2,'0')}`;

    if (remaining === 0) {
      clearInterval(_sessionTimerInterval);
      lockSession();
    }
  }, 1000);
}

function lockSession() {
  clearInterval(_sessionTimerInterval);
  ZTAdmin.lockAdminSession();
  setSessionUI(false);
  document.getElementById('queue-list').innerHTML =
    '<div class="empty-state">Session locked.</div>';
  document.getElementById('unlock-status').textContent = 'No key loaded';
  toast('Session locked.', 'warning');
}

async function loadQueue() {
  if (!ZTAdmin.isAdminUnlocked()) {
    toast('Session is locked.', 'error');
    return;
  }

  const queueList = document.getElementById('queue-list');
  queueList.innerHTML = '<div class="empty-state">Fetching queue...</div>';

  try {
    const issues = await ZTAdmin.fetchPendingComments('comment-queue');

    if (issues.length === 0) {
      queueList.innerHTML = '<div class="empty-state">Queue is empty. No pending comments.</div>';
      return;
    }

    queueList.innerHTML = '';

    for (const issue of issues) {
      const itemEl = buildQueueItemSkeleton(issue);
      queueList.appendChild(itemEl);

      // Decrypt asynchronously and update the card
      ZTAdmin.decryptAndVerifyComment(issue).then(result => {
        updateQueueItem(itemEl, result, issue.number);
      }).catch(err => {
        markQueueItemError(itemEl, err.message);
      });
    }

  } catch (err) {
    queueList.innerHTML = `<div class="empty-state">Error: ${err.message}</div>`;
    toast(`Queue load failed: ${err.message}`, 'error');
  }
}

function buildQueueItemSkeleton(issue) {
  const el = document.createElement('div');
  el.className    = 'queue-item';
  el.dataset.issue = issue.number;

  const meta = document.createElement('div');
  meta.className = 'queue-item-meta';

  const sender = document.createElement('span');
  sender.className   = 'queue-sender';
  sender.textContent = DOMPurify.sanitize(`#${issue.number}`, { ALLOWED_TAGS: [] });

  const status = document.createElement('span');
  status.className   = 'queue-status pending';
  status.textContent = 'decrypting...';

  meta.appendChild(sender);
  meta.appendChild(status);
  el.appendChild(meta);

  return el;
}

function updateQueueItem(el, result, issueNumber) {
  el.innerHTML = ''; // Clear skeleton

  const meta = document.createElement('div');
  meta.className = 'queue-item-meta';

  const sender = document.createElement('span');
  sender.className   = 'queue-sender';
  sender.textContent = DOMPurify.sanitize(result.sender || 'unknown', { ALLOWED_TAGS: [] });

  const status = document.createElement('span');
  status.className   = `queue-status ${result.valid ? 'valid' : 'invalid'}`;
  status.textContent = result.valid ? '✓ SIG VALID' : '✗ SIG INVALID';

  const time = document.createElement('span');
  time.className   = 'queue-time';
  time.textContent = result.timestamp ? new Date(result.timestamp).toLocaleString() : '';

  meta.appendChild(sender);
  meta.appendChild(status);
  meta.appendChild(time);

  const textEl = document.createElement('div');
  textEl.className   = 'queue-text';
  // textContent only — no HTML injection
  textEl.textContent = result.error
    ? `[Decrypt error: ${result.error}]`
    : DOMPurify.sanitize(result.text || '', { ALLOWED_TAGS: [] });

  const actions = document.createElement('div');
  actions.className = 'queue-actions';

  if (result.valid && !result.error) {
    const approveBtn = document.createElement('button');
    approveBtn.className   = 'btn btn-success';
    approveBtn.textContent = 'Approve';
    approveBtn.addEventListener('click', async () => {
      approveBtn.disabled   = true;
      approveBtn.textContent = 'Publishing...';
      try {
        await ZTAdmin.approveComment(result);
        el.remove();
        toast(`Comment from ${result.sender} approved.`, 'success');
      } catch (err) {
        approveBtn.disabled   = false;
        approveBtn.textContent = 'Approve';
        toast(`Approve failed: ${err.message}`, 'error');
      }
    });
    actions.appendChild(approveBtn);
  }

  const rejectBtn = document.createElement('button');
  rejectBtn.className   = 'btn btn-danger';
  rejectBtn.textContent = 'Reject';
  rejectBtn.addEventListener('click', async () => {
    rejectBtn.disabled = true;
    try {
      await ZTAdmin.rejectComment(issueNumber);
      el.remove();
      toast('Comment rejected.', 'warning');
    } catch (err) {
      rejectBtn.disabled   = false;
      toast(`Reject failed: ${err.message}`, 'error');
    }
  });
  actions.appendChild(rejectBtn);

  el.appendChild(meta);
  el.appendChild(textEl);
  el.appendChild(actions);
}

function markQueueItemError(el, message) {
  const errEl = document.createElement('div');
  errEl.className   = 'queue-text';
  errEl.style.color = 'var(--danger)';
  errEl.textContent = `Error: ${message}`;
  el.appendChild(errEl);
}

function toast(message, type = 'info') {
  const container = document.getElementById('toast-container');
  const el        = document.createElement('div');
  el.className    = `toast ${type}`;
  el.textContent  = message;
  container.appendChild(el);
  setTimeout(() => el.remove(), 4500);
}
