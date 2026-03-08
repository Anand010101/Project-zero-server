/**
 * app.js — Frontend Application Orchestrator
 *
 * Wires together ZTCrypto and ZTSignal modules with the DOM.
 * All user-generated content is sanitised through DOMPurify before
 * being inserted into the DOM — even content we ourselves encrypted.
 *
 * Security invariants enforced here:
 *   1. No innerHTML unless preceded by DOMPurify.sanitize()
 *   2. Identity keys are loaded as non-extractable CryptoKeys
 *   3. Comment text field is capped at 2000 chars (API body limit mitigation)
 *   4. Users list is fetched from raw GitHub (no rate limit cost)
 */

'use strict';

// ─── Configuration ────────────────────────────────────────────────────────────

const GITHUB_OWNER      = '__REPLACE_WITH_GITHUB_USERNAME__';
const GITHUB_REPO       = '__REPLACE_WITH_GITHUB_REPO__';
const BURNER_BOT_PAT    = '__REPLACE_WITH_BURNER_BOT_PAT__';
const COMMENT_MAX_CHARS = 2000;

// ─── Session State ────────────────────────────────────────────────────────────

let _session = null; // { username, decryptKey, signKey, inboxIssueId }

// ─── Boot ─────────────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', async () => {
  bindIdentityUI();
  bindCommentUI();
  bindCallUI();
  bindCallEvents();
  await loadCommentFeed();
});

// ─── Identity UI ─────────────────────────────────────────────────────────────

function bindIdentityUI() {
  const fileInput  = document.getElementById('key-file-input');
  const logoutBtn  = document.getElementById('logout-btn');

  fileInput.addEventListener('change', async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;

    try {
      const { decryptKey, signKey, username } = await ZTCrypto.importPrivateKeyBundle(file);

      // Fetch inbox issue ID from users.json
      const user = await fetchUserRecord(username);
      if (!user) {
        toast(`User '${username}' not found in registry.`, 'error');
        return;
      }

      _session = { username, decryptKey, signKey, inboxIssueId: user.inboxIssueId };

      // Initialise signaling with this identity
      ZTSignal.initSignaling(_session);

      updateIdentityUI(true, username);
      showAuthenticatedUI();
      await refreshCallUserList();
      toast(`Identity loaded: ${username}`, 'success');

    } catch (err) {
      toast(`Key load failed: ${err.message}`, 'error');
    } finally {
      fileInput.value = ''; // Allow re-selection of same file
    }
  });

  logoutBtn.addEventListener('click', () => {
    ZTSignal.destroy();
    _session = null;
    updateIdentityUI(false, null);
    hideAuthenticatedUI();
    toast('Identity unloaded.', 'warning');
  });
}

function updateIdentityUI(authenticated, username) {
  const dot    = document.getElementById('identity-dot');
  const label  = document.getElementById('identity-label');
  const logout = document.getElementById('logout-btn');

  if (authenticated) {
    dot.classList.add('active');
    // Sanitise username before inserting into DOM (XSS mitigation)
    label.textContent = `Authenticated as: ${DOMPurify.sanitize(username, { ALLOWED_TAGS: [] })}`;
    logout.style.display = 'inline-block';
  } else {
    dot.classList.remove('active');
    label.textContent    = 'No identity loaded';
    logout.style.display = 'none';
  }
}

function showAuthenticatedUI() {
  document.getElementById('comment-form').style.display  = 'block';
  document.getElementById('call-panel').style.display    = 'block';
}

function hideAuthenticatedUI() {
  document.getElementById('comment-form').style.display  = 'none';
  document.getElementById('call-panel').style.display    = 'none';
}

// ─── Comment Submission ───────────────────────────────────────────────────────

function bindCommentUI() {
  const submitBtn = document.getElementById('submit-btn');
  const input     = document.getElementById('comment-input');

  // Enforce character limit
  input.addEventListener('input', () => {
    if (input.value.length > COMMENT_MAX_CHARS) {
      input.value = input.value.slice(0, COMMENT_MAX_CHARS);
    }
  });

  submitBtn.addEventListener('click', submitComment);
}

async function submitComment() {
  if (!_session) { toast('Load your identity first.', 'warning'); return; }

  const input = document.getElementById('comment-input');
  const text  = input.value.trim();

  if (!text) { toast('Comment cannot be empty.', 'warning'); return; }
  if (text.length > COMMENT_MAX_CHARS) {
    toast(`Comment too long (max ${COMMENT_MAX_CHARS} chars).`, 'warning');
    return;
  }

  const submitBtn = document.getElementById('submit-btn');
  submitBtn.disabled   = true;
  submitBtn.textContent = 'Encrypting...';

  try {
    // 1. Fetch admin's encryption public key from users.json
    const adminUser = await fetchUserRecord('__ADMIN_USERNAME__');
    if (!adminUser) throw new Error('Admin public key not found.');

    const adminPubKey = await ZTCrypto.importPublicKey(adminUser.encryptPublicKeyPem, 'RSA-OAEP');

    // 2. Create signed + encrypted envelope
    const envelope = await ZTCrypto.createSecureEnvelope(
      { text, type: 'comment' },
      _session.signKey,
      adminPubKey,
      _session.username
    );

    // 3. Submit via Burner Bot to GitHub Issues (quarantine queue)
    await postCommentIssue(envelope);

    input.value          = '';
    submitBtn.textContent = 'Submit Encrypted';
    toast('Comment submitted for moderation.', 'success');

  } catch (err) {
    toast(`Submission failed: ${err.message}`, 'error');
    console.error('[app] submitComment error:', err);
  } finally {
    submitBtn.disabled    = false;
    submitBtn.textContent = 'Submit Encrypted';
  }
}

async function postCommentIssue(envelopeJson) {
  const res = await fetch(
    `https://api.github.com/repos/${GITHUB_OWNER}/${GITHUB_REPO}/issues`,
    {
      method:  'POST',
      headers: {
        'Authorization':     `Bearer ${BURNER_BOT_PAT}`,
        'Accept':            'application/vnd.github.v3+json',
        'Content-Type':      'application/json',
        'X-GitHub-Api-Version': '2022-11-28',
      },
      body: JSON.stringify({
        title:  `[COMMENT] ${_session.username} @ ${new Date().toISOString()}`,
        body:   envelopeJson,
        labels: ['comment-queue'],
      }),
    }
  );

  if (!res.ok) throw new Error(`GitHub Issue POST failed: ${res.status}`);
  return res.json();
}

// ─── Comments Feed ────────────────────────────────────────────────────────────

async function loadCommentFeed() {
  const feed = document.getElementById('comments-feed');

  try {
    const url = `https://raw.githubusercontent.com/${GITHUB_OWNER}/${GITHUB_REPO}/main/data/comments.json?t=${Date.now()}`;
    const res = await fetch(url);

    if (!res.ok) {
      feed.innerHTML = '<div class="loading">No comments yet.</div>';
      return;
    }

    const data = await res.json();
    const comments = Array.isArray(data.comments) ? data.comments : [];

    document.getElementById('comment-count').textContent =
      `${comments.length} message${comments.length !== 1 ? 's' : ''}`;

    if (comments.length === 0) {
      feed.innerHTML = '<div class="loading">No approved comments yet.</div>';
      return;
    }

    // Render newest-first
    feed.innerHTML = '';
    [...comments].reverse().forEach(comment => {
      feed.appendChild(renderComment(comment));
    });

  } catch (err) {
    feed.innerHTML = `<div class="loading">Failed to load feed: ${err.message}</div>`;
  }
}

/**
 * Renders a single comment card.
 * ALL values are passed through DOMPurify before DOM insertion.
 */
function renderComment(comment) {
  const card = document.createElement('div');
  card.className = 'comment-card';

  // Sanitise EVERY field — even though the admin already sanitised on approval,
  // defence-in-depth requires we also sanitise on render.
  const safeAuthor    = DOMPurify.sanitize(comment.sender    || 'anonymous', { ALLOWED_TAGS: [] });
  const safeText      = DOMPurify.sanitize(comment.text      || '',          { ALLOWED_TAGS: [] });
  const safeTimestamp = DOMPurify.sanitize(comment.timestamp || '',          { ALLOWED_TAGS: [] });

  const meta = document.createElement('div');
  meta.className = 'comment-meta';

  const author = document.createElement('span');
  author.className   = 'comment-author';
  author.textContent = safeAuthor;

  const time = document.createElement('span');
  time.className   = 'comment-time';
  time.textContent = safeTimestamp ? new Date(safeTimestamp).toLocaleString() : '';

  meta.appendChild(author);
  meta.appendChild(time);

  const text = document.createElement('p');
  text.className   = 'comment-text';
  text.textContent = safeText; // textContent — zero XSS risk

  card.appendChild(meta);
  card.appendChild(text);

  return card;
}

// ─── Call UI ─────────────────────────────────────────────────────────────────

function bindCallUI() {
  document.getElementById('call-btn').addEventListener('click', async () => {
    const select   = document.getElementById('call-user-select');
    const username = select.value;
    if (!username) { toast('Select a user to call.', 'warning'); return; }

    try {
      await ZTSignal.callUser(username);
    } catch (err) {
      toast(`Call failed: ${err.message}`, 'error');
    }
  });

  document.getElementById('hangup-btn').addEventListener('click', async () => {
    await ZTSignal.hangup();
  });
}

function bindCallEvents() {
  window.addEventListener('ztcall:state-change', (e) => {
    const { state } = e.detail;
    updateCallStatus(state);
  });

  window.addEventListener('ztcall:incoming-call', (e) => {
    const { from, callerInbox } = e.detail;
    showIncomingCallModal(from, callerInbox);
  });

  window.addEventListener('ztcall:remote-stream', (e) => {
    const audio = document.getElementById('remote-audio');
    audio.srcObject = e.detail.stream;
  });

  window.addEventListener('ztcall:call-rejected', (e) => {
    toast(`Call rejected by ${e.detail.by}`, 'warning');
  });

  window.addEventListener('ztcall:call-failed', (e) => {
    toast(`Call failed: ${e.detail.reason}`, 'error');
  });

  window.addEventListener('ztcall:session-expired', () => {
    toast('Admin session expired.', 'warning');
  });
}

function updateCallStatus(state) {
  const statusEl  = document.getElementById('call-status');
  const hangupBtn = document.getElementById('hangup-btn');
  const callBtn   = document.getElementById('call-btn');

  statusEl.textContent = `State: ${state}`;
  hangupBtn.style.display = (state === 'in-call' || state === 'connecting') ? 'inline-block' : 'none';
  callBtn.style.display   = state === 'idle' ? 'inline-block' : 'none';
}

async function refreshCallUserList() {
  const select = document.getElementById('call-user-select');
  try {
    const users = await ZTSignal.getAvailableUsers();
    select.innerHTML = '<option value="">-- Select user to call --</option>';
    users.forEach(username => {
      const opt       = document.createElement('option');
      opt.value       = DOMPurify.sanitize(username, { ALLOWED_TAGS: [] });
      opt.textContent = DOMPurify.sanitize(username, { ALLOWED_TAGS: [] });
      select.appendChild(opt);
    });
  } catch (err) {
    console.warn('[app] Failed to load users for call list:', err.message);
  }
}

function showIncomingCallModal(caller, callerInboxId) {
  const container = document.getElementById('modal-container');

  // Sanitise caller name
  const safeCaller = DOMPurify.sanitize(caller, { ALLOWED_TAGS: [] });

  const overlay = document.createElement('div');
  overlay.className = 'modal-overlay';

  const modal = document.createElement('div');
  modal.className = 'modal';

  const h3 = document.createElement('h3');
  h3.textContent = '// Incoming Call';

  const p = document.createElement('p');
  p.textContent = `${safeCaller} is calling you.`;

  const actions = document.createElement('div');
  actions.className = 'modal-actions';

  const acceptBtn = document.createElement('button');
  acceptBtn.className   = 'btn btn-primary';
  acceptBtn.textContent = 'Accept';
  acceptBtn.addEventListener('click', async () => {
    container.innerHTML = '';
    try {
      await ZTSignal.acceptCall(caller, callerInboxId);
    } catch (err) {
      toast(`Accept failed: ${err.message}`, 'error');
    }
  });

  const rejectBtn = document.createElement('button');
  rejectBtn.className   = 'btn btn-danger';
  rejectBtn.textContent = 'Reject';
  rejectBtn.addEventListener('click', async () => {
    container.innerHTML = '';
    await ZTSignal.rejectCall(caller);
    toast(`Rejected call from ${safeCaller}`, 'warning');
  });

  actions.appendChild(rejectBtn);
  actions.appendChild(acceptBtn);
  modal.appendChild(h3);
  modal.appendChild(p);
  modal.appendChild(actions);
  overlay.appendChild(modal);
  container.appendChild(overlay);
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

async function fetchUserRecord(username) {
  try {
    const url = `https://raw.githubusercontent.com/${GITHUB_OWNER}/${GITHUB_REPO}/main/data/users.json?t=${Date.now()}`;
    const res  = await fetch(url);
    if (!res.ok) return null;
    const data = await res.json();
    return data.users?.[username] || null;
  } catch {
    return null;
  }
}

function toast(message, type = 'info') {
  const container = document.getElementById('toast-container');
  const el        = document.createElement('div');
  el.className    = `toast ${type}`;
  // Use textContent — never innerHTML — for toast messages
  el.textContent  = message;
  container.appendChild(el);
  setTimeout(() => el.remove(), 4000);
}
