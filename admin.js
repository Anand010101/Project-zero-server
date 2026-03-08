/**
 * admin.js — Zero-Trust Admin Panel: Decrypted-State Authorization
 *
 * Security Model:
 *   The Admin PAT (GitHub Fine-Grained Personal Access Token with
 *   contents:write) NEVER exists in plaintext in the source code.
 *   It is stored as RSA-OAEP hybrid-encrypted ciphertext, unlockable
 *   ONLY by the Admin's RSA private key at runtime, in-memory.
 *
 *   Attack surface analysis:
 *     • Source code exposure  → Only ciphertext visible. Useless without privkey.
 *     • XSS after unlock      → PAT lives in JS closure; not in DOM or storage.
 *                               Non-extractable CryptoKey blocks key exfiltration.
 *     • MITM                  → All GitHub API calls are HTTPS. CSP blocks exfil.
 *
 *   This module depends on: crypto.js (window.ZTCrypto)
 */

'use strict';

// ─── Encrypted Admin PAT (Hardcoded Ciphertext) ───────────────────────────────
//
// HOW TO GENERATE THIS:
//   1. Run the Admin Key Generation tool (admin-keygen.html, offline).
//   2. That tool calls ZTCrypto.hybridEncrypt(GITHUB_PAT, adminPublicKey).
//   3. Paste the resulting JSON string here as ENCRYPTED_ADMIN_PAT.
//   4. The plaintext PAT is then destroyed. Only this ciphertext is committed.
//
// ROTATE: If the PAT is ever suspected compromised, revoke it on GitHub,
//         generate a new one, re-encrypt with the Admin public key, and redeploy.
//
const ENCRYPTED_ADMIN_PAT = `__REPLACE_WITH_HYBRIDENCRYPT_OUTPUT__`;

// The Admin's RSA-OAEP public key (PEM) — embedded in source, not secret.
// Used by the keygen tool to produce ENCRYPTED_ADMIN_PAT above.
const ADMIN_PUBLIC_KEY_PEM = `__REPLACE_WITH_ADMIN_RSA_OAEP_PUBLIC_KEY_PEM__`;

// The Admin's RSA-PSS public key (PEM) — used to verify admin-signed actions.
const ADMIN_SIGN_VERIFY_KEY_PEM = `__REPLACE_WITH_ADMIN_RSA_PSS_PUBLIC_KEY_PEM__`;

// GitHub repository coordinates
const GITHUB_OWNER      = '__REPLACE_WITH_GITHUB_USERNAME__';
const GITHUB_REPO       = '__REPLACE_WITH_GITHUB_REPO__';
const GITHUB_API_BASE   = 'https://api.github.com';
const GITHUB_CONTENT_BASE = `${GITHUB_API_BASE}/repos/${GITHUB_OWNER}/${GITHUB_REPO}/contents`;

// ─── Module State (Closure-scoped — not accessible via window) ────────────────

let _adminPat         = null;   // decrypted PAT string, lives only in closure
let _adminPrivDecrypt = null;   // non-extractable CryptoKey (RSA-OAEP)
let _adminPrivSign    = null;   // non-extractable CryptoKey (RSA-PSS)
let _adminVerifyKey   = null;   // admin RSA-PSS public key for self-verification
let _sessionExpiry    = null;   // auto-lock timestamp

const SESSION_TIMEOUT_MS = 30 * 60 * 1000; // 30 minutes inactivity lock

// ─── Admin Authentication ─────────────────────────────────────────────────────

/**
 * Unlocks the admin session by decrypting the hardcoded PAT ciphertext
 * using the Admin's RSA private key loaded from a file input.
 *
 * Flow:
 *   User selects .json key bundle → importPrivateKey (non-extractable) →
 *   hybridDecrypt(ENCRYPTED_ADMIN_PAT) → PAT stored in closure →
 *   Session timer started.
 *
 * @param {File} keyBundleFile - Admin's private key bundle JSON.
 * @returns {Promise<{ success: boolean, username: string, error?: string }>}
 */
async function unlockAdminSession(keyBundleFile) {
  try {
    const { ZTCrypto } = window;

    // 1. Import the admin's private keys as non-extractable CryptoKeys
    const { decryptKey, signKey, username } = await ZTCrypto.importPrivateKeyBundle(keyBundleFile);

    // 2. Decrypt the hardcoded Admin PAT ciphertext
    let decryptedPat;
    try {
      decryptedPat = await ZTCrypto.hybridDecrypt(ENCRYPTED_ADMIN_PAT, decryptKey);
    } catch (err) {
      return { success: false, error: 'Decryption failed — wrong private key or corrupted ciphertext.' };
    }

    // 3. Validate the PAT looks like a GitHub token (basic sanity check)
    if (!decryptedPat.startsWith('github_pat_') && !decryptedPat.startsWith('ghp_')) {
      return { success: false, error: 'Decrypted value does not appear to be a valid GitHub PAT.' };
    }

    // 4. Test the PAT against GitHub API before accepting it
    const testResult = await _validatePatWithGitHub(decryptedPat);
    if (!testResult.valid) {
      _zeroOutPat(decryptedPat);
      return { success: false, error: `GitHub PAT validation failed: ${testResult.reason}` };
    }

    // 5. Pre-import admin verify key for signature operations
    _adminVerifyKey = await ZTCrypto.importPublicKey(ADMIN_SIGN_VERIFY_KEY_PEM, 'RSA-PSS');

    // 6. Store everything in closure scope
    _adminPat         = decryptedPat;
    _adminPrivDecrypt = decryptKey;
    _adminPrivSign    = signKey;
    _resetSessionTimer();

    console.info('[admin] Session unlocked for:', username);
    return { success: true, username };

  } catch (err) {
    console.error('[admin] unlockAdminSession error:', err);
    return { success: false, error: err.message };
  }
}

/**
 * Validates the decrypted PAT by making a low-impact GitHub API call.
 * Uses the /user endpoint which requires no special scopes.
 */
async function _validatePatWithGitHub(pat) {
  try {
    const res = await fetch(`${GITHUB_API_BASE}/user`, {
      headers: _authHeaders(pat),
    });

    if (res.status === 200) {
      const data = await res.json();
      return { valid: true, login: data.login };
    } else if (res.status === 401) {
      return { valid: false, reason: 'Token unauthorized (revoked or expired).' };
    } else {
      return { valid: false, reason: `Unexpected status ${res.status}` };
    }
  } catch (err) {
    return { valid: false, reason: `Network error: ${err.message}` };
  }
}

/**
 * Locks the admin session, zeroing out the PAT from memory.
 * All subsequent API calls will fail until re-authentication.
 */
function lockAdminSession() {
  if (_adminPat) {
    _zeroOutPat(_adminPat);
    _adminPat = null;
  }
  _adminPrivDecrypt = null;
  _adminPrivSign    = null;
  _adminVerifyKey   = null;
  _sessionExpiry    = null;
  console.info('[admin] Session locked.');
}

/**
 * Overwrites a string's characters to reduce PAT lifetime in memory.
 * JS GC is non-deterministic, but this is a best-effort mitigation.
 * NOTE: Strings are immutable in JS; this creates a new string — true
 *       zeroing requires TypedArrays. Kept here for intent documentation.
 */
function _zeroOutPat(patStr) {
  // Best effort: replace reference. True secure erasure requires Uint8Array.
  patStr = '0'.repeat(patStr.length); // eslint-disable-line no-param-reassign
}

// ─── Session Management ───────────────────────────────────────────────────────

let _sessionTimer = null;

function _resetSessionTimer() {
  _sessionExpiry = Date.now() + SESSION_TIMEOUT_MS;
  clearTimeout(_sessionTimer);
  _sessionTimer = setTimeout(() => {
    console.warn('[admin] Session expired due to inactivity.');
    lockAdminSession();
    _dispatchAdminEvent('session-expired');
  }, SESSION_TIMEOUT_MS);
}

function _assertUnlocked() {
  if (!_adminPat) throw new Error('Admin session is locked. Authenticate first.');
  if (Date.now() > _sessionExpiry) {
    lockAdminSession();
    throw new Error('Admin session expired. Re-authenticate.');
  }
  _resetSessionTimer(); // Activity extends the session
}

function isAdminUnlocked() {
  return !!_adminPat && Date.now() < _sessionExpiry;
}

// ─── GitHub API Helpers ───────────────────────────────────────────────────────

function _authHeaders(pat = _adminPat) {
  return {
    'Authorization': `Bearer ${pat}`,
    'Accept':        'application/vnd.github.v3+json',
    'Content-Type':  'application/json',
    'X-GitHub-Api-Version': '2022-11-28',
  };
}

/**
 * Fetches the current SHA of a file in the repo.
 * Required for PUT (update) operations on the GitHub Contents API.
 *
 * @param {string} filePath  - e.g. 'data/comments.json'
 * @returns {Promise<{ sha: string, content: object }>}
 */
async function _getFileShaAndContent(filePath) {
  _assertUnlocked();
  const res = await fetch(`${GITHUB_CONTENT_BASE}/${filePath}`, {
    headers: _authHeaders(),
  });

  if (!res.ok) {
    if (res.status === 404) throw new Error(`File not found: ${filePath}`);
    throw new Error(`GitHub API error ${res.status}: ${await res.text()}`);
  }

  const data    = await res.json();
  const decoded = atob(data.content.replace(/\n/g, ''));
  return {
    sha:     data.sha,
    content: JSON.parse(decoded),
  };
}

/**
 * Commits updated content to a file in the repository.
 * Uses the SHA to ensure atomic updates (prevents overwriting concurrent edits).
 *
 * @param {string} filePath  - Repository file path.
 * @param {object} newContent - JavaScript object to serialise as JSON.
 * @param {string} sha       - Current file SHA from _getFileShaAndContent().
 * @param {string} message   - Git commit message.
 */
async function _putFileContent(filePath, newContent, sha, message) {
  _assertUnlocked();

  const encodedContent = btoa(
    unescape(encodeURIComponent(JSON.stringify(newContent, null, 2)))
  );

  const body = JSON.stringify({
    message,
    content: encodedContent,
    sha,
    committer: {
      name:  'ZeroTrust Bot',
      email: 'zerotrust-bot@noreply.local',
    },
  });

  const res = await fetch(`${GITHUB_CONTENT_BASE}/${filePath}`, {
    method:  'PUT',
    headers: _authHeaders(),
    body,
  });

  if (!res.ok) {
    const errBody = await res.text();
    if (res.status === 409) {
      throw new Error('SHA conflict — file was modified concurrently. Retry.');
    }
    throw new Error(`GitHub PUT failed ${res.status}: ${errBody}`);
  }

  return res.json();
}

// ─── Comment Moderation ───────────────────────────────────────────────────────

/**
 * Fetches all pending (open) GitHub Issues from the comment quarantine queue.
 * These contain E2EE-encrypted comment submissions from users.
 *
 * @param {string} label - GitHub Issue label used to tag comment queue items.
 * @returns {Promise<Array<{ id: number, number: number, body: string, created_at: string }>>}
 */
async function fetchPendingComments(label = 'comment-queue') {
  _assertUnlocked();

  const url = new URL(`${GITHUB_API_BASE}/repos/${GITHUB_OWNER}/${GITHUB_REPO}/issues`);
  url.searchParams.set('state',    'open');
  url.searchParams.set('labels',   label);
  url.searchParams.set('per_page', '50');
  url.searchParams.set('sort',     'created');
  url.searchParams.set('direction','asc');

  const res = await fetch(url.toString(), { headers: _authHeaders() });
  if (!res.ok) throw new Error(`Failed to fetch issues: ${res.status}`);

  const issues = await res.json();
  return issues.map(i => ({
    id:         i.id,
    number:     i.number,
    body:       i.body,
    created_at: i.created_at,
    labels:     i.labels.map(l => l.name),
  }));
}

/**
 * Decrypts and verifies a single pending comment issue.
 * Fetches the sender's public key from users.json for signature verification.
 *
 * @param {object} issue       - Issue object from fetchPendingComments().
 * @returns {Promise<{
 *   valid: boolean,
 *   sender: string,
 *   text: string,
 *   timestamp: string,
 *   issueNumber: number
 * }>}
 */
async function decryptAndVerifyComment(issue) {
  _assertUnlocked();
  const { ZTCrypto } = window;

  let envelopeJson;
  try {
    envelopeJson = JSON.parse(issue.body);
    if (!envelopeJson.cipher) throw new Error('Not a valid ZT envelope');
  } catch {
    return { valid: false, issueNumber: issue.number, error: 'Issue body is not a ZT envelope' };
  }

  // 1. Fetch the sender's public keys from users.json
  let usersData;
  try {
    const res = await fetch(`${GITHUB_CONTENT_BASE}/data/users.json`, {
      headers: _authHeaders()
    });
    const file = await res.json();
    usersData = JSON.parse(atob(file.content.replace(/\n/g, '')));
  } catch (err) {
    return { valid: false, issueNumber: issue.number, error: `Failed to load users.json: ${err.message}` };
  }

  const sender     = envelopeJson.from;
  const senderUser = usersData.users?.[sender];

  if (!senderUser) {
    return { valid: false, issueNumber: issue.number, error: `Unknown sender: ${sender}` };
  }

  // 2. Import sender's PSS verify key
  let senderVerifyKey;
  try {
    senderVerifyKey = await ZTCrypto.importPublicKey(senderUser.signPublicKeyPem, 'RSA-PSS');
  } catch (err) {
    return { valid: false, issueNumber: issue.number, error: `Bad sender public key: ${err.message}` };
  }

  // 3. Open the envelope — decrypt + verify signature in one step
  try {
    const result = await ZTCrypto.openSecureEnvelope(
      issue.body,
      _adminPrivDecrypt,
      senderVerifyKey
    );

    return {
      valid:       result.valid,
      sender:      result.sender,
      text:        result.payload.text,
      timestamp:   result.payload.timestamp,
      issueNumber: issue.number,
    };
  } catch (err) {
    return { valid: false, issueNumber: issue.number, error: `Envelope open failed: ${err.message}` };
  }
}

/**
 * Approves a comment: appends it to comments.json and closes the Issue.
 * Uses optimistic SHA locking to prevent lost updates.
 *
 * @param {object} verifiedComment - Output from decryptAndVerifyComment().
 */
async function approveComment(verifiedComment) {
  _assertUnlocked();
  if (!verifiedComment.valid) throw new Error('Cannot approve an invalid/unverified comment.');

  // DOMPurify sanitisation (belt-and-suspenders — content is also sanitised on render)
  if (!window.DOMPurify) throw new Error('DOMPurify is not loaded. Aborting to prevent XSS.');
  const safeText = DOMPurify.sanitize(verifiedComment.text, {
    ALLOWED_TAGS: [],  // Strip ALL HTML — plaintext only
    ALLOWED_ATTR: [],
  });

  const { sha, content: commentsData } = await _getFileShaAndContent('data/comments.json');

  if (!Array.isArray(commentsData.comments)) {
    commentsData.comments = [];
  }

  commentsData.comments.push({
    id:        `${Date.now()}-${Math.random().toString(36).slice(2)}`,
    sender:    verifiedComment.sender,
    text:      safeText,
    timestamp: verifiedComment.timestamp,
    approved:  new Date().toISOString(),
  });

  // Commit updated comments.json
  await _putFileContent(
    'data/comments.json',
    commentsData,
    sha,
    `chore: approve comment from ${verifiedComment.sender} [skip ci]`
  );

  // Close the GitHub Issue (removes from quarantine queue)
  await _closeIssue(verifiedComment.issueNumber);

  console.info('[admin] Comment approved from:', verifiedComment.sender);
}

/**
 * Rejects a comment: closes the Issue with a 'rejected' label without
 * publishing the content.
 *
 * @param {number} issueNumber
 * @param {string} reason - Optional reason for audit log.
 */
async function rejectComment(issueNumber, reason = 'Rejected by admin') {
  _assertUnlocked();
  await _closeIssue(issueNumber, reason);
  console.info('[admin] Comment rejected, issue #', issueNumber);
}

async function _closeIssue(issueNumber, comment) {
  _assertUnlocked();

  if (comment) {
    await fetch(
      `${GITHUB_API_BASE}/repos/${GITHUB_OWNER}/${GITHUB_REPO}/issues/${issueNumber}/comments`,
      {
        method:  'POST',
        headers: _authHeaders(),
        body:    JSON.stringify({ body: comment }),
      }
    );
  }

  await fetch(
    `${GITHUB_API_BASE}/repos/${GITHUB_OWNER}/${GITHUB_REPO}/issues/${issueNumber}`,
    {
      method:  'PATCH',
      headers: _authHeaders(),
      body:    JSON.stringify({ state: 'closed' }),
    }
  );
}

// ─── User Registration Approval ───────────────────────────────────────────────

/**
 * Registers a new user by adding their public keys to users.json.
 * Called from the admin panel after reviewing a registration request.
 *
 * @param {object} registrationPayload - Decrypted registration envelope payload.
 */
async function approveUserRegistration(registrationPayload) {
  _assertUnlocked();

  const { username, encryptPublicKeyPem, signPublicKeyPem, requestedAt } = registrationPayload;

  if (!username || !encryptPublicKeyPem || !signPublicKeyPem) {
    throw new Error('Invalid registration payload — missing required fields.');
  }

  // Validate PEMs are importable before committing to storage
  const { ZTCrypto } = window;
  await ZTCrypto.importPublicKey(encryptPublicKeyPem, 'RSA-OAEP');
  await ZTCrypto.importPublicKey(signPublicKeyPem,    'RSA-PSS');

  const { sha, content: usersData } = await _getFileShaAndContent('data/users.json');

  if (!usersData.users) usersData.users = {};

  if (usersData.users[username]) {
    throw new Error(`User '${username}' already exists.`);
  }

  usersData.users[username] = {
    username,
    encryptPublicKeyPem,
    signPublicKeyPem,
    registeredAt: new Date().toISOString(),
    requestedAt:  requestedAt || null,
    inboxIssueId: null,  // Set by assignUserInbox()
  };

  await _putFileContent(
    'data/users.json',
    usersData,
    sha,
    `feat: register user ${username} [skip ci]`
  );

  return usersData.users[username];
}

/**
 * Creates a dedicated GitHub Issue as the user's WebRTC signaling inbox
 * and records its ID in users.json.
 *
 * @param {string} username
 * @returns {Promise<number>} inboxIssueNumber
 */
async function assignUserInbox(username) {
  _assertUnlocked();

  // Create the inbox issue
  const res = await fetch(
    `${GITHUB_API_BASE}/repos/${GITHUB_OWNER}/${GITHUB_REPO}/issues`,
    {
      method:  'POST',
      headers: _authHeaders(),
      body:    JSON.stringify({
        title:  `[INBOX] ${username}`,
        body:   `Signal inbox for user: ${username}. DO NOT CLOSE MANUALLY.`,
        labels: ['signal-inbox'],
      }),
    }
  );

  if (!res.ok) throw new Error(`Failed to create inbox issue: ${res.status}`);
  const issue = await res.json();

  // Record inbox issue number in users.json
  const { sha, content: usersData } = await _getFileShaAndContent('data/users.json');

  if (!usersData.users?.[username]) {
    throw new Error(`User ${username} not found in users.json`);
  }

  usersData.users[username].inboxIssueId = issue.number;

  await _putFileContent(
    'data/users.json',
    usersData,
    sha,
    `chore: assign inbox to ${username} [skip ci]`
  );

  return issue.number;
}

// ─── Event Bus ────────────────────────────────────────────────────────────────

function _dispatchAdminEvent(type, detail = {}) {
  window.dispatchEvent(new CustomEvent(`ztadmin:${type}`, { detail }));
}

// ─── Exports ──────────────────────────────────────────────────────────────────

window.ZTAdmin = {
  // Authentication
  unlockAdminSession,
  lockAdminSession,
  isAdminUnlocked,

  // Comment moderation
  fetchPendingComments,
  decryptAndVerifyComment,
  approveComment,
  rejectComment,

  // User management
  approveUserRegistration,
  assignUserInbox,

  // Constants (read-only references for UI)
  ADMIN_PUBLIC_KEY_PEM,
  GITHUB_OWNER,
  GITHUB_REPO,
};
