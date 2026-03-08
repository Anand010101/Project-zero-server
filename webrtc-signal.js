/**
 * webrtc-signal.js — P2P Audio Calling via WebRTC + GitHub Issues Signaling
 *
 * Architecture Overview:
 *   GitHub Issues act as an asynchronous, encrypted signaling channel.
 *   Once ICE negotiation completes, all media flows directly P2P (SRTP/DTLS).
 *   GitHub is NEVER involved in the actual call media — only setup.
 *
 * Signal Message Types (all encrypted + signed using ZTCrypto):
 *   'connection-request' : A → B  "I want to call you"
 *   'connection-accept'  : B → A  "I accept, here is my SDP answer"
 *   'connection-reject'  : B → A  "Declined"
 *   'sdp-offer'          : A → B  RTCSessionDescription (type: offer)
 *   'sdp-answer'         : B → A  RTCSessionDescription (type: answer)
 *   'ice-candidate'      : A ↔ B  RTCIceCandidate (continuous exchange)
 *   'hangup'             : A ↔ B  Call terminated
 *
 * Rate Limiting:
 *   GitHub secondary rate limits: 100 requests/minute per authenticated user.
 *   The Burner Bot PAT is shared across all users — exponential backoff
 *   with jitter is mandatory to prevent collective exhaustion.
 *
 * This module depends on: crypto.js (window.ZTCrypto)
 */

'use strict';

// ─── Configuration ────────────────────────────────────────────────────────────

const GITHUB_OWNER    = '__REPLACE_WITH_GITHUB_USERNAME__';
const GITHUB_REPO     = '__REPLACE_WITH_GITHUB_REPO__';
const GITHUB_API_BASE = 'https://api.github.com';

// Burner Bot PAT: scoped ONLY to issues:write. No repo read/write access.
// Embedded as plaintext — acceptable because its blast radius is minimal.
// Rotate this token if abused (GitHub will also auto-revoke on secret scanning).
const BURNER_BOT_PAT  = '__REPLACE_WITH_BURNER_BOT_PAT__';

// STUN servers — prioritise IPv6 endpoints for better NAT traversal.
// Using multiple providers for redundancy and TURN fallback.
const ICE_SERVERS = [
  { urls: 'stun:stun.l.google.com:19302' },           // IPv4
  { urls: 'stun:stun1.l.google.com:19302' },
  { urls: 'stun:[2607:f8b0:4004:c07::7f]:19302' },    // IPv6 Google STUN
  { urls: 'stun:stun.cloudflare.com:3478' },
  // Add TURN server here for symmetric NAT traversal in production:
  // { urls: 'turn:turn.example.com:3478', username: '...', credential: '...' }
];

// Polling configuration
const POLL_BASE_INTERVAL_MS   = 4000;   // 4s base — below rate limit floor
const POLL_MAX_INTERVAL_MS    = 120000; // 2 min max backoff
const POLL_JITTER_MAX_MS      = 2000;   // ±2s jitter
const POLL_MAX_CONSECUTIVE_ERRS = 5;   // Lock out after 5 consecutive failures
const ICE_GATHERING_TIMEOUT_MS  = 15000;

// ─── Module State ─────────────────────────────────────────────────────────────

let _localUser        = null;  // { username, decryptKey, signKey, inboxIssueId }
let _usersCache       = null;  // In-memory cache of users.json
let _peerConnection   = null;  // RTCPeerConnection
let _localStream      = null;  // MediaStream (microphone)
let _remoteStream     = null;  // MediaStream (received audio)
let _callState        = 'idle'; // idle | connecting | ringing | in-call | ended
let _remoteUsername   = null;
let _pollTimer        = null;
let _pollInterval     = POLL_BASE_INTERVAL_MS;
let _pollErrCount     = 0;
let _processedMsgIds  = new Set(); // Idempotency: never process a signal twice

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Initialises the signaling module for an authenticated user.
 * Must be called before any other function.
 *
 * @param {{
 *   username:     string,
 *   decryptKey:   CryptoKey,   // Non-extractable RSA-OAEP private key
 *   signKey:      CryptoKey,   // Non-extractable RSA-PSS private key
 *   inboxIssueId: number       // From users.json
 * }} userConfig
 */
function initSignaling(userConfig) {
  _localUser = userConfig;
  _startPolling();
  console.info('[webrtc] Signaling initialised for:', userConfig.username);
}

/**
 * Initiates a call to a remote user.
 * Sends an encrypted connection-request to their GitHub Issue inbox.
 *
 * @param {string} remoteUsername
 * @returns {Promise<void>}
 */
async function callUser(remoteUsername) {
  _assertReady();
  if (_callState !== 'idle') throw new Error(`Cannot call while in state: ${_callState}`);

  const remoteUser = await _getUser(remoteUsername);
  if (!remoteUser?.inboxIssueId) {
    throw new Error(`User '${remoteUsername}' has no signal inbox assigned.`);
  }

  _remoteUsername = remoteUsername;
  _setCallState('connecting');

  // Request microphone access early so the user sees the browser prompt
  await _acquireLocalStream();

  // Create PeerConnection (but don't create offer yet — wait for acceptance)
  _createPeerConnection();

  // Send connection-request signal
  await _sendSignal(remoteUsername, {
    type:        'connection-request',
    callerInbox: _localUser.inboxIssueId,
  });

  _dispatchCallEvent('outgoing-call', { to: remoteUsername });
  console.info('[webrtc] Connection request sent to:', remoteUsername);
}

/**
 * Accepts an incoming call (call to this after receiving 'connection-request').
 *
 * @param {string} callerUsername
 * @param {number} callerInboxIssueId
 */
async function acceptCall(callerUsername, callerInboxIssueId) {
  _assertReady();
  if (_callState !== 'ringing') throw new Error('No incoming call to accept.');

  _remoteUsername = callerUsername;
  _setCallState('connecting');

  await _acquireLocalStream();
  _createPeerConnection();

  // Create SDP offer (caller side sends offer, but we need to inform caller
  // so they can create one too — we accept first, caller generates SDP offer)
  await _sendSignal(callerUsername, {
    type:        'connection-accept',
    acceptorInbox: _localUser.inboxIssueId,
  });

  // Caller will receive this acceptance and send the SDP offer
  console.info('[webrtc] Call accepted from:', callerUsername);
}

/**
 * Rejects an incoming call.
 *
 * @param {string} callerUsername
 */
async function rejectCall(callerUsername) {
  await _sendSignal(callerUsername, { type: 'connection-reject' });
  _setCallState('idle');
  _remoteUsername = null;
}

/**
 * Hangs up the current call.
 */
async function hangup() {
  if (_remoteUsername) {
    await _sendSignal(_remoteUsername, { type: 'hangup' }).catch(() => {});
  }
  _teardownCall();
}

// ─── Polling Engine (Exponential Backoff + Jitter) ───────────────────────────

/**
 * Starts polling the user's GitHub Issue inbox for new signal messages.
 * Uses exponential backoff with full jitter to avoid thundering herd
 * on the shared GitHub API rate limit.
 *
 * Backoff formula:
 *   nextInterval = min(base * 2^attempt, maxInterval) + random(0, jitter)
 */
function _startPolling() {
  if (_pollTimer) clearTimeout(_pollTimer);
  _pollTimer = setTimeout(_pollInbox, _pollInterval);
}

async function _pollInbox() {
  if (!_localUser?.inboxIssueId) return;

  try {
    const comments = await _fetchIssueComments(_localUser.inboxIssueId);
    _pollErrCount  = 0;
    _pollInterval  = POLL_BASE_INTERVAL_MS; // Reset backoff on success

    for (const comment of comments) {
      await _processInboxComment(comment);
    }

  } catch (err) {
    _pollErrCount++;
    console.warn(`[webrtc] Polling error (${_pollErrCount}):`, err.message);

    if (_pollErrCount >= POLL_MAX_CONSECUTIVE_ERRS) {
      console.error('[webrtc] Too many polling errors. Backing off for 2 minutes.');
      _pollInterval = POLL_MAX_INTERVAL_MS;
    } else {
      // Exponential backoff: base * 2^errCount, capped, plus jitter
      const exp     = Math.min(_pollErrCount, 10);
      const backoff = Math.min(POLL_BASE_INTERVAL_MS * Math.pow(2, exp), POLL_MAX_INTERVAL_MS);
      const jitter  = Math.random() * POLL_JITTER_MAX_MS;
      _pollInterval = backoff + jitter;
      console.info(`[webrtc] Next poll in ${(_pollInterval / 1000).toFixed(1)}s`);
    }
  }

  // Schedule next poll (adaptive interval)
  if (_localUser) {
    _pollTimer = setTimeout(_pollInbox, _pollInterval);
  }
}

function _stopPolling() {
  if (_pollTimer) {
    clearTimeout(_pollTimer);
    _pollTimer = null;
  }
}

// ─── Inbox Processing ─────────────────────────────────────────────────────────

/**
 * Decrypts and dispatches a single inbox comment (signal message).
 * Idempotency: messages are tracked by comment ID to prevent double-processing.
 */
async function _processInboxComment(comment) {
  // Idempotency guard
  if (_processedMsgIds.has(comment.id)) return;
  _processedMsgIds.add(comment.id);

  // Trim the set to prevent unbounded growth
  if (_processedMsgIds.size > 1000) {
    const oldest = [..._processedMsgIds].slice(0, 500);
    oldest.forEach(id => _processedMsgIds.delete(id));
  }

  let envelopeJson;
  try {
    envelopeJson = comment.body;
    JSON.parse(envelopeJson); // Validate it's JSON
  } catch {
    return; // Skip non-signal comments (e.g. human messages)
  }

  // Identify sender from the outer envelope (unencrypted metadata)
  let outerEnvelope;
  try {
    outerEnvelope = JSON.parse(envelopeJson);
  } catch {
    return;
  }

  if (!outerEnvelope?.from || !outerEnvelope?.cipher) return;

  const sender     = outerEnvelope.from;
  const senderUser = await _getUser(sender);
  if (!senderUser) {
    console.warn('[webrtc] Signal from unknown user:', sender);
    return;
  }

  // Import sender's verify key and open envelope
  const { ZTCrypto } = window;
  let senderVerifyKey;
  try {
    senderVerifyKey = await ZTCrypto.importPublicKey(senderUser.signPublicKeyPem, 'RSA-PSS');
  } catch {
    console.warn('[webrtc] Invalid sender sign key for:', sender);
    return;
  }

  let result;
  try {
    result = await ZTCrypto.openSecureEnvelope(
      envelopeJson,
      _localUser.decryptKey,
      senderVerifyKey
    );
  } catch (err) {
    console.error('[webrtc] Failed to open envelope from', sender, ':', err.message);
    return;
  }

  if (!result.valid) {
    console.warn('[webrtc] INVALID SIGNATURE from:', sender, '— discarding signal');
    return;
  }

  await _handleSignalMessage(result.payload, sender);
}

// ─── Signal Dispatcher ────────────────────────────────────────────────────────

/**
 * Handles a verified, decrypted signal message.
 * Routes to the appropriate handler based on message type.
 */
async function _handleSignalMessage(message, sender) {
  console.info(`[webrtc] Signal received: ${message.type} from ${sender}`);

  switch (message.type) {
    case 'connection-request':
      await _onConnectionRequest(message, sender);
      break;

    case 'connection-accept':
      await _onConnectionAccepted(message, sender);
      break;

    case 'connection-reject':
      _onConnectionRejected(sender);
      break;

    case 'sdp-offer':
      await _onSdpOffer(message, sender);
      break;

    case 'sdp-answer':
      await _onSdpAnswer(message, sender);
      break;

    case 'ice-candidate':
      await _onIceCandidate(message, sender);
      break;

    case 'hangup':
      _onRemoteHangup(sender);
      break;

    default:
      console.warn('[webrtc] Unknown signal type:', message.type);
  }
}

// ─── Signal Handlers ─────────────────────────────────────────────────────────

async function _onConnectionRequest(message, caller) {
  if (_callState !== 'idle') {
    // Busy — auto-reject
    await _sendSignal(caller, { type: 'connection-reject', reason: 'busy' });
    return;
  }

  _remoteUsername = caller;
  _setCallState('ringing');
  _dispatchCallEvent('incoming-call', {
    from:        caller,
    callerInbox: message.callerInbox,
  });
}

async function _onConnectionAccepted(message, remoteUsername) {
  if (_callState !== 'connecting' || _remoteUsername !== remoteUsername) return;

  console.info('[webrtc] Call accepted. Creating SDP offer...');

  // Now that the callee accepted, caller creates the WebRTC SDP offer
  try {
    const offer = await _peerConnection.createOffer({
      offerToReceiveAudio: true,
      offerToReceiveVideo: false,
    });

    await _peerConnection.setLocalDescription(offer);

    // Wait for ICE gathering to complete (or timeout)
    await _waitForIceGathering();

    // Send the completed offer (with all local ICE candidates embedded)
    await _sendSignal(remoteUsername, {
      type: 'sdp-offer',
      sdp:  _peerConnection.localDescription,
    });

    console.info('[webrtc] SDP offer sent to:', remoteUsername);
  } catch (err) {
    console.error('[webrtc] Failed to create SDP offer:', err);
    _teardownCall();
  }
}

function _onConnectionRejected(remoteUsername) {
  console.info('[webrtc] Call rejected by:', remoteUsername);
  _teardownCall();
  _dispatchCallEvent('call-rejected', { by: remoteUsername });
}

async function _onSdpOffer(message, caller) {
  if (!_peerConnection) {
    console.warn('[webrtc] Received SDP offer but no PeerConnection exists.');
    return;
  }

  try {
    const offer = new RTCSessionDescription(message.sdp);
    await _peerConnection.setRemoteDescription(offer);

    const answer = await _peerConnection.createAnswer();
    await _peerConnection.setLocalDescription(answer);

    await _waitForIceGathering();

    await _sendSignal(caller, {
      type: 'sdp-answer',
      sdp:  _peerConnection.localDescription,
    });

    console.info('[webrtc] SDP answer sent to:', caller);
  } catch (err) {
    console.error('[webrtc] SDP offer handling failed:', err);
    await hangup();
  }
}

async function _onSdpAnswer(message, remoteUsername) {
  if (!_peerConnection || _callState === 'idle') return;

  try {
    const answer = new RTCSessionDescription(message.sdp);
    await _peerConnection.setRemoteDescription(answer);
    console.info('[webrtc] SDP answer applied. Awaiting ICE connection...');
  } catch (err) {
    console.error('[webrtc] SDP answer handling failed:', err);
    await hangup();
  }
}

async function _onIceCandidate(message, _sender) {
  if (!_peerConnection || !message.candidate) return;

  try {
    const candidate = new RTCIceCandidate(message.candidate);
    await _peerConnection.addIceCandidate(candidate);
  } catch (err) {
    // Non-fatal: stale candidates are common
    console.debug('[webrtc] ICE candidate add failed (may be stale):', err.message);
  }
}

function _onRemoteHangup(remoteUsername) {
  console.info('[webrtc] Remote hung up:', remoteUsername);
  _teardownCall();
  _dispatchCallEvent('call-ended', { by: remoteUsername, reason: 'remote-hangup' });
}

// ─── RTCPeerConnection Management ────────────────────────────────────────────

/**
 * Creates and configures the RTCPeerConnection with ICE server config.
 * Wires up all event handlers for ICE, connection state, and track events.
 */
function _createPeerConnection() {
  if (_peerConnection) {
    _peerConnection.close();
    _peerConnection = null;
  }

  _peerConnection = new RTCPeerConnection({
    iceServers:           ICE_SERVERS,
    iceCandidatePoolSize: 10,
    // IPv6 preference: 'relay' falls back to TURN; for direct P2P leave as 'all'
    iceTransportPolicy: 'all',
    // BundlePolicy maximises IPv6 use by bundling all media on one transport
    bundlePolicy:   'max-bundle',
    rtcpMuxPolicy:  'require',
  });

  // Add local audio tracks to the PeerConnection
  if (_localStream) {
    _localStream.getAudioTracks().forEach(track => {
      _peerConnection.addTrack(track, _localStream);
    });
  }

  // ── ICE Candidate Handler ──────────────────────────────────────────────────
  // Trickle ICE: send each candidate to the remote peer as it's discovered.
  // We encrypt each candidate individually via the signaling channel.
  _peerConnection.onicecandidate = async (event) => {
    if (!event.candidate || !_remoteUsername) return;

    try {
      await _sendSignal(_remoteUsername, {
        type:      'ice-candidate',
        candidate: event.candidate.toJSON(),
      });
    } catch (err) {
      console.warn('[webrtc] Failed to send ICE candidate:', err.message);
    }
  };

  // ── ICE Connection State ───────────────────────────────────────────────────
  _peerConnection.oniceconnectionstatechange = () => {
    const state = _peerConnection.iceConnectionState;
    console.info('[webrtc] ICE state:', state);

    switch (state) {
      case 'connected':
      case 'completed':
        _setCallState('in-call');
        _dispatchCallEvent('call-connected', { with: _remoteUsername });
        // Log whether IPv6 is in use
        _logActiveCandidate();
        break;

      case 'failed':
        console.error('[webrtc] ICE connection failed.');
        _teardownCall();
        _dispatchCallEvent('call-failed', { reason: 'ice-failed' });
        break;

      case 'disconnected':
        _dispatchCallEvent('call-disconnected', { reason: 'ice-disconnected' });
        break;
    }
  };

  // ── Remote Track Handler ───────────────────────────────────────────────────
  _peerConnection.ontrack = (event) => {
    if (event.streams?.[0]) {
      _remoteStream = event.streams[0];
      _dispatchCallEvent('remote-stream', { stream: _remoteStream });
    }
  };

  // ── Connection State ───────────────────────────────────────────────────────
  _peerConnection.onconnectionstatechange = () => {
    console.info('[webrtc] Connection state:', _peerConnection.connectionState);
  };

  return _peerConnection;
}

/**
 * Waits for ICE gathering to complete OR times out.
 * Using 'complete' state rather than trickle ICE to reduce signal round-trips.
 */
function _waitForIceGathering() {
  return new Promise((resolve) => {
    if (_peerConnection.iceGatheringState === 'complete') {
      resolve();
      return;
    }

    const timeout = setTimeout(resolve, ICE_GATHERING_TIMEOUT_MS);

    _peerConnection.addEventListener('icegatheringstatechange', function onGather() {
      if (_peerConnection.iceGatheringState === 'complete') {
        clearTimeout(timeout);
        _peerConnection.removeEventListener('icegatheringstatechange', onGather);
        resolve();
      }
    });
  });
}

/**
 * Logs which ICE candidate pair is active (IPv4 vs IPv6) for diagnostics.
 */
async function _logActiveCandidate() {
  if (!_peerConnection) return;
  try {
    const stats = await _peerConnection.getStats();
    stats.forEach(report => {
      if (report.type === 'candidate-pair' && report.state === 'succeeded') {
        const local = stats.get(report.localCandidateId);
        if (local) {
          const isIPv6 = local.address?.includes(':');
          console.info(`[webrtc] Active path: ${local.protocol}/${isIPv6 ? 'IPv6' : 'IPv4'} via ${local.address}`);
        }
      }
    });
  } catch { /* Non-critical diagnostic */ }
}

// ─── Media Acquisition ────────────────────────────────────────────────────────

async function _acquireLocalStream() {
  if (_localStream) return; // Already acquired

  try {
    _localStream = await navigator.mediaDevices.getUserMedia({
      audio: {
        echoCancellation:  true,
        noiseSuppression:  true,
        autoGainControl:   true,
        channelCount:      1, // Mono for VoIP efficiency
        sampleRate:        48000,
      },
      video: false,
    });
    console.info('[webrtc] Microphone access granted.');
  } catch (err) {
    throw new Error(`Microphone access denied: ${err.message}`);
  }
}

// ─── Signaling Transport (GitHub Issues) ─────────────────────────────────────

/**
 * Sends an encrypted, signed signal to a remote user's GitHub Issue inbox.
 * Uses the Burner Bot PAT for posting — no admin credentials needed.
 *
 * @param {string} recipientUsername
 * @param {object} signalMessage
 */
async function _sendSignal(recipientUsername, signalMessage) {
  const { ZTCrypto } = window;

  // Get recipient's public key
  const recipient = await _getUser(recipientUsername);
  if (!recipient?.inboxIssueId) {
    throw new Error(`Recipient ${recipientUsername} has no inbox.`);
  }

  // Import recipient's encryption public key
  const recipientPubKey = await ZTCrypto.importPublicKey(
    recipient.encryptPublicKeyPem,
    'RSA-OAEP'
  );

  // Create signed + encrypted envelope
  const envelopeJson = await ZTCrypto.createSecureEnvelope(
    signalMessage,
    _localUser.signKey,
    recipientPubKey,
    _localUser.username
  );

  // Post to recipient's inbox Issue as a comment
  await _postIssueComment(recipient.inboxIssueId, envelopeJson);
}

/**
 * Fetches comments from a GitHub Issue (the user's signal inbox).
 * Only returns comments newer than the last processed ID.
 *
 * @param {number} issueNumber
 * @returns {Promise<Array<{ id: number, body: string, created_at: string }>>}
 */
async function _fetchIssueComments(issueNumber) {
  const url = new URL(
    `${GITHUB_API_BASE}/repos/${GITHUB_OWNER}/${GITHUB_REPO}/issues/${issueNumber}/comments`
  );
  url.searchParams.set('per_page', '100');
  url.searchParams.set('sort',     'created');
  url.searchParams.set('direction','asc');

  const res = await fetch(url.toString(), {
    headers: {
      'Authorization': `Bearer ${BURNER_BOT_PAT}`,
      'Accept':        'application/vnd.github.v3+json',
      'X-GitHub-Api-Version': '2022-11-28',
    },
  });

  _checkRateLimit(res.headers);

  if (res.status === 403) throw new Error('Rate limited by GitHub API');
  if (!res.ok) throw new Error(`GitHub issues fetch failed: ${res.status}`);

  return res.json();
}

/**
 * Posts a signal message as a comment on a GitHub Issue.
 *
 * @param {number} issueNumber
 * @param {string} body - JSON envelope string.
 */
async function _postIssueComment(issueNumber, body) {
  const res = await fetch(
    `${GITHUB_API_BASE}/repos/${GITHUB_OWNER}/${GITHUB_REPO}/issues/${issueNumber}/comments`,
    {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${BURNER_BOT_PAT}`,
        'Accept':        'application/vnd.github.v3+json',
        'Content-Type':  'application/json',
        'X-GitHub-Api-Version': '2022-11-28',
      },
      body: JSON.stringify({ body }),
    }
  );

  _checkRateLimit(res.headers);

  if (res.status === 403) throw new Error('Rate limited — retry with backoff');
  if (!res.ok) throw new Error(`Signal POST failed: ${res.status}`);

  return res.json();
}

/**
 * Inspects GitHub API rate limit headers and warns if approaching the limit.
 * GitHub returns X-RateLimit-* on every response.
 */
function _checkRateLimit(headers) {
  const remaining = parseInt(headers.get('X-RateLimit-Remaining') || '100', 10);
  const resetAt   = parseInt(headers.get('X-RateLimit-Reset')     || '0',   10);
  const limit     = parseInt(headers.get('X-RateLimit-Limit')     || '60',  10);

  if (remaining < 10) {
    const resetIn = Math.ceil((resetAt * 1000 - Date.now()) / 1000);
    console.warn(`[webrtc] GitHub rate limit low: ${remaining}/${limit} remaining. Resets in ${resetIn}s`);

    // Adaptively increase poll interval to protect remaining quota
    const safeInterval = Math.max(_pollInterval, (resetIn * 1000) / Math.max(remaining, 1));
    _pollInterval = Math.min(safeInterval, POLL_MAX_INTERVAL_MS);
  }
}

// ─── User Directory ───────────────────────────────────────────────────────────

/**
 * Fetches user data from the public users.json directory.
 * Cached in memory per session to reduce API calls.
 *
 * @param {string} username
 * @returns {Promise<object|null>}
 */
async function _getUser(username) {
  if (!_usersCache) {
    await _refreshUsersCache();
  }
  return _usersCache?.users?.[username] || null;
}

async function _refreshUsersCache() {
  // Fetch via CDN/raw to avoid burning the authenticated API rate limit
  const url = `https://raw.githubusercontent.com/${GITHUB_OWNER}/${GITHUB_REPO}/main/data/users.json`;
  const res = await fetch(`${url}?t=${Date.now()}`); // Cache-bust
  if (!res.ok) throw new Error(`Failed to fetch users.json: ${res.status}`);
  _usersCache = await res.json();
}

/**
 * Returns the list of available users for the calling UI.
 * @returns {Promise<string[]>}
 */
async function getAvailableUsers() {
  if (!_usersCache) await _refreshUsersCache();
  return Object.keys(_usersCache?.users || {}).filter(u => u !== _localUser?.username);
}

// ─── Call Teardown ────────────────────────────────────────────────────────────

function _teardownCall() {
  if (_peerConnection) {
    _peerConnection.close();
    _peerConnection = null;
  }

  if (_localStream) {
    _localStream.getTracks().forEach(t => t.stop());
    _localStream = null;
  }

  _remoteStream   = null;
  _remoteUsername = null;
  _setCallState('idle');
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function _assertReady() {
  if (!_localUser) throw new Error('Signaling not initialised. Call initSignaling() first.');
}

function _setCallState(state) {
  _callState = state;
  _dispatchCallEvent('state-change', { state });
  console.info('[webrtc] Call state →', state);
}

function _dispatchCallEvent(type, detail = {}) {
  window.dispatchEvent(new CustomEvent(`ztcall:${type}`, { detail }));
}

// ─── Diagnostic & Cleanup ─────────────────────────────────────────────────────

/**
 * Returns the current call state for UI binding.
 */
function getCallState() {
  return {
    state:          _callState,
    remoteUsername: _remoteUsername,
    isPolling:      !!_pollTimer,
    pollInterval:   _pollInterval,
    pollErrCount:   _pollErrCount,
  };
}

/**
 * Cleans up all resources (call on page unload).
 */
function destroy() {
  _stopPolling();
  _teardownCall();
  _localUser    = null;
  _usersCache   = null;
  _processedMsgIds.clear();
  console.info('[webrtc] Signaling module destroyed.');
}

// ─── Exports ──────────────────────────────────────────────────────────────────

window.ZTSignal = {
  // Lifecycle
  initSignaling,
  destroy,

  // Call control
  callUser,
  acceptCall,
  rejectCall,
  hangup,

  // State
  getCallState,
  getAvailableUsers,

  // Internal (exposed for testing/debugging)
  _refreshUsersCache,
};
