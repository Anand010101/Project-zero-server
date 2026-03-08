/**
 * crypto.js — Zero-Trust E2EE Cryptography Layer
 * Uses exclusively the native Web Crypto API (window.crypto.subtle).
 * All private keys are imported as NON-EXTRACTABLE to prevent exfiltration.
 *
 * Key Algorithms:
 *   - RSA-OAEP  (4096-bit, SHA-512) : Asymmetric encryption
 *   - RSA-PSS   (4096-bit, SHA-512) : Digital signatures
 *   - AES-GCM   (256-bit)           : Symmetric hybrid encryption for large payloads
 */

'use strict';

// ─── Constants ────────────────────────────────────────────────────────────────

const RSA_KEY_PARAMS = {
  modulusLength: 4096,
  publicExponent: new Uint8Array([0x01, 0x00, 0x01]), // 65537
  hash: 'SHA-512',
};

const RSA_OAEP_PARAMS  = { name: 'RSA-OAEP',  ...RSA_KEY_PARAMS };
const RSA_PSS_PARAMS   = { name: 'RSA-PSS',   ...RSA_KEY_PARAMS };
const PSS_SIGN_PARAMS  = { name: 'RSA-PSS', saltLength: 64 };
const AES_GCM_LENGTH   = 256;
const AES_GCM_IV_BYTES = 12; // 96-bit IV — NIST recommended for GCM

// ─── Utilities ────────────────────────────────────────────────────────────────

const buf2b64  = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
const b642buf  = (b64) => Uint8Array.from(atob(b64), c => c.charCodeAt(0)).buffer;
const str2buf  = (str) => new TextEncoder().encode(str).buffer;
const buf2str  = (buf) => new TextDecoder().decode(buf);

/**
 * Serialises a CryptoKey to a PEM-formatted string.
 * Only used for PUBLIC keys (exportable by design).
 * @param {CryptoKey} key  - Must be a public key.
 * @param {'spki'} format  - Only SPKI is supported for public keys.
 */
async function exportPublicKeyPem(key) {
  const exported = await window.crypto.subtle.exportKey('spki', key);
  const b64 = buf2b64(exported).match(/.{1,64}/g).join('\n');
  return `-----BEGIN PUBLIC KEY-----\n${b64}\n-----END PUBLIC KEY-----`;
}

/**
 * Exports a private key as a PKCS#8 PEM string for user backup.
 * NOTE: This is called ONLY once during key generation for the .pem download.
 * The in-memory CryptoKey for signing/decryption is always non-extractable.
 * @param {CryptoKey} key - Must be a private key with extractable: true.
 */
async function exportPrivateKeyPem(key) {
  const exported = await window.crypto.subtle.exportKey('pkcs8', key);
  const b64 = buf2b64(exported).match(/.{1,64}/g).join('\n');
  return `-----BEGIN PRIVATE KEY-----\n${b64}\n-----END PRIVATE KEY-----`;
}

/**
 * Strips PEM headers/footers and decodes the base64 DER payload.
 */
function pemToDer(pem) {
  const b64 = pem
    .replace(/-----BEGIN [A-Z ]+-----/, '')
    .replace(/-----END [A-Z ]+-----/, '')
    .replace(/\s+/g, '');
  return b642buf(b64);
}

// ─── Key Generation ───────────────────────────────────────────────────────────

/**
 * Generates a full PKI identity: two key pairs (encryption + signing).
 * Returns exportable private keys ONLY at generation time for PEM backup.
 * Subsequent in-memory usage re-imports them as non-extractable.
 *
 * @returns {Promise<{
 *   encryptKeyPair: { publicKey: CryptoKey, privateKey: CryptoKey },
 *   signKeyPair:    { publicKey: CryptoKey, privateKey: CryptoKey },
 *   publicPems:     { encrypt: string, sign: string },
 *   privatePems:    { encrypt: string, sign: string }
 * }>}
 */
async function generateIdentityKeyPairs() {
  // Generate RSA-OAEP pair for encryption/decryption (extractable=true for PEM export)
  const encryptKeyPair = await window.crypto.subtle.generateKey(
    RSA_OAEP_PARAMS,
    true, // extractable only during generation
    ['encrypt', 'decrypt']
  );

  // Generate RSA-PSS pair for signing/verification
  const signKeyPair = await window.crypto.subtle.generateKey(
    RSA_PSS_PARAMS,
    true,
    ['sign', 'verify']
  );

  const publicPems = {
    encrypt: await exportPublicKeyPem(encryptKeyPair.publicKey),
    sign:    await exportPublicKeyPem(signKeyPair.publicKey),
  };

  const privatePems = {
    encrypt: await exportPrivateKeyPem(encryptKeyPair.privateKey),
    sign:    await exportPrivateKeyPem(signKeyPair.privateKey),
  };

  return { encryptKeyPair, signKeyPair, publicPems, privatePems };
}

// ─── Key Import ───────────────────────────────────────────────────────────────

/**
 * Imports an RSA public key from a PEM string.
 * Public keys are always extractable (they're public by definition).
 *
 * @param {string} pem         - PEM-encoded SPKI public key.
 * @param {'RSA-OAEP'|'RSA-PSS'} usage - Determines key algorithm.
 */
async function importPublicKey(pem, usage) {
  const algorithm = usage === 'RSA-OAEP' ? RSA_OAEP_PARAMS : RSA_PSS_PARAMS;
  const keyUsages = usage === 'RSA-OAEP' ? ['encrypt'] : ['verify'];

  return window.crypto.subtle.importKey(
    'spki',
    pemToDer(pem),
    algorithm,
    true,       // public keys may be exported
    keyUsages
  );
}

/**
 * Imports an RSA private key from a PEM string as NON-EXTRACTABLE.
 * Once imported, the raw key material CANNOT be read back from JS.
 * This is the primary defence against XSS key exfiltration.
 *
 * @param {string} pem         - PEM-encoded PKCS#8 private key.
 * @param {'RSA-OAEP'|'RSA-PSS'} usage
 */
async function importPrivateKey(pem, usage) {
  const algorithm = usage === 'RSA-OAEP' ? RSA_OAEP_PARAMS : RSA_PSS_PARAMS;
  const keyUsages = usage === 'RSA-OAEP' ? ['decrypt'] : ['sign'];

  return window.crypto.subtle.importKey(
    'pkcs8',
    pemToDer(pem),
    algorithm,
    false,      // ← NON-EXTRACTABLE: key material can never be read back
    keyUsages
  );
}

// ─── Hybrid Encryption (RSA-OAEP + AES-GCM) ──────────────────────────────────

/**
 * Encrypts an arbitrary-length plaintext payload using hybrid encryption:
 *   1. Generates a random ephemeral AES-256-GCM key.
 *   2. Encrypts the plaintext with AES-GCM.
 *   3. Encrypts the AES key with the recipient's RSA-OAEP public key.
 *   4. Returns a JSON envelope.
 *
 * This overcomes the RSA block-size limitation and is the standard approach.
 *
 * @param {string} plaintext        - UTF-8 plaintext.
 * @param {CryptoKey} recipientPubKey - RSA-OAEP public key.
 * @returns {Promise<string>}         - JSON envelope (base64 encoded fields).
 */
async function hybridEncrypt(plaintext, recipientPubKey) {
  // 1. Generate ephemeral AES-256-GCM session key
  const aesKey = await window.crypto.subtle.generateKey(
    { name: 'AES-GCM', length: AES_GCM_LENGTH },
    true,
    ['encrypt', 'decrypt']
  );

  // 2. Generate random IV (must be unique per encryption)
  const iv = window.crypto.getRandomValues(new Uint8Array(AES_GCM_IV_BYTES));

  // 3. Encrypt plaintext with AES-GCM
  const ciphertext = await window.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    aesKey,
    str2buf(plaintext)
  );

  // 4. Export the raw AES key and encrypt it with recipient's RSA public key
  const rawAesKey    = await window.crypto.subtle.exportKey('raw', aesKey);
  const encryptedKey = await window.crypto.subtle.encrypt(
    { name: 'RSA-OAEP' },
    recipientPubKey,
    rawAesKey
  );

  return JSON.stringify({
    v:   '1',                        // envelope version
    ek:  buf2b64(encryptedKey),      // RSA-OAEP wrapped AES key
    iv:  buf2b64(iv.buffer),         // AES-GCM IV
    ct:  buf2b64(ciphertext),        // AES-GCM ciphertext
  });
}

/**
 * Decrypts a hybrid-encrypted JSON envelope.
 *
 * @param {string} envelopeJson      - JSON string from hybridEncrypt().
 * @param {CryptoKey} recipientPrivKey - Non-extractable RSA-OAEP private key.
 * @returns {Promise<string>}          - Recovered plaintext.
 */
async function hybridDecrypt(envelopeJson, recipientPrivKey) {
  const envelope = JSON.parse(envelopeJson);

  if (envelope.v !== '1') {
    throw new Error(`Unsupported envelope version: ${envelope.v}`);
  }

  // 1. Decrypt the wrapped AES key with RSA-OAEP private key
  const rawAesKey = await window.crypto.subtle.decrypt(
    { name: 'RSA-OAEP' },
    recipientPrivKey,
    b642buf(envelope.ek)
  );

  // 2. Reconstruct the AES-GCM key
  const aesKey = await window.crypto.subtle.importKey(
    'raw',
    rawAesKey,
    { name: 'AES-GCM', length: AES_GCM_LENGTH },
    false,  // non-extractable session key
    ['decrypt']
  );

  // 3. Decrypt the ciphertext
  const plainBuf = await window.crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: new Uint8Array(b642buf(envelope.iv)) },
    aesKey,
    b642buf(envelope.ct)
  );

  return buf2str(plainBuf);
}

// ─── Digital Signatures (RSA-PSS) ────────────────────────────────────────────

/**
 * Signs a payload with the user's RSA-PSS private key.
 * Returns a detached base64-encoded signature.
 *
 * @param {string} payload          - The string to sign (JSON serialised object).
 * @param {CryptoKey} signingKey    - Non-extractable RSA-PSS private key.
 * @returns {Promise<string>}         - Base64 DER signature.
 */
async function signPayload(payload, signingKey) {
  const signature = await window.crypto.subtle.sign(
    PSS_SIGN_PARAMS,
    signingKey,
    str2buf(payload)
  );
  return buf2b64(signature);
}

/**
 * Verifies an RSA-PSS signature against a known public key.
 * This is used by the Admin panel to authenticate comment submissions.
 *
 * @param {string} payload           - Original string that was signed.
 * @param {string} signatureB64      - Base64 detached signature.
 * @param {CryptoKey} verifyKey      - Signer's RSA-PSS public key.
 * @returns {Promise<boolean>}
 */
async function verifySignature(payload, signatureB64, verifyKey) {
  return window.crypto.subtle.verify(
    PSS_SIGN_PARAMS,
    verifyKey,
    b642buf(signatureB64),
    str2buf(payload)
  );
}

// ─── Signed + Encrypted Message Envelope ─────────────────────────────────────

/**
 * Creates a fully authenticated, encrypted message envelope.
 * Process: sign(payload) → encrypt(payload + signature) → JSON envelope
 *
 * This ensures:
 *   • Confidentiality  : Only the recipient can decrypt.
 *   • Authenticity     : Recipient can verify the sender's identity.
 *   • Non-repudiation  : Signature is over the plaintext, inside the ciphertext.
 *
 * @param {object} messageObj       - Structured message object.
 * @param {CryptoKey} senderSignKey - Sender's non-extractable RSA-PSS private key.
 * @param {CryptoKey} recipientPubKey - Recipient's RSA-OAEP public key.
 * @param {string} senderUsername
 * @returns {Promise<string>}         - Outer JSON envelope (safe to POST to GitHub).
 */
async function createSecureEnvelope(messageObj, senderSignKey, recipientPubKey, senderUsername) {
  const payload = JSON.stringify({
    ...messageObj,
    sender:    senderUsername,
    timestamp: new Date().toISOString(),
    nonce:     buf2b64(window.crypto.getRandomValues(new Uint8Array(16)).buffer),
  });

  // Sign the payload first so signature is inside the encryption
  const signature = await signPayload(payload, senderSignKey);

  const innerBundle = JSON.stringify({ payload, signature });
  const cipherEnvelope = await hybridEncrypt(innerBundle, recipientPubKey);

  return JSON.stringify({
    v:      '1',
    from:   senderUsername,
    cipher: cipherEnvelope,       // hybridEncrypt output
    ts:     Date.now(),
  });
}

/**
 * Opens a secure envelope: decrypts then verifies the sender's signature.
 *
 * @param {string} envelopeJson       - Outer envelope from createSecureEnvelope().
 * @param {CryptoKey} recipientPrivKey - Recipient's non-extractable RSA-OAEP private key.
 * @param {CryptoKey} senderVerifyKey  - Sender's RSA-PSS public key (from users.json).
 * @returns {Promise<{ valid: boolean, payload: object, sender: string }>}
 */
async function openSecureEnvelope(envelopeJson, recipientPrivKey, senderVerifyKey) {
  const outer = JSON.parse(envelopeJson);

  // 1. Decrypt the inner bundle
  const innerBundleStr = await hybridDecrypt(outer.cipher, recipientPrivKey);
  const { payload, signature } = JSON.parse(innerBundleStr);

  // 2. Verify signature against sender's public key
  const valid = await verifySignature(payload, signature, senderVerifyKey);

  if (!valid) {
    console.warn('[crypto] Signature verification FAILED for envelope from:', outer.from);
  }

  return {
    valid,
    sender:  outer.from,
    payload: JSON.parse(payload),
  };
}

// ─── Key Storage Helpers (localStorage) ───────────────────────────────────────

/**
 * Persists PEM private keys to localStorage.
 * In production, consider using the non-exportable in-memory key and
 * requiring the user to re-upload their .pem on each session.
 *
 * @param {{ encryptPem: string, signPem: string }} pems
 */
function storePrivateKeyPems(pems) {
  // Storing PEMs in localStorage is a trade-off: convenient but
  // XSS can read localStorage. The non-extractable CryptoKey
  // in memory is the stronger security boundary.
  localStorage.setItem('zt_enc_priv_pem',  pems.encrypt);
  localStorage.setItem('zt_sign_priv_pem', pems.sign);
}

/**
 * Loads PEM private keys from localStorage and imports them as
 * non-extractable CryptoKey objects.
 *
 * @returns {Promise<{ decryptKey: CryptoKey, signKey: CryptoKey } | null>}
 */
async function loadStoredPrivateKeys() {
  const encPem  = localStorage.getItem('zt_enc_priv_pem');
  const signPem = localStorage.getItem('zt_sign_priv_pem');

  if (!encPem || !signPem) return null;

  try {
    const decryptKey = await importPrivateKey(encPem,  'RSA-OAEP');
    const signKey    = await importPrivateKey(signPem, 'RSA-PSS');
    return { decryptKey, signKey };
  } catch (err) {
    console.error('[crypto] Failed to import stored private keys:', err);
    return null;
  }
}

/**
 * Loads the current user's public key PEMs from localStorage.
 */
function loadStoredPublicKeyPems() {
  return {
    encrypt: localStorage.getItem('zt_enc_pub_pem'),
    sign:    localStorage.getItem('zt_sign_pub_pem'),
  };
}

/**
 * Triggers a browser download of the user's private key bundle as a .json file.
 * The user MUST keep this file safe — it IS their identity.
 *
 * @param {{ encrypt: string, sign: string }} privatePems
 * @param {string} username
 */
function downloadPrivateKeyBundle(privatePems, username) {
  const bundle = JSON.stringify({
    version:    '1',
    username,
    created:    new Date().toISOString(),
    encryptPem: privatePems.encrypt,
    signPem:    privatePems.sign,
    warning:    'KEEP THIS FILE SECRET. Anyone with this file can impersonate you.',
  }, null, 2);

  const blob = new Blob([bundle], { type: 'application/json' });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href     = url;
  a.download = `${username}-private-keys.json`;
  a.click();
  URL.revokeObjectURL(url);
}

/**
 * Imports a previously downloaded private key bundle JSON file.
 *
 * @param {File} file  - The .json key bundle file.
 * @returns {Promise<{ decryptKey: CryptoKey, signKey: CryptoKey, username: string }>}
 */
async function importPrivateKeyBundle(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = async (e) => {
      try {
        const bundle     = JSON.parse(e.target.result);
        const decryptKey = await importPrivateKey(bundle.encryptPem, 'RSA-OAEP');
        const signKey    = await importPrivateKey(bundle.signPem,    'RSA-PSS');
        resolve({ decryptKey, signKey, username: bundle.username });
      } catch (err) {
        reject(new Error(`Key bundle import failed: ${err.message}`));
      }
    };
    reader.onerror = () => reject(new Error('File read error'));
    reader.readAsText(file);
  });
}

// ─── Exports ──────────────────────────────────────────────────────────────────

window.ZTCrypto = {
  // Key lifecycle
  generateIdentityKeyPairs,
  importPublicKey,
  importPrivateKey,
  exportPublicKeyPem,

  // Encryption / Decryption
  hybridEncrypt,
  hybridDecrypt,

  // Signatures
  signPayload,
  verifySignature,

  // High-level envelope API
  createSecureEnvelope,
  openSecureEnvelope,

  // Storage helpers
  storePrivateKeyPems,
  loadStoredPrivateKeys,
  loadStoredPublicKeyPems,
  downloadPrivateKeyBundle,
  importPrivateKeyBundle,

  // Utilities (exposed for other modules)
  buf2b64,
  b642buf,
  str2buf,
  buf2str,
  pemToDer,
};
