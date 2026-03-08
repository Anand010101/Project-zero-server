# ZeroTrust Board — Architectural Blueprint

## Folder Structure

```
zerotrust-app/                    ← GitHub Pages root
│
├── index.html                    ← Public feed + E2EE comment submission + WebRTC call UI
├── admin.html                    ← Admin moderation panel (no traditional login)
├── register.html                 ← User key generation + registration request
│
├── js/
│   ├── crypto.js                 ← [MODULE 1] RSA key gen, hybrid encrypt, PSS sign
│   ├── admin.js                  ← [MODULE 2] Encrypted PAT unlock, moderation API
│   ├── admin-ui.js               ← Admin panel DOM controller
│   ├── webrtc-signal.js          ← [MODULE 4] WebRTC + GitHub Issues signaling
│   └── app.js                    ← Frontend orchestrator (comment submit, call UI)
│
└── data/
    ├── users.json                ← Public key directory (committed to repo)
    └── comments.json             ← Approved plaintext comments (committed to repo)
```

## Data File Schemas

### data/users.json
```json
{
  "version": "1",
  "users": {
    "alice": {
      "username": "alice",
      "encryptPublicKeyPem": "-----BEGIN PUBLIC KEY-----\n...",
      "signPublicKeyPem": "-----BEGIN PUBLIC KEY-----\n...",
      "registeredAt": "2025-01-01T00:00:00.000Z",
      "inboxIssueId": 42
    }
  }
}
```

### data/comments.json
```json
{
  "version": "1",
  "comments": [
    {
      "id": "1735000000000-abc123",
      "sender": "alice",
      "text": "Hello, world.",
      "timestamp": "2025-01-01T00:00:00.000Z",
      "approved": "2025-01-01T00:05:00.000Z"
    }
  ]
}
```

## Setup Checklist

### 1. GitHub Repository
- [ ] Create a public GitHub repository
- [ ] Enable GitHub Pages (Settings → Pages → Deploy from branch: main)
- [ ] Create `data/users.json` and `data/comments.json` with empty schemas above
- [ ] Create GitHub Issue labels: `comment-queue`, `signal-inbox`

### 2. GitHub Tokens
- [ ] **Admin PAT**: Fine-grained token with `contents: write` and `issues: write`
  - Owner: YOUR account, Repository: THIS repo
  - Used only in-memory after decryption — never in plaintext source
- [ ] **Burner Bot PAT**: Fine-grained token with ONLY `issues: write`
  - Can be a separate GitHub account/bot for isolation
  - Embed plaintext in `BURNER_BOT_PAT` constants (acceptable blast radius)

### 3. Admin Key Generation (run offline, air-gapped recommended)
```javascript
// Open browser console on a blank page, paste crypto.js, then:
const { encryptKeyPair, signKeyPair, publicPems, privatePems } =
  await ZTCrypto.generateIdentityKeyPairs();

// Encrypt the Admin PAT with the admin's own public key:
const encryptedPat = await ZTCrypto.hybridEncrypt(
  'github_pat_YOUR_ACTUAL_TOKEN_HERE',
  encryptKeyPair.publicKey
);

console.log('ENCRYPTED_ADMIN_PAT:', encryptedPat);
console.log('ADMIN_PUBLIC_KEY_PEM (encrypt):', publicPems.encrypt);
console.log('ADMIN_SIGN_VERIFY_KEY_PEM:', publicPems.sign);
```

### 4. Configure Source Files
Replace all `__REPLACE_WITH_*__` placeholders in:
- `js/admin.js`:  `ENCRYPTED_ADMIN_PAT`, `ADMIN_PUBLIC_KEY_PEM`, `ADMIN_SIGN_VERIFY_KEY_PEM`
- `js/admin.js`:  `GITHUB_OWNER`, `GITHUB_REPO`
- `js/webrtc-signal.js`: `GITHUB_OWNER`, `GITHUB_REPO`, `BURNER_BOT_PAT`
- `js/app.js`:    `GITHUB_OWNER`, `GITHUB_REPO`, `BURNER_BOT_PAT`, `__ADMIN_USERNAME__`

### 5. Register Admin User
Run `approveUserRegistration()` and `assignUserInbox()` via browser console
with the admin's public key PEMs to create the admin entry in `users.json`.

---

## Security Architecture Summary

```
┌─────────────────────────────────────────────────────────────────┐
│                    THREAT MODEL                                  │
│                                                                  │
│  XSS Attack Surface:                                            │
│    • Non-extractable CryptoKey: key material NEVER in JS heap   │
│    • DOMPurify on ALL user content before DOM insertion          │
│    • CSP blocks inline scripts + external JS exfiltration        │
│    • Admin PAT only in closure scope, not window/localStorage    │
│                                                                  │
│  Key Compromise:                                                 │
│    • Burner Bot: issues:write only — repo cannot be modified     │
│    • Admin PAT: requires Master Private Key to decrypt           │
│    • User keys: downloading .json is the only auth factor        │
│                                                                  │
│  Data Integrity:                                                 │
│    • Every comment: RSA-PSS signed by sender                    │
│    • Admin verifies signature before approving                   │
│    • SHA-based optimistic locking on all PUT operations          │
│    • Nonces prevent replay attacks                               │
│                                                                  │
│  Transport:                                                      │
│    • All signals: hybrid-encrypted (RSA-OAEP + AES-256-GCM)     │
│    • Media: WebRTC SRTP/DTLS (end-to-end, GitHub never sees it)  │
│    • HTTPS everywhere (GitHub API + GitHub Pages enforced)       │
└─────────────────────────────────────────────────────────────────┘
```

## Known Limitations & Trade-offs

| Concern | Mitigation | Residual Risk |
|---|---|---|
| Private key in localStorage | Non-extractable import; offer .pem download | XSS can still read raw PEM from localStorage |
| Burner Bot PAT in source | `issues:write` only; auto-revoked by GitHub secret scanning | Bot can spam issues |
| GitHub API rate limits | Exponential backoff with jitter | High-traffic apps need a real signaling server |
| Async signaling latency | ICE trickle + gathered-offer strategy | Call setup takes 10-30 seconds |
| No TURN server | STUN only configured | Symmetric NAT will fail without TURN |
