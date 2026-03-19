# @kiora-tech/transfert-crypto

Open-source, zero-dependency, client-side encryption library for secure file transfers.

Built on the **Web Crypto API** — no external cryptography dependencies. Uses battle-tested browser primitives for AES-256-GCM authenticated encryption with chunked file support.

## Why Open Source?

This library handles the most security-critical part of [Kiora Transfert](https://github.com/kiora-tech/transfert): encrypting and decrypting files in the browser before they ever touch a server.

By open-sourcing the encryption layer:
- **Anyone can audit** the cryptographic implementation
- **Security researchers** can review and improve the code
- **Users can verify** the zero-knowledge claims
- **No trust required** — read the code yourself

## Security Specifications

| Component | Specification |
|-----------|--------------|
| Algorithm | AES-256-GCM (Galois/Counter Mode) |
| Key Size | 256 bits (32 bytes) |
| IV/Nonce | 96 bits (12 bytes, unique per chunk) |
| Auth Tag | 128 bits (16 bytes, built into GCM) |
| Key Derivation | PBKDF2 with 600,000 iterations (OWASP 2023) |
| PBKDF2 Hash | SHA-256 |
| Salt Length | 128 bits (16 bytes) |
| HMAC | HKDF-derived HMAC-SHA256 for metadata integrity |

## Features

- **AES-256-GCM** — Industry-standard authenticated encryption
- **Web Crypto API** — Native browser cryptography, no dependencies
- **Chunked Processing** — Optimized for large files (5MB chunks)
- **Two Encryption Modes**:
  - **Auto**: Random key shared via URL fragment (never sent to server)
  - **Password**: PBKDF2 key derivation from user password
- **Zero-Knowledge** — Server never has access to encryption keys or plaintext
- **HMAC Integrity** — Tamper detection on encrypted metadata
- **Secure Memory** — Best-effort cleanup of sensitive data from memory
- **Secure Logging** — Automatic redaction of sensitive data in dev logs

## Installation

### ES Modules (no build step)

```html
<script type="module">
  import { CryptoEngine, KeyManager, ChunkProcessor } from './src/index.js';
</script>
```

### npm

```bash
npm install @kiora-tech/transfert-crypto
```

```javascript
import { initCrypto, CryptoEngine, KeyManager, ChunkProcessor } from '@kiora-tech/transfert-crypto';
```

### Symfony Asset Mapper (importmap)

```php
// importmap.php
'@kiora-tech/transfert-crypto' => [
    'path' => './vendor/kiora-tech/transfert-crypto/src/index.js',
],
```

## Quick Start

### Auto Mode (random key in URL)

```javascript
import { initCrypto } from '@kiora-tech/transfert-crypto';

// Initialize with random key
const { engine, keyManager, processor } = await initCrypto('auto');

// Encrypt a file chunk
const { encryptedBlob, iv } = await processor.encryptChunkForUpload(
  keyManager.getKey(),
  fileChunkBlob,
  0 // chunk index
);

// Get key for sharing via URL fragment
const keyForUrl = await keyManager.exportKeyForUrl();
const shareUrl = `https://example.com/download/token#key=${keyForUrl}`;
```

### Password Mode

```javascript
import { initCrypto } from '@kiora-tech/transfert-crypto';

// Initialize with password
const { engine, keyManager, processor } = await initCrypto('password', 'MySecurePassword123!');

// Salt must be stored with metadata for decryption
const salt = keyManager.getSaltAsBase64Url();
```

### Decrypt

```javascript
import { CryptoEngine, KeyManager, ChunkProcessor } from '@kiora-tech/transfert-crypto';

const engine = new CryptoEngine();
const keyManager = new KeyManager(engine, 'auto');
const processor = new ChunkProcessor(engine);

// Import key from URL fragment
await keyManager.importKeyFromUrl(keyFromUrl);

// Decrypt metadata (verifies HMAC integrity)
const metadata = await engine.decryptMetadata(keyManager.getKey(), encryptedMetadataB64);

// Decrypt each chunk
for (const chunk of encryptedChunks) {
  const decrypted = await processor.decryptDownloadedChunk(keyManager.getKey(), chunk);
}
```

## Architecture

```
src/
├── index.js            # Main entry point, convenience initializer
├── encryption.js       # Core AES-256-GCM engine (encrypt, decrypt, HMAC, PBKDF2)
├── key-manager.js      # Key generation, derivation, import/export lifecycle
├── chunk-processor.js  # Chunked encryption/decryption with IV tracking
├── secure-memory.js    # Memory cleanup utilities for sensitive data
├── secure-logger.js    # Development logging with automatic data sanitization
└── mutex.js            # Async mutex and key consistency guard
```

### Module Responsibilities

| Module | Purpose |
|--------|---------|
| `CryptoEngine` | Core cryptographic operations: AES-256-GCM encrypt/decrypt, PBKDF2 key derivation, HMAC signing/verification, base64 encoding |
| `KeyManager` | Key lifecycle: generate random keys, derive from password, import/export for URL sharing, secure cleanup |
| `ChunkProcessor` | Large file support: encrypt/decrypt individual chunks, track IVs per chunk, calculate size overhead |
| `SecureMemory` | Defense-in-depth: zero buffers, register sensitive data for cleanup on page unload, scoped cleanup |
| `SecureLogger` | Safe debugging: auto-redact keys/passwords/IVs/salts, only log on localhost |
| `AsyncMutex` | Concurrency: prevent race conditions during multi-file encryption initialization |
| `KeyConsistencyGuard` | Safety: prevent key changes during active upload session |

## Encryption Flow

### Upload (Encrypt-then-Upload)

```
Raw File Chunk
  → AES-256-GCM encrypt (random IV per chunk)
  → [IV prefix (12 bytes) + encrypted data + auth tag (16 bytes)]
  → Upload to server

All chunks complete:
  → Build metadata (filename, size, MIME, chunk IVs)
  → HMAC sign metadata (tamper detection)
  → AES-256-GCM encrypt metadata
  → Store encrypted metadata on server
```

### Download (Download-then-Decrypt)

```
Fetch encrypted file + metadata from server
  → Import or derive decryption key
  → Decrypt metadata → Verify HMAC + transfer token binding
  → For each chunk:
    - Extract IV from prefix
    - AES-256-GCM decrypt
    - Verify chunk count integrity
  → Reconstruct original file
  → Trigger browser download
```

## Key Management

### Auto Mode
- Random 256-bit key generated via `crypto.subtle.generateKey()`
- Key exported as base64url and placed in URL fragment (`#key=...`)
- URL fragments are **never sent to the server** (RFC 3986)
- Recipient imports key from URL to decrypt

### Password Mode
- Key derived from password + random salt via PBKDF2 (600,000 iterations)
- Salt stored with encrypted metadata
- Recipient enters password to re-derive the same key

## Browser Support

Requires Web Crypto API (all modern browsers):

| Browser | Minimum Version |
|---------|----------------|
| Chrome | 37+ |
| Firefox | 34+ |
| Safari | 11+ |
| Edge | 79+ |
| Opera | 24+ |

```javascript
import { isCryptoSupported } from '@kiora-tech/transfert-crypto';

if (!isCryptoSupported()) {
  alert('Your browser does not support encryption. Please update.');
}
```

## Security Considerations

1. **IV Uniqueness** — Every chunk gets a unique random IV. Never reuse IVs.
2. **Key in Fragment** — Keys go in URL fragment (`#`), never in query params (`?`).
3. **HTTPS Required** — Encryption is meaningless without secure transport.
4. **Memory Cleanup** — Call `keyManager.clearKey()` when done.
5. **Password Strength** — Use `KeyManager.validatePasswordStrength()` for user feedback.

## API Reference

See [src/index.js](src/index.js) for the main entry point and [examples/](examples/) for usage patterns.

## Testing

```bash
npm install
npm test
```

Or open `examples/test.html` in a browser for interactive testing.

## Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Ensure tests pass
4. Submit a pull request

Security-related contributions are especially valued.

## License

[MIT](LICENSE) — Use freely in any project.

## References

- [Web Crypto API Specification](https://www.w3.org/TR/WebCryptoAPI/)
- [AES-GCM (RFC 5116)](https://tools.ietf.org/html/rfc5116)
- [PBKDF2 (RFC 2898)](https://tools.ietf.org/html/rfc2898)
- [NIST SP 800-38D (GCM)](https://csrc.nist.gov/publications/detail/sp/800-38d/final)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
