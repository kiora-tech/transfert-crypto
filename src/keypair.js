/**
 * Keypair Module
 *
 * Handles per-user RSA-OAEP-2048 keypairs (Web Crypto API only, no extra deps).
 *
 * =============================================================================
 * === LIB BOUNDARY (auditable, public) ========================================
 * THIS WHOLE FILE is pure crypto: no DOM, no sessionStorage, no app-specific
 * constants. It is the surface that should land in the public
 * `kiora-tech/transfert-crypto` repo as `keypair.js`. See `CRYPTO_LIB.md`.
 * =============================================================================
 *
 * Flow:
 * - Register: generate keypair -> encrypt private key with master key -> POST to /api/keys
 * - Login: master key already in sessionStorage; private key fetched + decrypted on demand
 * - Wrap vault AES key for a recipient using their public key (envelope encryption)
 *
 * Style mirrors `master-key.js`:
 * - Web Crypto API only
 * - Base64 (standard) for server transport, base64url helper for URL fragments
 * - AES-GCM 256 with 12-byte IV for symmetric envelope (consistent with encryptDocKey)
 */

export const KEYPAIR_VERSION = 'v1-rsa-oaep-2048';

const RSA_PARAMS = {
    name: 'RSA-OAEP',
    modulusLength: 2048,
    publicExponent: new Uint8Array([1, 0, 1]),
    hash: 'SHA-256',
};

const AES_PARAMS = { name: 'AES-GCM', length: 256 };

// ---------- base64 helpers (match master-key.js style) ----------

function bytesToB64(bytes) {
    return btoa(String.fromCharCode(...new Uint8Array(bytes)));
}

function b64ToBytes(b64) {
    return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
}

// ---------- keypair generation / export / import ----------

/**
 * Generate a fresh RSA-OAEP-2048 keypair.
 * Extractable so the private key can be wrapped with the master key for storage.
 */
export async function generateKeypair() {
    return crypto.subtle.generateKey(
        RSA_PARAMS,
        true, // extractable
        ['wrapKey', 'unwrapKey', 'encrypt', 'decrypt'],
    );
}

/**
 * Export a public key as base64 SPKI (the format the server stores in clear).
 */
export async function exportPublicKey(pubKey) {
    const spki = await crypto.subtle.exportKey('spki', pubKey);
    return bytesToB64(spki);
}

/**
 * Import a base64 SPKI public key, ready to wrap AES keys / encrypt for the recipient.
 */
export async function importPublicKey(spkiB64) {
    const spki = b64ToBytes(spkiB64);
    return crypto.subtle.importKey(
        'spki',
        spki,
        { name: 'RSA-OAEP', hash: 'SHA-256' },
        true,
        ['wrapKey', 'encrypt'],
    );
}

// ---------- private key envelope (encrypt with master key) ----------

/**
 * Encrypt the private key with the master key.
 * Returns { encryptedPrivateKey, iv } as separate base64 fields (per the contract).
 *
 * Uses AES-GCM 256 with a 12-byte IV. The ciphertext blob does NOT prepend the IV
 * because the server stores them in distinct columns (privateKeyIv).
 *
 * The exported pkcs8 private key bytes are zeroed in a `try/finally` after the
 * AES-GCM encrypt has consumed them. Best-effort: V8 may have copied the buffer,
 * but this lowers the heap exposure window. Pattern mirrors `SecureMemory.zeroBuffer` in `secure-memory.js`.zeroBuffer (line 1013).
 */
export async function exportPrivateKeyEncrypted(privKey, masterKey) {
    const pkcs8 = await crypto.subtle.exportKey('pkcs8', privKey);
    const iv = crypto.getRandomValues(new Uint8Array(12));

    try {
        const ciphertext = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv, tagLength: 128 },
            masterKey,
            pkcs8,
        );

        return {
            encryptedPrivateKey: bytesToB64(ciphertext),
            iv: bytesToB64(iv),
        };
    } finally {
        // ArrayBuffer needs a Uint8Array view to .fill — pkcs8 contains the
        // raw private key material, every bit as sensitive as a `raw` AES key.
        new Uint8Array(pkcs8).fill(0);
    }
}

/**
 * Decrypt and re-import a private key previously stored via exportPrivateKeyEncrypted.
 * Imports as RSA-OAEP with key usages for unwrapping vault keys / decrypting payloads.
 *
 * The decrypted pkcs8 bytes are zeroed in a `try/finally` after importKey
 * consumes them. Best-effort, same V8 caveat as `exportPrivateKeyEncrypted`.
 */
export async function importEncryptedPrivateKey(encryptedB64, ivB64, masterKey) {
    const ciphertext = b64ToBytes(encryptedB64);
    const iv = b64ToBytes(ivB64);

    const pkcs8 = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv, tagLength: 128 },
        masterKey,
        ciphertext,
    );

    try {
        return await crypto.subtle.importKey(
            'pkcs8',
            pkcs8,
            { name: 'RSA-OAEP', hash: 'SHA-256' },
            true,
            ['unwrapKey', 'decrypt'],
        );
    } finally {
        new Uint8Array(pkcs8).fill(0);
    }
}

// ---------- AES key wrap / unwrap with RSA-OAEP envelope ----------

/**
 * Wrap an AES vault/document key with a recipient's public key.
 * Returns base64 ciphertext. Uses subtle.wrapKey raw format so the unwrap side
 * gets a CryptoKey directly, not raw bytes.
 */
export async function wrapAesKey(aesKey, recipientPublicKey) {
    const wrapped = await crypto.subtle.wrapKey(
        'raw',
        aesKey,
        recipientPublicKey,
        { name: 'RSA-OAEP' },
    );
    return bytesToB64(wrapped);
}

/**
 * Unwrap a base64 RSA-OAEP-wrapped AES-GCM 256 key with the local private key.
 * Returns an extractable CryptoKey suitable for encrypt/decrypt.
 */
export async function unwrapAesKey(wrappedB64, recipientPrivateKey) {
    const wrapped = b64ToBytes(wrappedB64);
    return crypto.subtle.unwrapKey(
        'raw',
        wrapped,
        recipientPrivateKey,
        { name: 'RSA-OAEP' },
        AES_PARAMS,
        true,
        ['encrypt', 'decrypt'],
    );
}
