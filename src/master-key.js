/**
 * Master Key Module
 *
 * Derives a deterministic master key from the user's password + email.
 * This master key encrypts/decrypts per-document AES keys.
 * Same password + email = same master key on any device.
 */

// =============================================================================
// === LIB BOUNDARY (auditable, public) ========================================
// Everything between this marker and "APP COMPOSITION" below is pure crypto
// glue (PBKDF2 / AES-GCM / Web Crypto API). It is the surface that should
// land in the public `kiora-tech/transfert-crypto` repo. The functions accept
// every app-tunable parameter explicitly — no hardcoded constants.
// =============================================================================

const PBKDF2_ITERATIONS = 600000;

/**
 * Derive a deterministic AES-GCM-256 key from a password + email + salt prefix.
 * Same inputs always produce the same key — usable as a per-user master key.
 *
 * @param {string} password
 * @param {string} email
 * @param {string} saltPrefix    e.g. "your-app-master-key-v1-"
 * @param {number} [iterations=600000]
 * @returns {Promise<CryptoKey>} AES-GCM-256 CryptoKey, extractable, usable for encrypt/decrypt
 */
export async function deriveKeyFromPasswordAndEmail(password, email, saltPrefix, iterations = PBKDF2_ITERATIONS) {
    const saltStr = saltPrefix + email.toLowerCase().trim();
    const salt = new TextEncoder().encode(saltStr);
    const passwordBytes = new TextEncoder().encode(password);

    const keyMaterial = await crypto.subtle.importKey('raw', passwordBytes, 'PBKDF2', false, ['deriveKey']);

    return crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        true,
        ['encrypt', 'decrypt'],
    );
}

/**
 * Wrap an AES key under another AES key using AES-GCM-256.
 * Output: base64 string of [12-byte IV][ciphertext+16-byte tag].
 */
export async function encryptKeyWithKey(wrappingKey, keyToWrap) {
    const raw = await crypto.subtle.exportKey('raw', keyToWrap);
    const iv = crypto.getRandomValues(new Uint8Array(12));

    const encrypted = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv, tagLength: 128 },
        wrappingKey,
        raw,
    );

    const combined = new Uint8Array(iv.length + encrypted.byteLength);
    combined.set(iv);
    combined.set(new Uint8Array(encrypted), iv.length);

    return btoa(String.fromCharCode(...combined));
}

/**
 * Unwrap an AES key wrapped via {@link encryptKeyWithKey}.
 */
export async function decryptKeyWithKey(wrappingKey, encryptedB64) {
    const combined = Uint8Array.from(atob(encryptedB64), c => c.charCodeAt(0));
    const iv = combined.slice(0, 12);
    const ciphertext = combined.slice(12);

    const raw = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv, tagLength: 128 },
        wrappingKey,
        ciphertext,
    );

    return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
}

/**
 * Export a CryptoKey as base64url string (for share URL fragments).
 */
export async function exportKeyAsB64Url(key) {
    const raw = await crypto.subtle.exportKey('raw', key);
    return btoa(String.fromCharCode(...new Uint8Array(raw)))
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

// =============================================================================
// Original master-key.js LIB portion. Public auditable surface — see https://github.com/kiora-tech/transfert-crypto
