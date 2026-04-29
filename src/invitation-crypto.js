/**
 * Invitation Crypto Module
 *
 * =============================================================================
 * === LIB BOUNDARY (auditable, public) ========================================
 * THIS WHOLE FILE is pure crypto: no DOM, no sessionStorage, no app-specific
 * constants. It is the surface that should land in the public
 * `kiora-tech/transfert-crypto` repo as `invitation-crypto.js`. See
 * `CRYPTO_LIB.md`.
 * =============================================================================
 *
 * Helpers used by the invitation create/accept flows. Wraps a vault AES key
 * using a passphrase known only to the inviter and the invitee. The
 * passphrase is shared out-of-band (Signal, phone, in person) so the link
 * itself is not enough to access the vault.
 *
 * Style mirrors `keypair.js` (base64 helpers, AES-GCM 256, 12-byte IV) and
 * `master-key.js` (PBKDF2-SHA256 with 600 000 iterations).
 *
 * Wrap chain (inviter):
 *   passphrase + 16-byte salt
 *   -> PBKDF2-SHA256 600k iterations
 *   -> AES-GCM 256 derived "wrap-key"
 *   -> AES-GCM encrypt(rawVaultKeyBytes, wrapKey, 12-byte iv)
 *   -> wrappedVaultKey
 *
 * Unwrap chain (invitee):
 *   passphrase + passphraseSalt
 *   -> derive same wrap-key
 *   -> AES-GCM decrypt(wrappedVaultKey, wrapKey, passphraseIv)
 *   -> raw vault key bytes
 *   -> import as AES-GCM CryptoKey
 *
 * If the passphrase is wrong, AES-GCM throws an OperationError (tag
 * mismatch); the caller surfaces that as "Passphrase invalide.".
 */

const PBKDF2_ITERATIONS = 600000;
const PBKDF2_HASH = 'SHA-256';
const AES_PARAMS = { name: 'AES-GCM', length: 256 };
const SALT_LENGTH = 16;
const IV_LENGTH = 12;

// ---------- base64 helpers (match keypair.js style) ----------

function bytesToB64(bytes) {
    return btoa(String.fromCharCode(...new Uint8Array(bytes)));
}

function b64ToBytes(b64) {
    return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
}

// ---------- passphrase derivation ----------

/**
 * Derive a wrap-key from a passphrase + salt with PBKDF2.
 * Same iteration count as `master-key.js` so users perceive a similar latency.
 *
 * @param {string} passphrase
 * @param {Uint8Array} salt - 16 bytes recommended
 * @returns {Promise<CryptoKey>} AES-GCM 256 CryptoKey usable for encrypt/decrypt
 */
async function deriveWrapKey(passphrase, salt) {
    const passphraseBytes = new TextEncoder().encode(passphrase);

    const keyMaterial = await crypto.subtle.importKey(
        'raw',
        passphraseBytes,
        'PBKDF2',
        false,
        ['deriveKey'],
    );

    return crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt, iterations: PBKDF2_ITERATIONS, hash: PBKDF2_HASH },
        keyMaterial,
        AES_PARAMS,
        false, // non-extractable: only used for wrap/unwrap inside this module
        ['encrypt', 'decrypt'],
    );
}

// ---------- public API ----------

/**
 * Wrap a vault AES-GCM CryptoKey with a passphrase.
 *
 * Generates a fresh random salt (16 bytes) and IV (12 bytes), derives a
 * wrap-key with PBKDF2, exports the vault key as raw bytes, then AES-GCM
 * encrypts those bytes with the wrap-key.
 *
 * @param {CryptoKey} vaultKey - The unwrapped vault AES-GCM key (must be extractable)
 * @param {string} passphrase
 * @returns {Promise<{passphraseSalt: string, passphraseIv: string, wrappedVaultKey: string}>}
 *          All fields are standard base64.
 */
export async function wrapVaultKeyWithPassphrase(vaultKey, passphrase) {
    if (!vaultKey) throw new Error('vaultKey is required');
    if (!passphrase) throw new Error('passphrase is required');

    const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
    const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));

    const wrapKey = await deriveWrapKey(passphrase, salt);
    const rawVaultKey = await crypto.subtle.exportKey('raw', vaultKey);

    const wrapped = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv, tagLength: 128 },
        wrapKey,
        rawVaultKey,
    );

    return {
        passphraseSalt: bytesToB64(salt),
        passphraseIv: bytesToB64(iv),
        wrappedVaultKey: bytesToB64(wrapped),
    };
}

/**
 * Unwrap a wrappedVaultKey produced by `wrapVaultKeyWithPassphrase`.
 *
 * @param {{passphraseSalt: string, passphraseIv: string, wrappedVaultKey: string}} material
 *        All fields base64, exactly as returned by `wrapVaultKeyWithPassphrase`
 *        and forwarded by the server.
 * @param {string} passphrase
 * @returns {Promise<CryptoKey>} The unwrapped vault AES-GCM 256 key (extractable).
 * @throws {Error} If the passphrase is wrong (AES-GCM tag mismatch) or material is malformed.
 */
export async function unwrapVaultKeyWithPassphrase(material, passphrase) {
    if (!material || !material.passphraseSalt || !material.passphraseIv || !material.wrappedVaultKey) {
        throw new Error('material missing one of {passphraseSalt, passphraseIv, wrappedVaultKey}');
    }
    if (!passphrase) throw new Error('passphrase is required');

    const salt = b64ToBytes(material.passphraseSalt);
    const iv = b64ToBytes(material.passphraseIv);
    const wrapped = b64ToBytes(material.wrappedVaultKey);

    const wrapKey = await deriveWrapKey(passphrase, salt);

    const rawVaultKey = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv, tagLength: 128 },
        wrapKey,
        wrapped,
    );

    return crypto.subtle.importKey(
        'raw',
        rawVaultKey,
        AES_PARAMS,
        true, // extractable so it can be re-wrapped with the user's RSA pubkey
        ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'],
    );
}
