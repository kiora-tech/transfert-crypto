/**
 * Account key — the indirection between the unlock passphrase and data keys.
 *
 * Key hierarchy (see DESIGN-DECOUPLAGE-IDENTITE-CLES, 2026-06-11):
 *
 *   passphrase ──PBKDF2──► masterKey ──wrap──► K_account ──wrap──► data keys
 *
 * K_account is a random AES-256 key generated once at enrollment and stored
 * server-side ONLY in wrapped form — one envelope per unlock mechanism:
 *   - the passphrase envelope (masterKey wraps K_account)
 *   - the recovery envelope (a key derived from a 240-bit recovery code
 *     wraps K_account); the server should keep it insert-only.
 *
 * What the indirection buys:
 *   - a built-in verifier: unwrapping the envelope with a wrong passphrase
 *     fails the AES-GCM tag check immediately — no more deriving a wrong
 *     key silently and failing much later on data decryption;
 *   - O(1) passphrase rotation: re-wrap one envelope, never the data keys;
 *   - future unlock mechanisms (trusted device, WebAuthn PRF) are just
 *     additional envelopes.
 *
 * Pure crypto: no DOM, no storage, no app constants. The app provides the
 * salt prefix (per-product isolation) and the subject (prefer the immutable
 * OIDC `sub` over email for new enrollments — emails change).
 *
 * Envelope format: a single base64 string with the 12-byte IV prefixed to
 * the AES-GCM ciphertext — the format of `encryptKeyWithKey`/
 * `decryptKeyWithKey` (master-key.js), which also carry the zeroization
 * hardening for every raw intermediate.
 */

import {
    decryptKeyWithKey,
    deriveKeyFromPasswordAndEmail,
    encryptKeyWithKey,
} from './master-key.js';
import {
    generateRecoveryCode,
    normalizeRecoveryCode,
} from './recovery-code.js';

export const ACCOUNT_KEY_VERSION = 'v1-account-key';

// Domain separation: the recovery code must never derive the same key as a
// passphrase that happened to be the same string.
const RECOVERY_SALT_SUFFIX = 'recovery//';

/**
 * Generate a fresh random account key (K_account).
 *
 * Extractable on purpose: wrapping it into envelopes requires exporting its
 * raw bytes (which encryptKeyWithKey zeroizes after use).
 *
 * @returns {Promise<CryptoKey>} AES-GCM 256 key (encrypt/decrypt)
 */
export async function generateAccountKey() {
    return crypto.subtle.generateKey(
        { name: 'AES-GCM', length: 256 },
        true,
        ['encrypt', 'decrypt'],
    );
}

/**
 * Enroll an account: generate K_account and both envelopes.
 *
 * The recovery code is returned ONCE for display — it is never derivable
 * again. The caller persists `passphraseEnvelope` (mutable) and
 * `recoveryEnvelope` (insert-only) server-side, shows `recoveryCode` to the
 * user with an explicit acknowledgement, and keeps `masterKey`/`accountKey`
 * for the session.
 *
 * @param {string} passphrase
 * @param {string} subject    Stable user identifier (OIDC sub preferred)
 * @param {string} saltPrefix Per-product prefix, e.g. 'zerotrust-id-account-v1-'
 * @param {number} [iterations] PBKDF2 override (tests only)
 * @returns {Promise<{accountKey: CryptoKey, masterKey: CryptoKey, passphraseEnvelope: string, recoveryCode: string, recoveryEnvelope: string, version: string}>}
 */
export async function enrollAccount(passphrase, subject, saltPrefix, iterations = undefined) {
    const masterKey = await deriveKeyFromPasswordAndEmail(passphrase, subject, saltPrefix, iterations);
    const accountKey = await generateAccountKey();
    const passphraseEnvelope = await encryptKeyWithKey(masterKey, accountKey);

    const { recoveryCode, recoveryEnvelope } = await issueRecoveryEnvelope(accountKey, subject, saltPrefix, iterations);

    return { accountKey, masterKey, passphraseEnvelope, recoveryCode, recoveryEnvelope, version: ACCOUNT_KEY_VERSION };
}

/**
 * Unlock: derive the master key from the passphrase and unwrap K_account.
 *
 * A wrong passphrase fails the envelope's AES-GCM tag check — this IS the
 * verifier. The failure is rethrown as an Error with
 * `name === 'AccountUnlockError'` so UIs can show "passphrase incorrecte"
 * without string-matching WebCrypto internals.
 *
 * @param {string} passphrase
 * @param {string} subject
 * @param {string} saltPrefix
 * @param {string} passphraseEnvelope
 * @param {number} [iterations]
 * @returns {Promise<{masterKey: CryptoKey, accountKey: CryptoKey}>}
 */
export async function unlockAccount(passphrase, subject, saltPrefix, passphraseEnvelope, iterations = undefined) {
    const masterKey = await deriveKeyFromPasswordAndEmail(passphrase, subject, saltPrefix, iterations);
    try {
        const accountKey = await decryptKeyWithKey(masterKey, passphraseEnvelope);

        return { masterKey, accountKey };
    } catch (cause) {
        const error = new Error('Wrong passphrase: account-key envelope failed authentication');
        error.name = 'AccountUnlockError';
        error.cause = cause;
        throw error;
    }
}

/**
 * Recover K_account from a recovery code (lenient input: any case, with or
 * without dashes — see normalizeRecoveryCode).
 *
 * After a successful recovery the caller MUST rotate: new passphrase
 * envelope (rotatePassphrase) + new recovery envelope (issueRecoveryEnvelope)
 * — a recovery code is single-use by contract.
 *
 * @param {string} recoveryCodeInput
 * @param {string} subject
 * @param {string} saltPrefix
 * @param {string} recoveryEnvelope
 * @param {number} [iterations]
 * @returns {Promise<CryptoKey>} K_account
 */
export async function recoverAccount(recoveryCodeInput, subject, saltPrefix, recoveryEnvelope, iterations = undefined) {
    const normalized = normalizeRecoveryCode(recoveryCodeInput);
    if (null === normalized) {
        const error = new Error('Recovery code contains characters outside the Crockford alphabet');
        error.name = 'AccountUnlockError';
        throw error;
    }

    const recoveryKey = await deriveKeyFromPasswordAndEmail(normalized, subject, saltPrefix + RECOVERY_SALT_SUFFIX, iterations);
    try {
        return await decryptKeyWithKey(recoveryKey, recoveryEnvelope);
    } catch (cause) {
        const error = new Error('Wrong recovery code: account-key envelope failed authentication');
        error.name = 'AccountUnlockError';
        error.cause = cause;
        throw error;
    }
}

/**
 * Rotate the passphrase: re-wrap K_account under a new master key.
 * O(1) — data keys and the recovery envelope are untouched.
 *
 * @param {string} newPassphrase
 * @param {string} subject
 * @param {string} saltPrefix
 * @param {CryptoKey} accountKey
 * @param {number} [iterations]
 * @returns {Promise<{masterKey: CryptoKey, passphraseEnvelope: string}>}
 */
export async function rotatePassphrase(newPassphrase, subject, saltPrefix, accountKey, iterations = undefined) {
    const masterKey = await deriveKeyFromPasswordAndEmail(newPassphrase, subject, saltPrefix, iterations);
    const passphraseEnvelope = await encryptKeyWithKey(masterKey, accountKey);

    return { masterKey, passphraseEnvelope };
}

/**
 * Issue a fresh recovery code + envelope for an existing K_account (initial
 * enrollment, or rotation after a recovery-code use).
 *
 * @param {CryptoKey} accountKey
 * @param {string} subject
 * @param {string} saltPrefix
 * @param {number} [iterations]
 * @returns {Promise<{recoveryCode: string, recoveryEnvelope: string}>}
 */
export async function issueRecoveryEnvelope(accountKey, subject, saltPrefix, iterations = undefined) {
    const recoveryCode = generateRecoveryCode();
    const recoveryKey = await deriveKeyFromPasswordAndEmail(
        // generateRecoveryCode emits the canonical dashed form; the KDF input
        // is the normalized (dash-free) form so lenient re-entry matches.
        /** @type {string} */ (normalizeRecoveryCode(recoveryCode)),
        subject,
        saltPrefix + RECOVERY_SALT_SUFFIX,
        iterations,
    );
    const recoveryEnvelope = await encryptKeyWithKey(recoveryKey, accountKey);

    return { recoveryCode, recoveryEnvelope };
}
