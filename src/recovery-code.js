/**
 * Recovery code primitives (auditable, public).
 *
 * A recovery code is a high-entropy secret the user notes down at
 * registration. Combined with the user's email, it derives a recoveryKey
 * (PBKDF2, same parameters as the master key) that protects an alternate
 * envelope of the user's private key. Lets the password reset flow
 * re-wrap the privateKey under a fresh masterKey without the server
 * ever seeing the recovery code in any form.
 *
 * Format: 30 random bytes encoded in Crockford base32 (no I/L/O/U so the
 * code is harder to misread on paper) and grouped in fours separated by
 * dashes. 30 bytes × 8 / 5 = 48 base32 characters → 12 groups → 240 bits
 * of entropy. That's well past anything an attacker could brute-force.
 *
 *   XKVR-3FA2-9TQH-MBJD-58ZN-RPCV-7WSE-K2GH-4FY8-MNTC-ZB6P-AHKQ
 *
 * Normalization (`normalizeRecoveryCode`) is intentionally lenient: the
 * user can type the code in any case, add or omit dashes, and substitute
 * the visually ambiguous characters that aren't in the Crockford
 * alphabet (`I`/`l` → `1`, `O`/`o` → `0`). The canonical form fed to the
 * KDF is uppercase, dash-free, ambiguity-resolved.
 */

const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'; // Crockford
const RECOVERY_CODE_BYTES = 30;
const GROUP_SIZE = 4;

/**
 * Generate a fresh recovery code with cryptographically random entropy.
 * @returns {string} formatted as `XXXX-XXXX-...`
 */
export function generateRecoveryCode() {
    const bytes = crypto.getRandomValues(new Uint8Array(RECOVERY_CODE_BYTES));
    const encoded = encodeBase32(bytes);
    return groupWithDashes(encoded, GROUP_SIZE);
}

/**
 * Canonicalise a user-typed recovery code so it produces the same KDF
 * output regardless of casing, whitespace, dashes, or visually ambiguous
 * characters. Returns the dash-free uppercase form, or null if any
 * character cannot be unambiguously mapped to the Crockford alphabet.
 *
 * @param {string} input
 * @returns {string|null}
 */
export function normalizeRecoveryCode(input) {
    if (typeof input !== 'string') return null;
    let out = '';
    for (const raw of input) {
        if (raw === '-' || raw === ' ' || raw === '\t' || raw === '\n') continue;
        let c = raw.toUpperCase();
        if (c === 'I' || c === 'L') c = '1';
        if (c === 'O') c = '0';
        if (c === 'U') c = 'V'; // user typed U thinking it's V; either is plausible
        if (!ALPHABET.includes(c)) return null;
        out += c;
    }
    if (out.length === 0) return null;
    return out;
}

function encodeBase32(bytes) {
    // Standard 5-bits-per-char base32 encoding using the Crockford alphabet.
    // No padding — the recovery code is fixed-length so we don't need it.
    let bits = 0;
    let value = 0;
    let out = '';
    for (let i = 0; i < bytes.length; i++) {
        value = (value << 8) | bytes[i];
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            out += ALPHABET[(value >>> bits) & 0x1f];
        }
    }
    if (bits > 0) {
        out += ALPHABET[(value << (5 - bits)) & 0x1f];
    }
    return out;
}

function groupWithDashes(s, n) {
    const parts = [];
    for (let i = 0; i < s.length; i += n) parts.push(s.slice(i, i + n));
    return parts.join('-');
}
