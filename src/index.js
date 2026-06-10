/**
 * Crypto Module - End-to-End Encryption for File Transfers
 *
 * Main entry point for encryption functionality using Web Crypto API.
 * Provides AES-256-GCM encryption for file chunks with support for
 * both automatic (random key) and password-based encryption modes.
 *
 * @module crypto
 */

// Import for internal use
import { CryptoEngine, isCryptoSupported } from './encryption.js';
import { KeyManager, EncryptionMode } from './key-manager.js';
import { ChunkProcessor } from './chunk-processor.js';
import { AsyncMutex, AsyncSemaphore, KeyConsistencyGuard } from './mutex.js';
import { SecureMemory, SecureBuffer, withSecureCleanup } from './secure-memory.js';

// Re-export for external use
export { CryptoEngine, isCryptoSupported };
export { KeyManager, EncryptionMode };
export { ChunkProcessor };
export { AsyncMutex, AsyncSemaphore, KeyConsistencyGuard };
export { SecureMemory, SecureBuffer, withSecureCleanup };

// v2: identity envelope helpers (per-user keypair + passphrase wrap +
// password-derived master key). These are pure crypto primitives — no DOM,
// no storage, no app-specific constants. The consuming app provides the
// salt prefix and storage keys.
//
// Written as import-then-export (not `export ... from`) on purpose: Symfony
// Asset Mapper's import scanner only follows `import` statements, so bare
// re-exports would leave these modules out of the compiled importmap (404 in
// prod).
import {
    deriveKeyFromPasswordAndEmail,
    encryptKeyWithKey,
    decryptKeyWithKey,
    exportKeyAsB64Url,
} from './master-key.js';
import {
    KEYPAIR_VERSION,
    generateKeypair,
    exportPublicKey,
    importPublicKey,
    exportPrivateKeyEncrypted,
    importEncryptedPrivateKey,
    wrapAesKey,
    unwrapAesKey,
} from './keypair.js';
import {
    wrapVaultKeyWithPassphrase,
    unwrapVaultKeyWithPassphrase,
} from './invitation-crypto.js';
import {
    generateRecoveryCode,
    normalizeRecoveryCode,
} from './recovery-code.js';

export {
    deriveKeyFromPasswordAndEmail,
    encryptKeyWithKey,
    decryptKeyWithKey,
    exportKeyAsB64Url,
};
export {
    KEYPAIR_VERSION,
    generateKeypair,
    exportPublicKey,
    importPublicKey,
    exportPrivateKeyEncrypted,
    importEncryptedPrivateKey,
    wrapAesKey,
    unwrapAesKey,
};
export {
    wrapVaultKeyWithPassphrase,
    unwrapVaultKeyWithPassphrase,
};
export {
    generateRecoveryCode,
    normalizeRecoveryCode,
};

/**
 * Quick start helper - Create fully initialized crypto system
 *
 * @param {string} mode - Encryption mode: 'auto' or 'password'
 * @param {string|null} password - Password (required for 'password' mode)
 * @returns {Promise<{engine: CryptoEngine, keyManager: KeyManager, processor: ChunkProcessor}>}
 * @throws {Error} If initialization fails
 *
 * @example
 * // Auto mode with random key
 * const { engine, keyManager, processor } = await initCrypto('auto');
 * const keyForUrl = await keyManager.exportKeyForUrl();
 *
 * @example
 * // Password mode
 * const { engine, keyManager, processor } = await initCrypto('password', 'mySecurePass123');
 * const salt = keyManager.getSaltAsBase64Url();
 */
export async function initCrypto(mode = 'auto', password = null) {
    // Check browser support
    if (!isCryptoSupported()) {
        throw new Error('Web Crypto API is not supported in this browser');
    }

    // Create engine
    const engine = new CryptoEngine();

    // Create key manager - use already imported class
    const keyManager = new KeyManager(engine, mode);

    // Initialize key based on mode
    if (mode === 'password') {
        if (!password) {
            throw new Error('Password required for password mode');
        }
        await keyManager.deriveKeyFromPassword(password);
    } else {
        await keyManager.generateRandomKey();
    }

    // Create chunk processor - use already imported class
    const processor = new ChunkProcessor(engine);

    return {
        engine,
        keyManager,
        processor
    };
}

/**
 * Version information
 * @constant {string}
 */
export const VERSION = '2.1.2';

/**
 * Encryption specifications for reference
 * @constant {Object}
 */
export const CRYPTO_SPECS = {
    algorithm: 'AES-256-GCM',
    keyLength: 256,
    ivLength: 12,
    tagLength: 16,
    pbkdf2Iterations: 100000,
    pbkdf2Hash: 'SHA-256',
    version: 'v1-aes-gcm-256'
};
