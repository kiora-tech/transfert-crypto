/**
 * Key Management Module
 *
 * Manages encryption keys for both automatic and password-based encryption modes.
 * Handles key generation, derivation, storage, and secure cleanup.
 *
 * @module crypto/key-manager
 */

import { CryptoEngine } from './encryption.js';
import { createLogger } from './secure-logger.js';

/**
 * Module logger with automatic sensitive data sanitization
 * @type {SecureLogger}
 */
const logger = createLogger('KeyManager');

/**
 * Encryption modes supported by the application
 * @enum {string}
 */
export const EncryptionMode = {
    /** Automatic encryption with randomly generated key */
    AUTO: 'auto',
    /** Password-based encryption with PBKDF2 key derivation */
    PASSWORD: 'password'
};

/**
 * Key Manager - Handles encryption key lifecycle
 *
 * Supports two encryption modes:
 * - AUTO: Generates random key, shared via URL fragment
 * - PASSWORD: Derives key from user password using PBKDF2
 *
 * @class KeyManager
 */
export class KeyManager {
    /**
     * Create a new KeyManager instance
     *
     * @param {CryptoEngine} cryptoEngine - CryptoEngine instance
     * @param {string} mode - Encryption mode ('auto' or 'password')
     * @throws {Error} If mode is invalid or cryptoEngine is missing
     */
    constructor(cryptoEngine, mode = EncryptionMode.AUTO) {
        if (!(cryptoEngine instanceof CryptoEngine)) {
            throw new Error('Valid CryptoEngine instance required');
        }

        if (!Object.values(EncryptionMode).includes(mode)) {
            throw new Error(`Invalid encryption mode: ${mode}. Use 'auto' or 'password'`);
        }

        /**
         * @private
         * @type {CryptoEngine}
         */
        this.engine = cryptoEngine;

        /**
         * @private
         * @type {string}
         */
        this.mode = mode;

        /**
         * @private
         * @type {CryptoKey|null}
         */
        this.key = null;

        /**
         * @private
         * @type {Uint8Array|null}
         */
        this.salt = null;

        /**
         * @private
         * @type {boolean}
         */
        this.initialized = false;
    }

    /**
     * Generate a random encryption key (AUTO mode)
     *
     * Creates a new AES-256 key using CSPRNG. This key must be shared
     * via URL fragment for recipients to decrypt the file.
     *
     * @returns {Promise<CryptoKey>} Generated encryption key
     * @throws {Error} If key generation fails
     */
    async generateRandomKey() {
        try {
            this.key = await this.engine.generateKey();
            this.mode = EncryptionMode.AUTO;
            this.initialized = true;
            return this.key;
        } catch (error) {
            throw new Error(`Failed to generate random key: ${error.message}`);
        }
    }

    /**
     * Derive encryption key from password (PASSWORD mode)
     *
     * Uses PBKDF2 with 100,000 iterations to derive AES-256 key from password.
     * Salt must be stored with the file metadata for decryption.
     *
     * @param {string} password - User password (minimum recommended: 12 characters)
     * @param {Uint8Array|ArrayBuffer|null} salt - Optional salt (generates new if null)
     * @returns {Promise<{key: CryptoKey, salt: Uint8Array}>} Derived key and salt
     * @throws {Error} If password is empty or derivation fails
     */
    async deriveKeyFromPassword(password, salt = null) {
        try {
            // Validate password strength (basic check)
            if (!password || password.length < 8) {
                throw new Error('Password must be at least 8 characters long');
            }

            // Generate or use existing salt
            if (salt === null) {
                this.salt = this.engine.generateSalt();
            } else {
                this.salt = salt instanceof Uint8Array ? salt : new Uint8Array(salt);
            }

            // Derive key from password
            this.key = await this.engine.deriveKeyFromPassword(password, this.salt);
            this.mode = EncryptionMode.PASSWORD;
            this.initialized = true;

            return {
                key: this.key,
                salt: this.salt
            };
        } catch (error) {
            throw new Error(`Failed to derive key from password: ${error.message}`);
        }
    }

    /**
     * Export key as base64url string for URL fragment
     *
     * Only works for AUTO mode. Password mode keys should not be exported
     * as they're derived from user password.
     *
     * @returns {Promise<string>} Base64url-encoded key
     * @throws {Error} If not initialized, no key, or in PASSWORD mode
     */
    async exportKeyForUrl() {
        if (!this.initialized || !this.key) {
            throw new Error('Key not initialized. Call generateRandomKey() first');
        }

        if (this.mode !== EncryptionMode.AUTO) {
            throw new Error('Cannot export key in PASSWORD mode. Key is derived from password');
        }

        try {
            const exportedKey = await this.engine.exportKeyToUrl(this.key);
            logger.debug('Exported key for URL (sanitized):', exportedKey);

            return exportedKey;
        } catch (error) {
            throw new Error(`Failed to export key: ${error.message}`);
        }
    }

    /**
     * Import key from base64url string (from URL fragment)
     *
     * Used by recipient to decrypt files encrypted in AUTO mode.
     *
     * @param {string} keyString - Base64url-encoded key from URL fragment
     * @returns {Promise<CryptoKey>} Imported encryption key
     * @throws {Error} If import fails or key is invalid
     */
    async importKeyFromUrl(keyString) {
        if (!keyString || typeof keyString !== 'string') {
            throw new Error('Invalid key string');
        }

        try {
            logger.debug('Importing key from URL (sanitized):', keyString);
            this.key = await this.engine.importKeyFromUrl(keyString);

            logger.debug('Key imported successfully');
            this.mode = EncryptionMode.AUTO;
            this.initialized = true;
            return this.key;
        } catch (error) {
            throw new Error(`Failed to import key: ${error.message}`);
        }
    }

    /**
     * Get current encryption key
     *
     * @returns {CryptoKey|null} Current key or null if not initialized
     */
    getKey() {
        return this.key;
    }

    /**
     * Get salt used for password derivation
     *
     * @returns {Uint8Array|null} Salt or null if not in PASSWORD mode
     */
    getSalt() {
        return this.salt;
    }

    /**
     * Get current encryption mode
     *
     * @returns {string} 'auto' or 'password'
     */
    getMode() {
        return this.mode;
    }

    /**
     * Check if key manager is initialized with a key
     *
     * @returns {boolean} True if key is ready for use
     */
    isInitialized() {
        return this.initialized && this.key !== null;
    }

    /**
     * Securely clear key from memory
     *
     * Should be called when encryption/decryption is complete to minimize
     * exposure of key material in memory. Note: Browser may still have
     * key material in internal structures.
     *
     * @returns {void}
     */
    clearKey() {
        if (this.key) {
            // Note: We cannot directly zero out CryptoKey internal data,
            // but we can remove our reference to allow garbage collection
            this.key = null;
        }

        if (this.salt) {
            // Zero out salt
            CryptoEngine.zeroBuffer(this.salt);
            this.salt = null;
        }

        this.initialized = false;
    }

    /**
     * Get salt as base64url string for storage/transmission
     *
     * @returns {string|null} Base64url-encoded salt or null if no salt
     */
    getSaltAsBase64Url() {
        if (!this.salt) {
            return null;
        }
        return this.engine.arrayBufferToBase64Url(this.salt.buffer);
    }

    /**
     * Get salt as standard base64 string (for backend compatibility)
     *
     * @returns {string|null} Base64-encoded salt or null if no salt
     */
    getSaltAsBase64() {
        if (!this.salt) {
            return null;
        }
        // Convert to standard base64 (not base64url)
        const base64url = this.engine.arrayBufferToBase64Url(this.salt.buffer);
        // Convert base64url to standard base64
        return base64url.replace(/-/g, '+').replace(/_/g, '/');
    }

    /**
     * Import salt from base64url string
     *
     * @param {string} saltString - Base64url-encoded salt
     * @returns {Uint8Array} Decoded salt
     * @throws {Error} If salt is invalid
     */
    importSaltFromBase64Url(saltString) {
        if (!saltString || typeof saltString !== 'string') {
            throw new Error('Invalid salt string');
        }

        try {
            this.salt = new Uint8Array(this.engine.base64UrlToArrayBuffer(saltString));

            // Validate salt length
            if (this.salt.length !== CryptoEngine.CONFIG.SALT_LENGTH) {
                throw new Error(`Invalid salt length: expected ${CryptoEngine.CONFIG.SALT_LENGTH} bytes`);
            }

            return this.salt;
        } catch (error) {
            throw new Error(`Failed to import salt: ${error.message}`);
        }
    }

    /**
     * Validate password strength (basic checks)
     *
     * @param {string} password - Password to validate
     * @returns {{valid: boolean, message: string, strength: string}} Validation result
     */
    static validatePasswordStrength(password) {
        const result = {
            valid: false,
            message: '',
            strength: 'weak'
        };

        if (!password || password.length === 0) {
            result.message = 'Password cannot be empty';
            return result;
        }

        if (password.length < 8) {
            result.message = 'Password must be at least 8 characters';
            return result;
        }

        // Calculate strength score
        let score = 0;
        if (password.length >= 12) score++;
        if (password.length >= 16) score++;
        if (/[a-z]/.test(password)) score++;
        if (/[A-Z]/.test(password)) score++;
        if (/[0-9]/.test(password)) score++;
        if (/[^a-zA-Z0-9]/.test(password)) score++;

        if (score < 3) {
            result.strength = 'weak';
            result.message = 'Weak password. Add uppercase, numbers, or symbols';
        } else if (score < 5) {
            result.strength = 'medium';
            result.message = 'Medium strength password';
            result.valid = true;
        } else {
            result.strength = 'strong';
            result.message = 'Strong password';
            result.valid = true;
        }

        return result;
    }

    /**
     * Create a KeyManager instance and initialize with random key (convenience method)
     *
     * @param {CryptoEngine} cryptoEngine - CryptoEngine instance
     * @returns {Promise<KeyManager>} Initialized KeyManager with random key
     */
    static async createWithRandomKey(cryptoEngine) {
        const manager = new KeyManager(cryptoEngine, EncryptionMode.AUTO);
        await manager.generateRandomKey();
        return manager;
    }

    /**
     * Create a KeyManager instance and initialize with password (convenience method)
     *
     * @param {CryptoEngine} cryptoEngine - CryptoEngine instance
     * @param {string} password - User password
     * @param {Uint8Array|null} salt - Optional salt
     * @returns {Promise<KeyManager>} Initialized KeyManager with derived key
     */
    static async createWithPassword(cryptoEngine, password, salt = null) {
        const manager = new KeyManager(cryptoEngine, EncryptionMode.PASSWORD);
        await manager.deriveKeyFromPassword(password, salt);
        return manager;
    }

    /**
     * Create a KeyManager instance and import key from URL fragment
     *
     * @param {CryptoEngine} cryptoEngine - CryptoEngine instance
     * @param {string} keyString - Base64url-encoded key from URL
     * @returns {Promise<KeyManager>} Initialized KeyManager with imported key
     */
    static async createFromUrlKey(cryptoEngine, keyString) {
        const manager = new KeyManager(cryptoEngine, EncryptionMode.AUTO);
        await manager.importKeyFromUrl(keyString);
        return manager;
    }
}
