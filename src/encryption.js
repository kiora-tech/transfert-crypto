/**
 * Core Encryption Module - Web Crypto API Implementation
 *
 * Provides AES-256-GCM encryption/decryption for file chunks and metadata
 * using browser's native Web Crypto API for secure, performant operations.
 *
 * @module crypto/encryption
 */

import { createLogger } from './secure-logger.js';

/**
 * Module logger with automatic sensitive data sanitization
 * @type {SecureLogger}
 */
const logger = createLogger('CryptoEngine');

/**
 * Check if Web Crypto API is available in the current environment
 *
 * @returns {boolean} True if crypto.subtle is available
 */
export function isCryptoSupported() {
    return typeof window !== 'undefined' &&
           window.crypto &&
           window.crypto.subtle !== undefined;
}

/**
 * Core cryptographic engine implementing AES-256-GCM encryption
 *
 * Security specifications:
 * - Algorithm: AES-256-GCM (Galois/Counter Mode)
 * - Key Size: 256 bits (32 bytes)
 * - IV/Nonce: 96 bits (12 bytes) - unique per operation
 * - Auth Tag: 128 bits (16 bytes) - built into GCM
 * - PBKDF2: 600,000 iterations with SHA-256 (OWASP 2023)
 *
 * @class CryptoEngine
 */
export class CryptoEngine {
    /**
     * Encryption version identifier for forward compatibility
     * @constant {string}
     */
    static VERSION = 'v2-aes-gcm-256';

    /**
     * AES-GCM configuration constants
     * @constant {Object}
     */
    /**
     * Supported encryption versions for forward/backward compatibility
     * @constant {Object}
     */
    static VERSIONS = {
        'v1-aes-gcm-256': { iterations: 100000 }, // Legacy
        'v2-aes-gcm-256': { iterations: 600000 }  // Current (OWASP 2023)
    };

    static CONFIG = {
        ALGORITHM: 'AES-GCM',
        KEY_LENGTH: 256,        // bits
        IV_LENGTH: 12,          // bytes (96 bits)
        TAG_LENGTH: 128,        // bits (16 bytes)
        PBKDF2_ITERATIONS: 600000, // OWASP 2023 recommendation
        PBKDF2_HASH: 'SHA-256',
        SALT_LENGTH: 16,        // bytes
        HMAC_ALGORITHM: 'SHA-256',
        HMAC_KEY_INFO: 'metadata-integrity-hmac-v1'  // HKDF info for HMAC key derivation
    };

    constructor() {
        if (!isCryptoSupported()) {
            throw new Error('Web Crypto API is not supported in this environment');
        }
    }

    /**
     * Generate a cryptographically secure random AES-256 key
     *
     * @returns {Promise<CryptoKey>} AES-GCM key suitable for encryption/decryption
     * @throws {Error} If key generation fails
     */
    async generateKey() {
        try {
            const key = await crypto.subtle.generateKey(
                {
                    name: CryptoEngine.CONFIG.ALGORITHM,
                    length: CryptoEngine.CONFIG.KEY_LENGTH
                },
                true, // extractable (needed for export)
                ['encrypt', 'decrypt']
            );
            return key;
        } catch (error) {
            throw new Error(`Failed to generate encryption key: ${error.message}`);
        }
    }

    /**
     * Export CryptoKey to base64url string suitable for URL fragments
     *
     * @param {CryptoKey} key - The key to export
     * @returns {Promise<string>} Base64url-encoded key string (URL-safe)
     * @throws {Error} If export fails
     */
    async exportKeyToUrl(key) {
        try {
            const rawKey = await crypto.subtle.exportKey('raw', key);
            return this.arrayBufferToBase64Url(rawKey);
        } catch (error) {
            throw new Error(`Failed to export key: ${error.message}`);
        }
    }

    /**
     * Import CryptoKey from base64url string
     *
     * @param {string} base64Key - Base64url-encoded key string
     * @returns {Promise<CryptoKey>} Imported AES-GCM key
     * @throws {Error} If import fails or key is invalid
     */
    async importKeyFromUrl(base64Key) {
        try {
            const rawKey = this.base64UrlToArrayBuffer(base64Key);

            // Validate key length
            if (rawKey.byteLength !== CryptoEngine.CONFIG.KEY_LENGTH / 8) {
                throw new Error(`Invalid key length: expected ${CryptoEngine.CONFIG.KEY_LENGTH / 8} bytes`);
            }

            const key = await crypto.subtle.importKey(
                'raw',
                rawKey,
                {
                    name: CryptoEngine.CONFIG.ALGORITHM,
                    length: CryptoEngine.CONFIG.KEY_LENGTH
                },
                true,
                ['encrypt', 'decrypt']
            );
            return key;
        } catch (error) {
            throw new Error(`Failed to import key: ${error.message}`);
        }
    }

    /**
     * Encrypt chunk data with AES-256-GCM using a random IV
     *
     * @param {CryptoKey} key - AES-GCM encryption key
     * @param {ArrayBuffer|Uint8Array} chunkData - Raw chunk data to encrypt
     * @returns {Promise<{encryptedData: ArrayBuffer, iv: Uint8Array}>} Encrypted data and IV
     * @throws {Error} If encryption fails
     */
    async encryptChunk(key, chunkData) {
        try {
            // Generate unique IV for this chunk
            const iv = crypto.getRandomValues(new Uint8Array(CryptoEngine.CONFIG.IV_LENGTH));

            // Convert input to ArrayBuffer if needed
            const data = chunkData instanceof ArrayBuffer ? chunkData : chunkData.buffer;

            // Perform AES-GCM encryption
            const encryptedData = await crypto.subtle.encrypt(
                {
                    name: CryptoEngine.CONFIG.ALGORITHM,
                    iv: iv,
                    tagLength: CryptoEngine.CONFIG.TAG_LENGTH
                },
                key,
                data
            );

            return {
                encryptedData,
                iv
            };
        } catch (error) {
            throw new Error(`Failed to encrypt chunk: ${error.message}`);
        }
    }

    /**
     * Decrypt chunk data with AES-256-GCM
     *
     * @param {CryptoKey} key - AES-GCM decryption key
     * @param {ArrayBuffer|Uint8Array} encryptedData - Encrypted chunk data
     * @param {Uint8Array|ArrayBuffer} iv - Initialization vector used for encryption
     * @returns {Promise<ArrayBuffer>} Decrypted chunk data
     * @throws {Error} If decryption fails (wrong key, corrupted data, or tampered)
     */
    async decryptChunk(key, encryptedData, iv) {
        try {
            // Debug logging (sensitive data automatically sanitized)
            logger.debug('decryptChunk - key type:', key?.constructor?.name);
            logger.debug('decryptChunk - encryptedData type:', encryptedData?.constructor?.name);
            logger.debug('decryptChunk - encryptedData length:', encryptedData?.byteLength || encryptedData?.length);
            if (encryptedData instanceof Uint8Array) {
                logger.debug('decryptChunk - encryptedData.byteOffset:', encryptedData.byteOffset);
                logger.debug('decryptChunk - encryptedData.buffer.byteLength:', encryptedData.buffer.byteLength);
            }
            logger.debug('decryptChunk - iv type:', iv?.constructor?.name);
            logger.debug('decryptChunk - iv length:', iv?.length);
            logger.debug('decryptChunk - iv bytes:', iv);

            // Convert inputs to proper formats
            // BUG FIX: If encryptedData is a Uint8Array with an offset, using .buffer
            // will include bytes before the offset (like the IV). We need to copy just the view's data.
            const data = encryptedData instanceof ArrayBuffer ? encryptedData :
                         (encryptedData.byteOffset === 0 && encryptedData.byteLength === encryptedData.buffer.byteLength
                          ? encryptedData.buffer
                          : encryptedData.slice().buffer);
            const ivArray = iv instanceof Uint8Array ? iv : new Uint8Array(iv);

            logger.debug('decryptChunk - data to decrypt length:', data.byteLength);

            // Validate IV length
            if (ivArray.length !== CryptoEngine.CONFIG.IV_LENGTH) {
                throw new Error(`Invalid IV length: expected ${CryptoEngine.CONFIG.IV_LENGTH} bytes`);
            }

            // Perform AES-GCM decryption
            const decryptedData = await crypto.subtle.decrypt(
                {
                    name: CryptoEngine.CONFIG.ALGORITHM,
                    iv: ivArray,
                    tagLength: CryptoEngine.CONFIG.TAG_LENGTH
                },
                key,
                data
            );

            return decryptedData;
        } catch (error) {
            // GCM will throw if authentication fails (wrong key or tampered data)
            throw new Error('Decryption failed: wrong key or corrupted data');
        }
    }

    /**
     * Derive an HMAC key from the encryption key using HKDF
     *
     * This creates a separate key for HMAC to avoid key reuse issues.
     * Uses HKDF with a fixed info string to derive a deterministic HMAC key.
     *
     * @param {CryptoKey} encryptionKey - The main AES-GCM encryption key
     * @returns {Promise<CryptoKey>} HMAC key suitable for signing
     * @throws {Error} If key derivation fails
     */
    async deriveHmacKey(encryptionKey) {
        try {
            // Export the encryption key to use as input key material
            const rawKey = await crypto.subtle.exportKey('raw', encryptionKey);

            // Import as HKDF key material
            const hkdfKey = await crypto.subtle.importKey(
                'raw',
                rawKey,
                'HKDF',
                false,
                ['deriveKey']
            );

            // Derive HMAC key using HKDF
            const hmacKey = await crypto.subtle.deriveKey(
                {
                    name: 'HKDF',
                    hash: CryptoEngine.CONFIG.HMAC_ALGORITHM,
                    salt: new Uint8Array(0), // Empty salt is fine for key derivation from strong key
                    info: new TextEncoder().encode(CryptoEngine.CONFIG.HMAC_KEY_INFO)
                },
                hkdfKey,
                {
                    name: 'HMAC',
                    hash: CryptoEngine.CONFIG.HMAC_ALGORITHM,
                    length: 256
                },
                false,
                ['sign', 'verify']
            );

            return hmacKey;
        } catch (error) {
            throw new Error(`Failed to derive HMAC key: ${error.message}`);
        }
    }

    /**
     * Compute HMAC-SHA256 of data
     *
     * @param {CryptoKey} hmacKey - HMAC key
     * @param {string|ArrayBuffer} data - Data to sign
     * @returns {Promise<ArrayBuffer>} HMAC signature
     */
    async computeHmac(hmacKey, data) {
        const dataBuffer = typeof data === 'string'
            ? new TextEncoder().encode(data)
            : data;

        return await crypto.subtle.sign('HMAC', hmacKey, dataBuffer);
    }

    /**
     * Verify HMAC-SHA256 signature
     *
     * @param {CryptoKey} hmacKey - HMAC key
     * @param {ArrayBuffer} signature - Expected HMAC signature
     * @param {string|ArrayBuffer} data - Data that was signed
     * @returns {Promise<boolean>} True if signature is valid
     */
    async verifyHmac(hmacKey, signature, data) {
        const dataBuffer = typeof data === 'string'
            ? new TextEncoder().encode(data)
            : data;

        return await crypto.subtle.verify('HMAC', hmacKey, signature, dataBuffer);
    }

    /**
     * Constant-time string comparison to prevent timing attacks
     *
     * @param {string} a - First string
     * @param {string} b - Second string
     * @returns {boolean} True if strings are equal
     */
    constantTimeCompare(a, b) {
        if (typeof a !== 'string' || typeof b !== 'string') {
            return false;
        }
        if (a.length !== b.length) {
            return false;
        }
        let result = 0;
        for (let i = 0; i < a.length; i++) {
            result |= a.charCodeAt(i) ^ b.charCodeAt(i);
        }
        return result === 0;
    }

    /**
     * Encrypt metadata object with HMAC integrity protection
     *
     * Includes:
     * - HMAC for tamper detection
     * - Transfer token binding
     * - Chunk count verification
     * - Timestamp for audit
     *
     * @param {CryptoKey} key - AES-GCM encryption key
     * @param {Object} metadata - Metadata object to encrypt
     * @param {string} metadata.originalName - Original filename
     * @param {number} metadata.size - File size in bytes
     * @param {string} metadata.mimeType - MIME type
     * @param {Array<Uint8Array>} metadata.chunkIVs - Array of IVs for each chunk
     * @param {string} [metadata.expiresAt] - Optional ISO expiration timestamp
     * @param {string} [transferToken] - Optional transfer token for binding
     * @returns {Promise<string>} Base64-encoded encrypted metadata with IV prefix
     * @throws {Error} If encryption fails
     */
    async encryptMetadata(key, metadata, transferToken = null) {
        try {
            // Debug: Log key being used (SecureLogger will sanitize sensitive data)
            logger.debug('Encrypting metadata with key:', key);

            // Generate unique key ID for this encryption operation
            const keyId = crypto.randomUUID();

            // Build metadata object with integrity and key lifecycle fields
            const metadataObj = {
                version: CryptoEngine.VERSION,
                originalName: metadata.originalName,
                size: metadata.size,
                mimeType: metadata.mimeType,
                chunkIVs: metadata.chunkIVs.map(iv => this.arrayBufferToBase64Url(iv)),
                // Integrity fields
                chunkCount: metadata.chunkIVs.length,  // Expected chunk count for verification
                createdAt: new Date().toISOString(),   // Timestamp for audit
                transferToken: transferToken || null,   // Bind to specific transfer
                // Key lifecycle metadata for rotation/expiration support
                keyId: keyId,
                expiresAt: metadata.expiresAt || null
            };

            // Compute HMAC over metadata (before adding HMAC field)
            const hmacKey = await this.deriveHmacKey(key);
            const metadataForHmac = JSON.stringify(metadataObj);
            const hmac = await this.computeHmac(hmacKey, metadataForHmac);

            // Add HMAC to metadata
            metadataObj.hmac = this.arrayBufferToBase64Url(hmac);

            // Serialize complete metadata with HMAC
            const metadataJson = JSON.stringify(metadataObj);
            logger.debug('Metadata JSON prepared, length:', metadataJson.length);

            // Convert to ArrayBuffer
            const encoder = new TextEncoder();
            const metadataBuffer = encoder.encode(metadataJson);

            // Encrypt with unique IV
            const { encryptedData, iv } = await this.encryptChunk(key, metadataBuffer);

            logger.debug('Metadata encrypted, IV:', iv);

            // Combine IV + encrypted data
            const combined = new Uint8Array(iv.length + encryptedData.byteLength);
            combined.set(iv, 0);
            combined.set(new Uint8Array(encryptedData), iv.length);

            // Return as base64
            const encrypted = this.arrayBufferToBase64(combined.buffer);
            logger.debug('Encrypted metadata size:', encrypted.length, 'chars');
            return encrypted;
        } catch (error) {
            throw new Error(`Failed to encrypt metadata: ${error.message}`);
        }
    }

    /**
     * Decrypt metadata from base64 string with integrity verification
     *
     * Verifies:
     * - HMAC integrity check
     * - Transfer token binding (if provided)
     * - Version compatibility
     *
     * @param {CryptoKey} key - AES-GCM decryption key
     * @param {string} encryptedMetadataB64 - Base64-encoded encrypted metadata
     * @param {string} [expectedTransferToken] - Optional transfer token to verify binding
     * @returns {Promise<Object>} Decrypted and verified metadata object
     * @throws {Error} If decryption fails, HMAC invalid, or token mismatch
     */
    async decryptMetadata(key, encryptedMetadataB64, expectedTransferToken = null) {
        try {
            // Debug: Log key being used (SecureLogger will sanitize)
            logger.debug('Decrypting metadata with key:', key);
            logger.debug('Encrypted metadata size:', encryptedMetadataB64?.length, 'chars');

            // Decode base64
            const combined = this.base64ToArrayBuffer(encryptedMetadataB64);

            // Split IV and encrypted data
            const iv = new Uint8Array(combined, 0, CryptoEngine.CONFIG.IV_LENGTH);
            const encryptedData = new Uint8Array(combined, CryptoEngine.CONFIG.IV_LENGTH);

            logger.debug('Metadata IV:', iv);
            logger.debug('Attempting decryption...');

            // Decrypt
            const decryptedBuffer = await this.decryptChunk(key, encryptedData, iv);

            logger.debug('Metadata decrypted successfully');

            // Parse JSON
            const decoder = new TextDecoder();
            const metadataJson = decoder.decode(decryptedBuffer);
            const metadata = JSON.parse(metadataJson);

            logger.debug('Metadata JSON parsed, length:', metadataJson.length);

            // Validate version - support both v1 and v2
            if (!CryptoEngine.VERSIONS[metadata.version]) {
                throw new Error(`Unsupported encryption version: ${metadata.version}`);
            }
            logger.debug('Detected encryption version:', metadata.version);

            // INTEGRITY CHECK: Verify HMAC if present (v1+ metadata)
            if (metadata.hmac) {
                logger.debug('Verifying metadata HMAC...');

                // Extract and remove HMAC for verification
                const providedHmac = metadata.hmac;
                const metadataWithoutHmac = { ...metadata };
                delete metadataWithoutHmac.hmac;

                // Recompute HMAC
                const hmacKey = await this.deriveHmacKey(key);
                const metadataForHmac = JSON.stringify(metadataWithoutHmac);
                const expectedHmac = await this.computeHmac(hmacKey, metadataForHmac);
                const expectedHmacB64 = this.arrayBufferToBase64Url(expectedHmac);

                // Constant-time comparison
                if (!this.constantTimeCompare(providedHmac, expectedHmacB64)) {
                    logger.error('HMAC verification failed - possible tampering!');
                    throw new Error('Metadata integrity check failed - possible tampering detected');
                }

                logger.debug('HMAC verification passed');
            } else {
                logger.warn('No HMAC in metadata - older format without integrity protection');
            }

            // TRANSFER BINDING: Verify transfer token if expected
            if (expectedTransferToken !== null) {
                if (metadata.transferToken && metadata.transferToken !== expectedTransferToken) {
                    logger.error('Transfer token mismatch!');
                    throw new Error('Metadata does not belong to this transfer');
                }
            }

            // Convert base64 IVs back to Uint8Array
            metadata.chunkIVs = metadata.chunkIVs.map(ivB64 =>
                new Uint8Array(this.base64UrlToArrayBuffer(ivB64))
            );

            return metadata;
        } catch (error) {
            logger.error('Metadata decryption error:', error?.message || 'Unknown error');
            throw new Error(`Failed to decrypt metadata: ${error.message}`);
        }
    }

    /**
     * Validate that chunk count matches expected metadata
     *
     * @param {number} actualChunkCount - Actual number of chunks received
     * @param {Object} metadata - Decrypted metadata with chunkCount field
     * @throws {Error} If chunk count doesn't match
     */
    validateChunkCount(actualChunkCount, metadata) {
        if (metadata.chunkCount !== undefined && actualChunkCount !== metadata.chunkCount) {
            throw new Error(`Chunk count mismatch: expected ${metadata.chunkCount}, got ${actualChunkCount}`);
        }
        if (actualChunkCount !== metadata.chunkIVs.length) {
            throw new Error(`Chunk count doesn't match IV count: ${actualChunkCount} chunks vs ${metadata.chunkIVs.length} IVs`);
        }
    }

    /**
     * Derive encryption key from password using PBKDF2
     *
     * @param {string} password - User password
     * @param {Uint8Array|ArrayBuffer} salt - Cryptographic salt (16 bytes)
     * @param {string} version - Encryption version for iteration count (default: current version)
     * @returns {Promise<CryptoKey>} Derived AES-GCM key
     * @throws {Error} If derivation fails
     */
    async deriveKeyFromPassword(password, salt, version = CryptoEngine.VERSION) {
        try {
            // Validate inputs
            if (!password || password.length === 0) {
                throw new Error('Password cannot be empty');
            }

            const saltArray = salt instanceof Uint8Array ? salt : new Uint8Array(salt);
            if (saltArray.length !== CryptoEngine.CONFIG.SALT_LENGTH) {
                throw new Error(`Invalid salt length: expected ${CryptoEngine.CONFIG.SALT_LENGTH} bytes`);
            }

            // Import password as key material
            const encoder = new TextEncoder();
            const passwordBuffer = encoder.encode(password);
            const passwordKey = await crypto.subtle.importKey(
                'raw',
                passwordBuffer,
                'PBKDF2',
                false,
                ['deriveBits', 'deriveKey']
            );

            // Zero out password buffer
            passwordBuffer.fill(0);

            // Get iterations from version for backward compatibility
            const versionConfig = CryptoEngine.VERSIONS[version] || CryptoEngine.VERSIONS[CryptoEngine.VERSION];
            const iterations = versionConfig.iterations;
            logger.debug('Deriving key with PBKDF2 iterations:', iterations, 'version:', version);

            // Derive key using PBKDF2
            const derivedKey = await crypto.subtle.deriveKey(
                {
                    name: 'PBKDF2',
                    salt: saltArray,
                    iterations: iterations,
                    hash: CryptoEngine.CONFIG.PBKDF2_HASH
                },
                passwordKey,
                {
                    name: CryptoEngine.CONFIG.ALGORITHM,
                    length: CryptoEngine.CONFIG.KEY_LENGTH
                },
                true,
                ['encrypt', 'decrypt']
            );

            return derivedKey;
        } catch (error) {
            throw new Error(`Failed to derive key from password: ${error.message}`);
        }
    }

    /**
     * Generate cryptographically secure random salt for PBKDF2
     *
     * @returns {Uint8Array} Random 16-byte salt
     */
    generateSalt() {
        return crypto.getRandomValues(new Uint8Array(CryptoEngine.CONFIG.SALT_LENGTH));
    }

    /**
     * Convert ArrayBuffer to base64url string (URL-safe, no padding)
     *
     * @param {ArrayBuffer} buffer - Data to encode
     * @returns {string} Base64url-encoded string
     */
    arrayBufferToBase64Url(buffer) {
        const base64 = this.arrayBufferToBase64(buffer);
        return base64
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');
    }

    /**
     * Convert base64url string to ArrayBuffer
     *
     * @param {string} base64url - Base64url-encoded string
     * @returns {ArrayBuffer} Decoded data
     */
    base64UrlToArrayBuffer(base64url) {
        // Convert base64url to base64
        let base64 = base64url
            .replace(/-/g, '+')
            .replace(/_/g, '/');

        // Add padding
        const padding = '='.repeat((4 - (base64.length % 4)) % 4);
        base64 += padding;

        return this.base64ToArrayBuffer(base64);
    }

    /**
     * Convert ArrayBuffer to standard base64 string
     *
     * @param {ArrayBuffer} buffer - Data to encode
     * @returns {string} Base64-encoded string
     */
    arrayBufferToBase64(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
    }

    /**
     * Convert standard base64 string to ArrayBuffer
     *
     * @param {string} base64 - Base64-encoded string
     * @returns {ArrayBuffer} Decoded data
     */
    base64ToArrayBuffer(base64) {
        const binary = atob(base64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes.buffer;
    }

    /**
     * Securely zero out ArrayBuffer or Uint8Array
     *
     * @param {ArrayBuffer|Uint8Array} buffer - Buffer to clear
     */
    static zeroBuffer(buffer) {
        if (buffer instanceof ArrayBuffer) {
            new Uint8Array(buffer).fill(0);
        } else if (buffer instanceof Uint8Array) {
            buffer.fill(0);
        }
    }
}
