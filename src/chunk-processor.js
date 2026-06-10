/**
 * Chunk Processor Module
 *
 * Handles encryption and decryption of file chunks for chunked upload/download.
 * Manages chunk-specific IVs and prepares encrypted data for network transmission.
 *
 * @module crypto/chunk-processor
 */

import { CryptoEngine } from './encryption.js';
import { createLogger } from './secure-logger.js';

/**
 * Module logger with automatic sensitive data sanitization
 * @type {SecureLogger}
 */
const logger = createLogger('ChunkProcessor');

/**
 * Chunk Processor - Encrypts/decrypts file chunks for upload/download
 *
 * Manages the encryption of large files split into chunks (typically 5MB).
 * Each chunk is encrypted with a unique IV, which is tracked for decryption.
 *
 * Design considerations:
 * - Chunk IVs must be preserved for decryption in correct order
 * - Encrypted chunks include IV prefix for self-contained decryption
 * - Memory efficient: processes one chunk at a time
 * - Performance: targets <500ms for 5MB chunks
 *
 * @class ChunkProcessor
 */
export class ChunkProcessor {
    /**
     * Create a new ChunkProcessor instance
     *
     * @param {CryptoEngine} cryptoEngine - CryptoEngine instance for crypto operations
     * @throws {Error} If cryptoEngine is invalid
     */
    constructor(cryptoEngine) {
        if (!(cryptoEngine instanceof CryptoEngine)) {
            throw new Error('Valid CryptoEngine instance required');
        }

        /**
         * @private
         * @type {CryptoEngine}
         */
        this.engine = cryptoEngine;

        /**
         * Stores IV for each encrypted chunk (indexed by chunk number)
         * @private
         * @type {Map<number, Uint8Array>}
         */
        this.chunkIVs = new Map();

        /**
         * Total number of chunks processed
         * @private
         * @type {number}
         */
        this.totalChunks = 0;
    }

    /**
     * Encrypt a file chunk for upload
     *
     * Encrypts the chunk and stores its IV for metadata. The returned data
     * contains IV prefix + encrypted data + auth tag for self-contained
     * decryption.
     *
     * Memory layout of `encryptedData` (Uint8Array):
     *   [12 bytes IV][N bytes AES-GCM ciphertext + 16-byte auth tag]
     *
     * Callers should prefer `encryptedData` (Uint8Array) for hashing/uploading
     * to avoid the ~5MB Blob→ArrayBuffer round-trip per chunk. `encryptedBlob`
     * is kept as a thin wrapper around the same buffer for backward
     * compatibility with existing call sites.
     *
     * @param {CryptoKey} key - Encryption key
     * @param {Blob} chunkBlob - Raw chunk data as Blob
     * @param {number} chunkIndex - Zero-based chunk index
     * @returns {Promise<{encryptedData: Uint8Array, encryptedBlob: Blob, iv: Uint8Array, size: number}>} Encrypted chunk data
     * @throws {Error} If encryption fails or inputs are invalid
     */
    async encryptChunkForUpload(key, chunkBlob, chunkIndex) {
        try {
            logger.debug('encryptChunkForUpload called for chunk', chunkIndex);

            // Validate inputs
            if (!key) {
                throw new Error('Encryption key is required');
            }

            if (!(chunkBlob instanceof Blob)) {
                throw new Error('Chunk must be a Blob');
            }

            if (typeof chunkIndex !== 'number' || chunkIndex < 0) {
                throw new Error('Invalid chunk index');
            }

            // Convert Blob to ArrayBuffer
            const chunkBuffer = await chunkBlob.arrayBuffer();

            // Encrypt chunk
            const { encryptedData, iv } = await this.engine.encryptChunk(key, chunkBuffer);

            // Store IV for this chunk
            this.chunkIVs.set(chunkIndex, iv);
            this.totalChunks = Math.max(this.totalChunks, chunkIndex + 1);
            logger.debug('Stored IV for chunk', chunkIndex, ', totalChunks now:', this.totalChunks);

            // Combine IV + ciphertext into a single Uint8Array (one allocation).
            // Both `encryptedData` and `encryptedBlob` view the same underlying
            // buffer, so there is no extra copy for backward-compatible callers.
            const combined = new Uint8Array(iv.length + encryptedData.byteLength);
            combined.set(iv, 0);
            combined.set(new Uint8Array(encryptedData), iv.length);

            const encryptedBlob = new Blob([combined], { type: 'application/octet-stream' });

            return {
                encryptedData: combined,
                encryptedBlob,
                iv,
                size: combined.byteLength
            };
        } catch (error) {
            throw new Error(`Failed to encrypt chunk ${chunkIndex}: ${error.message}`);
        }
    }

    /**
     * Decrypt a downloaded chunk
     *
     * Extracts IV from chunk prefix and decrypts the remaining data.
     *
     * @param {CryptoKey} key - Decryption key
     * @param {Blob|ArrayBuffer} encryptedChunkWithIV - Encrypted chunk with IV prefix
     * @returns {Promise<ArrayBuffer>} Decrypted chunk data
     * @throws {Error} If decryption fails or data is corrupted
     */
    async decryptDownloadedChunk(key, encryptedChunkWithIV) {
        try {
            // Validate inputs
            if (!key) {
                throw new Error('Decryption key is required');
            }

            // Convert to ArrayBuffer if needed
            let chunkBuffer;
            if (encryptedChunkWithIV instanceof Blob) {
                chunkBuffer = await encryptedChunkWithIV.arrayBuffer();
            } else if (encryptedChunkWithIV instanceof ArrayBuffer) {
                chunkBuffer = encryptedChunkWithIV;
            } else {
                throw new Error('Invalid chunk data type');
            }

            // Validate minimum size (IV + at least some data)
            const ivLength = CryptoEngine.CONFIG.IV_LENGTH;
            if (chunkBuffer.byteLength <= ivLength) {
                throw new Error('Chunk data too small or corrupted');
            }

            // Extract IV and encrypted data
            const iv = new Uint8Array(chunkBuffer, 0, ivLength);
            const encryptedData = new Uint8Array(chunkBuffer, ivLength);

            // Decrypt chunk
            const decryptedData = await this.engine.decryptChunk(key, encryptedData, iv);

            return decryptedData;
        } catch (error) {
            throw new Error(`Failed to decrypt chunk: ${error.message}`);
        }
    }

    /**
     * Decrypt chunk with explicit IV (for metadata-driven decryption)
     *
     * Use this when IVs are stored separately in metadata rather than
     * prefixed to each chunk.
     *
     * @param {CryptoKey} key - Decryption key
     * @param {Blob|ArrayBuffer} encryptedChunk - Encrypted chunk (no IV prefix)
     * @param {Uint8Array} iv - Initialization vector for this chunk
     * @returns {Promise<ArrayBuffer>} Decrypted chunk data
     * @throws {Error} If decryption fails
     */
    async decryptChunkWithIV(key, encryptedChunk, iv) {
        try {
            // Validate inputs
            if (!key) {
                throw new Error('Decryption key is required');
            }

            if (!iv || iv.length !== CryptoEngine.CONFIG.IV_LENGTH) {
                throw new Error('Valid IV is required');
            }

            // Convert to ArrayBuffer if needed
            let chunkBuffer;
            if (encryptedChunk instanceof Blob) {
                chunkBuffer = await encryptedChunk.arrayBuffer();
            } else if (encryptedChunk instanceof ArrayBuffer) {
                chunkBuffer = encryptedChunk;
            } else {
                throw new Error('Invalid chunk data type');
            }

            // Decrypt chunk
            const decryptedData = await this.engine.decryptChunk(key, chunkBuffer, iv);

            return decryptedData;
        } catch (error) {
            throw new Error(`Failed to decrypt chunk with IV: ${error.message}`);
        }
    }

    /**
     * Prepare encrypted blob by combining IV + encrypted data
     *
     * Creates a single Blob containing:
     * [12 bytes IV][N bytes encrypted data + auth tag]
     *
     * @param {Uint8Array} iv - Initialization vector
     * @param {ArrayBuffer} encryptedData - Encrypted chunk data
     * @returns {Blob} Combined blob ready for upload
     */
    prepareEncryptedBlob(iv, encryptedData) {
        // Combine IV and encrypted data into single blob
        const combined = new Uint8Array(iv.length + encryptedData.byteLength);
        combined.set(iv, 0);
        combined.set(new Uint8Array(encryptedData), iv.length);

        return new Blob([combined], { type: 'application/octet-stream' });
    }

    /**
     * Get all chunk IVs in order (for metadata storage)
     *
     * Returns IVs sorted by chunk index for storage in file metadata.
     * These IVs are required for decryption.
     *
     * @returns {Array<Uint8Array>} Ordered array of IVs
     */
    getChunkIVs() {
        const ivs = [];
        for (let i = 0; i < this.totalChunks; i++) {
            const iv = this.chunkIVs.get(i);
            if (!iv) {
                throw new Error(`Missing IV for chunk ${i}`);
            }
            ivs.push(iv);
        }
        return ivs;
    }

    /**
     * Get IV for specific chunk
     *
     * @param {number} chunkIndex - Chunk index
     * @returns {Uint8Array|undefined} IV for the chunk or undefined if not found
     */
    getChunkIV(chunkIndex) {
        return this.chunkIVs.get(chunkIndex);
    }

    /**
     * Set IV for specific chunk (for import/restore)
     *
     * @param {number} chunkIndex - Chunk index
     * @param {Uint8Array} iv - Initialization vector
     * @throws {Error} If inputs are invalid
     */
    setChunkIV(chunkIndex, iv) {
        if (typeof chunkIndex !== 'number' || chunkIndex < 0) {
            throw new Error('Invalid chunk index');
        }

        if (!(iv instanceof Uint8Array) || iv.length !== CryptoEngine.CONFIG.IV_LENGTH) {
            throw new Error('Invalid IV');
        }

        this.chunkIVs.set(chunkIndex, iv);
        this.totalChunks = Math.max(this.totalChunks, chunkIndex + 1);
    }

    /**
     * Import chunk IVs from array (for decryption)
     *
     * @param {Array<Uint8Array>} ivs - Array of IVs in chunk order
     * @throws {Error} If IVs are invalid
     */
    importChunkIVs(ivs) {
        if (!Array.isArray(ivs)) {
            throw new Error('IVs must be an array');
        }

        this.clearChunkIVs();

        ivs.forEach((iv, index) => {
            if (!(iv instanceof Uint8Array) || iv.length !== CryptoEngine.CONFIG.IV_LENGTH) {
                throw new Error(`Invalid IV at index ${index}`);
            }
            this.chunkIVs.set(index, iv);
        });

        this.totalChunks = ivs.length;
    }

    /**
     * Get total number of chunks processed
     *
     * @returns {number} Total chunks
     */
    getTotalChunks() {
        return this.totalChunks;
    }

    /**
     * Check if all chunk IVs are present (validation)
     *
     * @returns {boolean} True if all IVs from 0 to totalChunks-1 are present
     */
    hasAllChunkIVs() {
        for (let i = 0; i < this.totalChunks; i++) {
            if (!this.chunkIVs.has(i)) {
                return false;
            }
        }
        return true;
    }

    /**
     * Clear all stored chunk IVs
     *
     * Call this when starting a new file upload/download to reset state.
     *
     * @returns {void}
     */
    clearChunkIVs() {
        // Zero out IVs before clearing
        this.chunkIVs.forEach(iv => {
            CryptoEngine.zeroBuffer(iv);
        });

        this.chunkIVs.clear();
        this.totalChunks = 0;
    }

    /**
     * Calculate encrypted chunk size overhead
     *
     * Each encrypted chunk is larger than original due to IV prefix and auth tag.
     * - IV: 12 bytes
     * - Auth tag: 16 bytes (GCM)
     *
     * @param {number} originalChunkSize - Original chunk size in bytes
     * @returns {number} Encrypted chunk size in bytes
     */
    static calculateEncryptedChunkSize(originalChunkSize) {
        const overhead = CryptoEngine.CONFIG.IV_LENGTH + (CryptoEngine.CONFIG.TAG_LENGTH / 8);
        return originalChunkSize + overhead;
    }

    /**
     * Calculate original chunk size from encrypted chunk
     *
     * @param {number} encryptedChunkSize - Encrypted chunk size in bytes
     * @returns {number} Original chunk size in bytes
     */
    static calculateOriginalChunkSize(encryptedChunkSize) {
        const overhead = CryptoEngine.CONFIG.IV_LENGTH + (CryptoEngine.CONFIG.TAG_LENGTH / 8);
        return encryptedChunkSize - overhead;
    }

    /**
     * Estimate total encrypted file size
     *
     * @param {number} originalFileSize - Original file size in bytes
     * @param {number} chunkSize - Chunk size in bytes (e.g., 5MB)
     * @returns {number} Estimated encrypted file size in bytes
     */
    static estimateEncryptedFileSize(originalFileSize, chunkSize) {
        const numChunks = Math.ceil(originalFileSize / chunkSize);
        const overhead = CryptoEngine.CONFIG.IV_LENGTH + (CryptoEngine.CONFIG.TAG_LENGTH / 8);
        return originalFileSize + (numChunks * overhead);
    }

    /**
     * Validate chunk encryption integrity
     *
     * Checks if chunk can be encrypted/decrypted properly for testing.
     *
     * @param {CryptoKey} key - Test key
     * @param {Blob} testChunk - Test chunk data
     * @returns {Promise<boolean>} True if encryption round-trip succeeds
     */
    async validateChunkEncryption(key, testChunk) {
        try {
            // Encrypt
            const { encryptedBlob, iv } = await this.encryptChunkForUpload(key, testChunk, 0);

            // Decrypt
            const decryptedBuffer = await this.decryptDownloadedChunk(key, encryptedBlob);

            // Compare with original
            const originalBuffer = await testChunk.arrayBuffer();
            if (decryptedBuffer.byteLength !== originalBuffer.byteLength) {
                return false;
            }

            const original = new Uint8Array(originalBuffer);
            const decrypted = new Uint8Array(decryptedBuffer);

            for (let i = 0; i < original.length; i++) {
                if (original[i] !== decrypted[i]) {
                    return false;
                }
            }

            return true;
        } catch (error) {
            logger.error('Chunk encryption validation failed:', error?.message || 'Unknown error');
            return false;
        }
    }

    /**
     * Get encryption statistics
     *
     * @returns {Object} Statistics about chunk processing
     */
    getStats() {
        return {
            totalChunks: this.totalChunks,
            ivsStored: this.chunkIVs.size,
            allIVsPresent: this.hasAllChunkIVs(),
            overheadPerChunk: CryptoEngine.CONFIG.IV_LENGTH + (CryptoEngine.CONFIG.TAG_LENGTH / 8)
        };
    }
}
