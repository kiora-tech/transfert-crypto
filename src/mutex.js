/**
 * Mutex - Simple async mutex implementation for JavaScript
 *
 * Provides mutual exclusion for asynchronous operations to prevent race conditions.
 * Used to ensure single initialization of encryption system when multiple files
 * are added simultaneously.
 *
 * @module crypto/mutex
 */

import { createLogger } from './secure-logger.js';

/**
 * Module logger with automatic sensitive data sanitization
 * @type {SecureLogger}
 */
const logger = createLogger('Mutex');

/**
 * AsyncMutex - Mutual exclusion lock for async operations
 *
 * Ensures only one async operation can execute a critical section at a time.
 * Uses a promise-based queue to serialize access.
 *
 * @class AsyncMutex
 */
export class AsyncMutex {
    constructor() {
        /**
         * Queue of waiting lock requests
         * @type {Array<Function>}
         */
        this._queue = [];

        /**
         * Whether the mutex is currently locked
         * @type {boolean}
         */
        this._locked = false;
    }

    /**
     * Acquire the mutex lock
     *
     * If the mutex is already locked, the caller will wait until it's released.
     * Returns a release function that MUST be called to release the lock.
     *
     * @returns {Promise<Function>} A release function to call when done
     *
     * @example
     * const release = await mutex.acquire();
     * try {
     *     // Critical section
     *     await doSomethingAsync();
     * } finally {
     *     release();
     * }
     */
    async acquire() {
        return new Promise((resolve) => {
            const tryAcquire = () => {
                if (!this._locked) {
                    this._locked = true;
                    resolve(this._createReleaseFunction());
                } else {
                    // Add to queue
                    this._queue.push(tryAcquire);
                }
            };

            tryAcquire();
        });
    }

    /**
     * Create the release function for the current lock holder
     *
     * @private
     * @returns {Function} Release function
     */
    _createReleaseFunction() {
        let released = false;

        return () => {
            if (released) {
                logger.warn('Lock already released, ignoring duplicate release');
                return;
            }

            released = true;
            this._locked = false;

            // Process next in queue
            if (this._queue.length > 0) {
                const next = this._queue.shift();
                // Use microtask to avoid stack buildup
                queueMicrotask(next);
            }
        };
    }

    /**
     * Execute a function while holding the mutex lock
     *
     * Automatically acquires and releases the lock around the function execution.
     * Handles both sync and async functions.
     *
     * @template T
     * @param {function(): T|Promise<T>} fn - Function to execute while holding lock
     * @returns {Promise<T>} Result of the function
     *
     * @example
     * const result = await mutex.runExclusive(async () => {
     *     return await initializeSystem();
     * });
     */
    async runExclusive(fn) {
        const release = await this.acquire();
        try {
            return await fn();
        } finally {
            release();
        }
    }

    /**
     * Check if the mutex is currently locked
     *
     * Note: This is for debugging/logging only. Do not use for conditional
     * logic as it creates race conditions.
     *
     * @returns {boolean} True if locked
     */
    isLocked() {
        return this._locked;
    }

    /**
     * Get the number of waiters in the queue
     *
     * @returns {number} Number of pending lock requests
     */
    getQueueLength() {
        return this._queue.length;
    }
}

/**
 * AsyncSemaphore - Bounded concurrency limiter for async operations.
 *
 * Unlike AsyncMutex (max 1 concurrent holder), this allows up to N concurrent
 * operations, blocking further acquisitions until a slot is released.
 *
 * Use case: bound the number of chunks being encrypted/prepared concurrently
 * in memory. Without this, Dropzone's `parallelChunkUploads: true` can trigger
 * simultaneous encryption of hundreds of chunks for a multi-GB file, each
 * holding ~10MB in RAM.
 *
 * @class AsyncSemaphore
 */
export class AsyncSemaphore {
    /**
     * @param {number} maxConcurrent - Maximum concurrent holders (>= 1)
     */
    constructor(maxConcurrent) {
        if (!Number.isInteger(maxConcurrent) || maxConcurrent < 1) {
            throw new Error('maxConcurrent must be a positive integer');
        }
        this._max = maxConcurrent;
        this._current = 0;
        /** @type {Array<Function>} */
        this._waiters = [];
    }

    /**
     * Acquire a slot. Resolves to a release function that MUST be called.
     * @returns {Promise<Function>}
     */
    async acquire() {
        return new Promise((resolve) => {
            const tryAcquire = () => {
                if (this._current < this._max) {
                    this._current++;
                    let released = false;
                    resolve(() => {
                        if (released) return;
                        released = true;
                        this._current--;
                        const next = this._waiters.shift();
                        if (next) queueMicrotask(next);
                    });
                } else {
                    this._waiters.push(tryAcquire);
                }
            };
            tryAcquire();
        });
    }

    /**
     * Run a function while holding a semaphore slot.
     * @template T
     * @param {function(): T|Promise<T>} fn
     * @returns {Promise<T>}
     */
    async runExclusive(fn) {
        const release = await this.acquire();
        try {
            return await fn();
        } finally {
            release();
        }
    }

    /** @returns {number} Current active holders */
    getCurrent() { return this._current; }
    /** @returns {number} Queued waiters */
    getQueueLength() { return this._waiters.length; }
}

/**
 * KeyConsistencyGuard - Ensures encryption key consistency during upload session
 *
 * Prevents key changes after encryption has started, which would cause
 * files to be encrypted with different keys (making decryption impossible).
 *
 * @class KeyConsistencyGuard
 */
export class KeyConsistencyGuard {
    constructor() {
        /**
         * The committed key fingerprint (hash of first 8 bytes)
         * @type {string|null}
         */
        this._committedKeyFingerprint = null;

        /**
         * Whether encryption has started
         * @type {boolean}
         */
        this._encryptionStarted = false;

        /**
         * Number of files currently using this key
         * @type {number}
         */
        this._activeFileCount = 0;
    }

    /**
     * Compute a fingerprint for a CryptoKey
     *
     * @param {CryptoKey} key - The key to fingerprint
     * @returns {Promise<string>} Hex fingerprint of the key
     */
    async _computeFingerprint(key) {
        try {
            const rawKey = await crypto.subtle.exportKey('raw', key);
            const bytes = new Uint8Array(rawKey);
            // Use first 8 bytes for fingerprint (64 bits)
            return Array.from(bytes.slice(0, 8))
                .map(b => b.toString(16).padStart(2, '0'))
                .join('');
        } catch (error) {
            logger.error('Failed to compute fingerprint:', error?.message || 'Unknown error');
            throw new Error('Failed to verify key consistency');
        }
    }

    /**
     * Commit a key for the upload session
     *
     * Once a key is committed, all subsequent verifyKey calls must use the same key.
     * This prevents key regeneration during multi-file uploads.
     *
     * @param {CryptoKey} key - The key to commit
     * @throws {Error} If a different key was already committed
     */
    async commitKey(key) {
        const fingerprint = await this._computeFingerprint(key);

        if (this._committedKeyFingerprint === null) {
            this._committedKeyFingerprint = fingerprint;
            logger.debug('Key committed, fingerprint:', fingerprint);
        } else if (this._committedKeyFingerprint !== fingerprint) {
            logger.error('Key mismatch! Committed vs New fingerprints differ');
            throw new Error('Encryption key changed during upload session. This should not happen.');
        }
    }

    /**
     * Verify that a key matches the committed key
     *
     * @param {CryptoKey} key - The key to verify
     * @returns {Promise<boolean>} True if key matches or no key committed yet
     * @throws {Error} If key doesn't match committed key
     */
    async verifyKey(key) {
        if (this._committedKeyFingerprint === null) {
            return true; // No key committed yet
        }

        const fingerprint = await this._computeFingerprint(key);
        if (fingerprint !== this._committedKeyFingerprint) {
            logger.error('Key verification failed!');
            throw new Error('Encryption key mismatch detected');
        }

        return true;
    }

    /**
     * Mark that encryption has started (files are being processed)
     */
    startEncryption() {
        this._encryptionStarted = true;
        this._activeFileCount++;
        logger.debug('Encryption started, active files:', this._activeFileCount);
    }

    /**
     * Mark that a file has finished encrypting
     */
    finishFile() {
        this._activeFileCount = Math.max(0, this._activeFileCount - 1);
        logger.debug('File finished, active files:', this._activeFileCount);
    }

    /**
     * Check if it's safe to change the encryption key
     *
     * @returns {boolean} True if safe to change key (no active encryption)
     */
    canChangeKey() {
        return !this._encryptionStarted || this._activeFileCount === 0;
    }

    /**
     * Reset the guard (only when all files are complete)
     */
    reset() {
        if (this._activeFileCount > 0) {
            logger.warn('Cannot reset while files are active');
            return false;
        }

        this._committedKeyFingerprint = null;
        this._encryptionStarted = false;
        logger.debug('Reset complete');
        return true;
    }

    /**
     * Get current state for debugging
     *
     * @returns {Object} Current guard state
     */
    getState() {
        return {
            hasCommittedKey: this._committedKeyFingerprint !== null,
            encryptionStarted: this._encryptionStarted,
            activeFileCount: this._activeFileCount
        };
    }
}
