/**
 * Secure Memory Management Module
 *
 * Provides centralized memory cleanup utilities for sensitive cryptographic data.
 * Implements defense-in-depth approach to minimize exposure of key material in memory.
 *
 * Security considerations:
 * - JavaScript cannot guarantee memory is truly zeroed (GC, JIT, browser internals)
 * - CryptoKey objects cannot be directly zeroed (Web Crypto API limitation)
 * - These utilities provide best-effort cleanup to reduce attack surface
 * - Sensitive data should be cleared as soon as it's no longer needed
 *
 * @module crypto/secure-memory
 */

import { CryptoEngine } from './encryption.js';
import { createLogger } from './secure-logger.js';

/**
 * Module logger with automatic sensitive data sanitization
 * @type {SecureLogger}
 */
const logger = createLogger('SecureMemory');

/**
 * Registry of sensitive buffers for cleanup on page unload
 * Uses WeakRef where supported for automatic cleanup when objects are GC'd
 * @type {Set<WeakRef<ArrayBuffer|Uint8Array>|ArrayBuffer|Uint8Array>}
 */
const sensitiveBufferRegistry = new Set();

/**
 * Track if cleanup handlers are registered
 * @type {boolean}
 */
let cleanupHandlersRegistered = false;

/**
 * Secure Memory Manager - Centralized sensitive data cleanup
 *
 * Provides utilities for:
 * - Registering sensitive buffers for automatic cleanup
 * - Zeroing buffers immediately when no longer needed
 * - Page unload cleanup to minimize data persistence
 * - Scope-based cleanup with try/finally patterns
 *
 * @class SecureMemory
 */
export class SecureMemory {
    /**
     * Zero out an ArrayBuffer or TypedArray
     *
     * @param {ArrayBuffer|Uint8Array|Int8Array|Uint16Array|Int16Array|Uint32Array|Int32Array|Float32Array|Float64Array} buffer - Buffer to clear
     * @returns {void}
     */
    static zeroBuffer(buffer) {
        if (!buffer) return;

        try {
            if (buffer instanceof ArrayBuffer) {
                new Uint8Array(buffer).fill(0);
            } else if (ArrayBuffer.isView(buffer)) {
                // TypedArray - fill with zeros
                buffer.fill(0);
            }
        } catch (error) {
            // Buffer may be detached or read-only
            logger.warn('Failed to zero buffer:', error?.message || 'Unknown error');
        }
    }

    /**
     * Zero out multiple buffers at once
     *
     * @param {...(ArrayBuffer|Uint8Array|null|undefined)} buffers - Buffers to clear
     * @returns {void}
     */
    static zeroBuffers(...buffers) {
        for (const buffer of buffers) {
            if (buffer) {
                SecureMemory.zeroBuffer(buffer);
            }
        }
    }

    /**
     * Register a sensitive buffer for cleanup on page unload
     * Uses WeakRef if available to avoid preventing garbage collection
     *
     * @param {ArrayBuffer|Uint8Array} buffer - Sensitive buffer to track
     * @returns {void}
     */
    static registerSensitive(buffer) {
        if (!buffer) return;

        // Ensure cleanup handlers are registered
        SecureMemory.ensureCleanupHandlers();

        try {
            // Use WeakRef if available (modern browsers)
            if (typeof WeakRef !== 'undefined') {
                sensitiveBufferRegistry.add(new WeakRef(buffer));
            } else {
                // Fallback: direct reference (may prevent GC until page unload)
                sensitiveBufferRegistry.add(buffer);
            }
        } catch (error) {
            logger.warn('Failed to register sensitive buffer:', error?.message || 'Unknown error');
        }
    }

    /**
     * Unregister and zero a sensitive buffer
     *
     * @param {ArrayBuffer|Uint8Array} buffer - Buffer to unregister and clear
     * @returns {void}
     */
    static unregisterAndZero(buffer) {
        if (!buffer) return;

        // Zero the buffer first
        SecureMemory.zeroBuffer(buffer);

        // Remove from registry
        // Need to iterate because we might have stored WeakRef
        for (const entry of sensitiveBufferRegistry) {
            try {
                const ref = entry instanceof WeakRef ? entry.deref() : entry;
                if (ref === buffer) {
                    sensitiveBufferRegistry.delete(entry);
                    break;
                }
            } catch (error) {
                // WeakRef may already be collected
            }
        }
    }

    /**
     * Clear all registered sensitive buffers
     * Called automatically on page unload
     *
     * @returns {void}
     */
    static clearAll() {
        logger.debug('Clearing all registered sensitive buffers...');

        for (const entry of sensitiveBufferRegistry) {
            try {
                const buffer = entry instanceof WeakRef ? entry.deref() : entry;
                if (buffer) {
                    SecureMemory.zeroBuffer(buffer);
                }
            } catch (error) {
                // Buffer may already be collected or detached
            }
        }

        sensitiveBufferRegistry.clear();
        logger.debug('All buffers cleared');
    }

    /**
     * Ensure page unload cleanup handlers are registered
     *
     * @returns {void}
     */
    static ensureCleanupHandlers() {
        if (cleanupHandlersRegistered) return;

        if (typeof window !== 'undefined') {
            // Multiple events for browser compatibility
            window.addEventListener('beforeunload', SecureMemory.clearAll);
            window.addEventListener('unload', SecureMemory.clearAll);
            window.addEventListener('pagehide', SecureMemory.clearAll);

            logger.debug('Cleanup handlers registered');
        }

        cleanupHandlersRegistered = true;
    }

    /**
     * Execute a function with automatic cleanup of sensitive data
     * Ensures cleanup happens even if an error occurs
     *
     * @template T
     * @param {() => T|Promise<T>} fn - Function to execute
     * @param {...(ArrayBuffer|Uint8Array|{clear: () => void}|null)} sensitiveItems - Items to clean up after execution
     * @returns {Promise<T>} Result of the function
     *
     * @example
     * // Using with buffers
     * const result = await SecureMemory.withCleanup(
     *     async () => {
     *         const password = new TextEncoder().encode('secret');
     *         const key = await deriveKey(password);
     *         return key;
     *     },
     *     passwordBuffer
     * );
     */
    static async withCleanup(fn, ...sensitiveItems) {
        try {
            return await fn();
        } finally {
            for (const item of sensitiveItems) {
                if (!item) continue;

                try {
                    if (typeof item.clear === 'function') {
                        // Object with clear method (e.g., KeyManager)
                        item.clear();
                    } else if (item instanceof ArrayBuffer || ArrayBuffer.isView(item)) {
                        // Buffer
                        SecureMemory.zeroBuffer(item);
                    }
                } catch (error) {
                    logger.warn('Cleanup error:', error?.message || 'Unknown error');
                }
            }
        }
    }

    /**
     * Create a secure scope that tracks and cleans up all buffers created within it
     *
     * @returns {{track: (buffer: ArrayBuffer|Uint8Array) => void, cleanup: () => void}}
     *
     * @example
     * const scope = SecureMemory.createScope();
     * try {
     *     const buffer1 = new Uint8Array(32);
     *     scope.track(buffer1);
     *     const buffer2 = new Uint8Array(16);
     *     scope.track(buffer2);
     *     // ... use buffers ...
     * } finally {
     *     scope.cleanup();
     * }
     */
    static createScope() {
        const trackedBuffers = new Set();

        return {
            track(buffer) {
                if (buffer) {
                    trackedBuffers.add(buffer);
                }
            },

            cleanup() {
                for (const buffer of trackedBuffers) {
                    SecureMemory.zeroBuffer(buffer);
                }
                trackedBuffers.clear();
            }
        };
    }

    /**
     * Zero a string by creating a buffer and zeroing it
     * Note: This cannot truly clear the original string from memory,
     * but can help clear any buffers created from it
     *
     * @param {string} str - String to attempt to clear
     * @returns {string} Empty string to replace the variable
     *
     * @example
     * let password = 'secret';
     * // ... use password ...
     * password = SecureMemory.clearString(password);
     */
    static clearString(str) {
        if (!str || typeof str !== 'string') return '';

        // Create a buffer from the string and zero it
        // This won't clear the original string but helps with any copies
        try {
            const buffer = new TextEncoder().encode(str);
            SecureMemory.zeroBuffer(buffer);
        } catch (error) {
            // Ignore errors
        }

        return '';
    }

    /**
     * Create a secure password handler that auto-clears after use
     *
     * @param {string} password - Password string
     * @returns {{use: (fn: (password: string) => Promise<T>) => Promise<T>}}
     *
     * @example
     * const securePassword = SecureMemory.securePassword(userInput);
     * const key = await securePassword.use(async (pwd) => {
     *     return await deriveKeyFromPassword(pwd);
     * });
     * // Password is automatically cleared after use
     */
    static securePassword(password) {
        let pwd = password;
        let used = false;

        return {
            async use(fn) {
                if (used) {
                    throw new Error('Secure password has already been used and cleared');
                }

                try {
                    return await fn(pwd);
                } finally {
                    pwd = SecureMemory.clearString(pwd);
                    used = true;
                }
            }
        };
    }

    /**
     * Get the number of registered sensitive buffers (for testing/debugging)
     *
     * @returns {number} Count of registered buffers
     */
    static getRegisteredCount() {
        return sensitiveBufferRegistry.size;
    }

    /**
     * Check if a buffer appears to be zeroed
     *
     * @param {ArrayBuffer|Uint8Array} buffer - Buffer to check
     * @returns {boolean} True if all bytes are zero
     */
    static isZeroed(buffer) {
        if (!buffer) return true;

        try {
            const view = buffer instanceof ArrayBuffer
                ? new Uint8Array(buffer)
                : buffer;

            for (let i = 0; i < view.length; i++) {
                if (view[i] !== 0) return false;
            }
            return true;
        } catch (error) {
            return false;
        }
    }
}

/**
 * Decorator-style wrapper for functions that handle sensitive data
 * Automatically cleans up specified parameters after execution
 *
 * @param {Function} fn - Function to wrap
 * @param {number[]} sensitiveParamIndices - Indices of parameters to clean up
 * @returns {Function} Wrapped function with automatic cleanup
 *
 * @example
 * const secureEncrypt = withSecureCleanup(
 *     async (key, data) => {
 *         return await crypto.subtle.encrypt({...}, key, data);
 *     },
 *     [1] // Clean up 'data' parameter after execution
 * );
 */
export function withSecureCleanup(fn, sensitiveParamIndices = []) {
    return async function(...args) {
        try {
            return await fn.apply(this, args);
        } finally {
            for (const index of sensitiveParamIndices) {
                if (args[index]) {
                    SecureMemory.zeroBuffer(args[index]);
                }
            }
        }
    };
}

/**
 * SecureBuffer - A wrapper that auto-zeros on disposal
 *
 * @class SecureBuffer
 */
export class SecureBuffer {
    /**
     * Create a new secure buffer
     *
     * @param {number} size - Size of buffer in bytes
     */
    constructor(size) {
        this._buffer = new Uint8Array(size);
        this._disposed = false;
        SecureMemory.registerSensitive(this._buffer);
    }

    /**
     * Create from existing data
     *
     * @param {ArrayBuffer|Uint8Array|number[]} data - Data to copy
     * @returns {SecureBuffer}
     */
    static from(data) {
        const buffer = new SecureBuffer(data.length || data.byteLength);
        if (data instanceof ArrayBuffer) {
            buffer._buffer.set(new Uint8Array(data));
        } else if (data instanceof Uint8Array) {
            buffer._buffer.set(data);
        } else if (Array.isArray(data)) {
            buffer._buffer.set(data);
        }
        return buffer;
    }

    /**
     * Get the underlying buffer (read-only access)
     * @returns {Uint8Array}
     */
    get buffer() {
        if (this._disposed) {
            throw new Error('SecureBuffer has been disposed');
        }
        return this._buffer;
    }

    /**
     * Get buffer length
     * @returns {number}
     */
    get length() {
        return this._buffer.length;
    }

    /**
     * Get byte at index
     * @param {number} index
     * @returns {number}
     */
    at(index) {
        if (this._disposed) {
            throw new Error('SecureBuffer has been disposed');
        }
        return this._buffer[index];
    }

    /**
     * Set byte at index
     * @param {number} index
     * @param {number} value
     */
    set(index, value) {
        if (this._disposed) {
            throw new Error('SecureBuffer has been disposed');
        }
        this._buffer[index] = value;
    }

    /**
     * Dispose and zero the buffer
     */
    dispose() {
        if (!this._disposed) {
            SecureMemory.unregisterAndZero(this._buffer);
            this._disposed = true;
        }
    }

    /**
     * Check if buffer is disposed
     * @returns {boolean}
     */
    get isDisposed() {
        return this._disposed;
    }
}

// Auto-initialize cleanup handlers when module loads
if (typeof window !== 'undefined') {
    SecureMemory.ensureCleanupHandlers();
}

export default SecureMemory;
