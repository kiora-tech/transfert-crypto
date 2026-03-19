/**
 * SecureLogger - Sanitized logging for cryptographic operations
 *
 * This module provides secure logging that:
 * - Only logs in debug mode (localhost/development)
 * - Automatically sanitizes sensitive data (keys, IVs, passwords, etc.)
 * - Prevents accidental exposure of cryptographic material in production
 *
 * @module crypto/secure-logger
 */

/**
 * Patterns that indicate sensitive data fields
 * @type {RegExp[]}
 */
const SENSITIVE_PATTERNS = [
    /key/i,
    /password/i,
    /secret/i,
    /iv/i,
    /salt/i,
    /nonce/i,
    /token/i,
    /credential/i,
    /private/i,
    /hash/i,
    /encrypted/i,
    /cipher/i,
    /raw/i,
    /buffer/i,
    /arraybuffer/i,
    /uint8/i,
    /hex/i,
    /base64/i,
];

/**
 * Check if a field name indicates sensitive data
 * @param {string} fieldName - The field name to check
 * @returns {boolean} True if the field is likely sensitive
 */
function isSensitiveField(fieldName) {
    if (typeof fieldName !== 'string') return false;
    return SENSITIVE_PATTERNS.some(pattern => pattern.test(fieldName));
}

/**
 * Sanitize a value for safe logging
 * @param {*} value - The value to sanitize
 * @param {string} [fieldName] - Optional field name for context
 * @returns {*} Sanitized value safe for logging
 */
function sanitizeValue(value, fieldName = '') {
    // Check if field name indicates sensitive data
    if (fieldName && isSensitiveField(fieldName)) {
        return '[REDACTED]';
    }

    // Handle null/undefined
    if (value === null || value === undefined) {
        return value;
    }

    // Handle ArrayBuffer and TypedArrays - always redact
    if (value instanceof ArrayBuffer || ArrayBuffer.isView(value)) {
        const length = value instanceof ArrayBuffer ? value.byteLength : value.length;
        return `[Binary data: ${length} bytes]`;
    }

    // Handle CryptoKey objects - always redact
    if (typeof CryptoKey !== 'undefined' && value instanceof CryptoKey) {
        return `[CryptoKey: ${value.type}, ${value.algorithm?.name || 'unknown'}]`;
    }

    // Handle strings that look like hex or base64 encoded data
    if (typeof value === 'string') {
        // Hex strings (32+ chars of hex)
        if (/^[0-9a-fA-F]{32,}$/.test(value)) {
            return `[Hex data: ${value.length} chars]`;
        }
        // Base64 strings (24+ chars of base64)
        if (/^[A-Za-z0-9+/]{24,}={0,2}$/.test(value)) {
            return `[Base64 data: ${value.length} chars]`;
        }
        // Truncated hex/base64 with ellipsis
        if (/^[0-9a-fA-F]{8,}\.{3}$/.test(value) || /^[A-Za-z0-9+/]{8,}\.{3}$/.test(value)) {
            return '[Truncated encoded data]';
        }
    }

    // Handle objects recursively
    if (typeof value === 'object') {
        if (Array.isArray(value)) {
            return value.map((item, index) => sanitizeValue(item, `[${index}]`));
        }

        const sanitized = {};
        for (const [key, val] of Object.entries(value)) {
            sanitized[key] = sanitizeValue(val, key);
        }
        return sanitized;
    }

    return value;
}

/**
 * SecureLogger class for cryptographic operations
 */
class SecureLogger {
    /**
     * @param {string} module - Module name for log prefixing
     * @param {Object} [options] - Configuration options
     * @param {boolean} [options.forceEnable] - Force enable logging (for testing)
     * @param {boolean} [options.forceDisable] - Force disable logging
     */
    constructor(module, options = {}) {
        this.module = module;
        this.prefix = `[${module}]`;
        this.options = options;

        // Cache the debug mode check
        this._debugMode = null;
    }

    /**
     * Check if debug mode is enabled
     * Debug mode is only active on localhost or when explicitly enabled
     * @returns {boolean} True if debug logging is enabled
     */
    isDebugMode() {
        if (this._debugMode !== null) {
            return this._debugMode;
        }

        // Force flags take precedence
        if (this.options.forceDisable) {
            this._debugMode = false;
            return false;
        }

        if (this.options.forceEnable) {
            this._debugMode = true;
            return true;
        }

        // Check if we're on localhost
        if (typeof window !== 'undefined' && window.location) {
            const hostname = window.location.hostname;
            this._debugMode = (
                hostname === 'localhost' ||
                hostname === '127.0.0.1' ||
                hostname === '::1' ||
                hostname.endsWith('.local') ||
                hostname.endsWith('.test')
            );
        } else {
            // Node.js environment or no window - check NODE_ENV
            this._debugMode = typeof process !== 'undefined' &&
                              process.env &&
                              process.env.NODE_ENV === 'development';
        }

        return this._debugMode;
    }

    /**
     * Format arguments for logging, sanitizing sensitive data
     * @param {Array} args - Arguments to format
     * @returns {Array} Sanitized arguments
     */
    formatArgs(args) {
        return args.map((arg, index) => {
            // First argument is often a message string - check for sensitive patterns
            if (index === 0 && typeof arg === 'string') {
                // Extract field hints from the message
                const fieldMatch = arg.match(/(\w+)(?:\s*[:(]|$)/);
                const fieldHint = fieldMatch ? fieldMatch[1] : '';

                // If message mentions sensitive data, we still log the message
                // but subsequent args will be sanitized
                return arg;
            }

            return sanitizeValue(arg);
        });
    }

    /**
     * Log a debug message (only in debug mode)
     * @param {...*} args - Arguments to log
     */
    debug(...args) {
        if (!this.isDebugMode()) return;

        const sanitizedArgs = this.formatArgs(args);
        console.debug(this.prefix, ...sanitizedArgs);
    }

    /**
     * Log an info message (only in debug mode)
     * @param {...*} args - Arguments to log
     */
    info(...args) {
        if (!this.isDebugMode()) return;

        const sanitizedArgs = this.formatArgs(args);
        console.info(this.prefix, ...sanitizedArgs);
    }

    /**
     * Log a standard message (only in debug mode)
     * @param {...*} args - Arguments to log
     */
    log(...args) {
        if (!this.isDebugMode()) return;

        const sanitizedArgs = this.formatArgs(args);
        console.log(this.prefix, ...sanitizedArgs);
    }

    /**
     * Log a warning message (always logged, but sanitized)
     * @param {...*} args - Arguments to log
     */
    warn(...args) {
        const sanitizedArgs = this.formatArgs(args);
        console.warn(this.prefix, ...sanitizedArgs);
    }

    /**
     * Log an error message (always logged, but sanitized)
     * @param {...*} args - Arguments to log
     */
    error(...args) {
        const sanitizedArgs = this.formatArgs(args);
        console.error(this.prefix, ...sanitizedArgs);
    }

    /**
     * Create a child logger with a sub-module name
     * @param {string} subModule - Sub-module name
     * @returns {SecureLogger} New logger instance
     */
    child(subModule) {
        return new SecureLogger(`${this.module}:${subModule}`, this.options);
    }

    /**
     * Log timing information for performance analysis
     * @param {string} operation - Operation name
     * @param {number} startTime - Start time from performance.now()
     */
    timing(operation, startTime) {
        if (!this.isDebugMode()) return;

        const duration = performance.now() - startTime;
        console.log(this.prefix, `${operation} completed in ${duration.toFixed(2)}ms`);
    }

    /**
     * Log a group of related messages
     * @param {string} label - Group label
     * @param {Function} fn - Function containing log calls
     */
    group(label, fn) {
        if (!this.isDebugMode()) return;

        console.group(this.prefix, label);
        try {
            fn();
        } finally {
            console.groupEnd();
        }
    }
}

/**
 * Create a logger instance for a module
 * @param {string} module - Module name
 * @param {Object} [options] - Configuration options
 * @returns {SecureLogger} Logger instance
 */
export function createLogger(module, options = {}) {
    return new SecureLogger(module, options);
}

/**
 * Default logger instance for general use
 */
export const logger = createLogger('Crypto');

/**
 * Utility to sanitize a single value (for external use)
 */
export { sanitizeValue, isSensitiveField };

export default SecureLogger;
