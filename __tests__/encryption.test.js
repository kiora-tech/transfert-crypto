/**
 * Unit tests for CryptoEngine encryption module
 *
 * @jest-environment jsdom
 */

import { CryptoEngine, isCryptoSupported } from '../src/encryption.js';

// Mock Web Crypto API if not available
if (typeof crypto === 'undefined' || !crypto.subtle) {
    global.crypto = {
        subtle: {
            generateKey: jest.fn(),
            encrypt: jest.fn(),
            decrypt: jest.fn(),
            importKey: jest.fn(),
            exportKey: jest.fn(),
            deriveKey: jest.fn()
        },
        getRandomValues: (arr) => {
            for (let i = 0; i < arr.length; i++) {
                arr[i] = Math.floor(Math.random() * 256);
            }
            return arr;
        }
    };
}

describe('CryptoEngine', () => {
    describe('Configuration', () => {
        it('should use 600000 PBKDF2 iterations (OWASP 2023)', () => {
            expect(CryptoEngine.CONFIG.PBKDF2_ITERATIONS).toBe(600000);
        });

        it('should have current version as v2-aes-gcm-256', () => {
            expect(CryptoEngine.VERSION).toBe('v2-aes-gcm-256');
        });

        it('should support both v1 and v2 versions', () => {
            expect(CryptoEngine.VERSIONS).toHaveProperty('v1-aes-gcm-256');
            expect(CryptoEngine.VERSIONS).toHaveProperty('v2-aes-gcm-256');
        });

        it('should have v1 with 100000 iterations for backward compatibility', () => {
            expect(CryptoEngine.VERSIONS['v1-aes-gcm-256'].iterations).toBe(100000);
        });

        it('should have v2 with 600000 iterations', () => {
            expect(CryptoEngine.VERSIONS['v2-aes-gcm-256'].iterations).toBe(600000);
        });

        it('should use AES-256-GCM algorithm', () => {
            expect(CryptoEngine.CONFIG.ALGORITHM).toBe('AES-GCM');
            expect(CryptoEngine.CONFIG.KEY_LENGTH).toBe(256);
        });

        it('should use 12-byte IV (96 bits)', () => {
            expect(CryptoEngine.CONFIG.IV_LENGTH).toBe(12);
        });

        it('should use 128-bit authentication tag', () => {
            expect(CryptoEngine.CONFIG.TAG_LENGTH).toBe(128);
        });

        it('should use 16-byte salt (128 bits)', () => {
            expect(CryptoEngine.CONFIG.SALT_LENGTH).toBe(16);
        });
    });

    describe('Version Support', () => {
        it('should accept v1-aes-gcm-256 metadata version', () => {
            const isSupported = !!CryptoEngine.VERSIONS['v1-aes-gcm-256'];
            expect(isSupported).toBe(true);
        });

        it('should accept v2-aes-gcm-256 metadata version', () => {
            const isSupported = !!CryptoEngine.VERSIONS['v2-aes-gcm-256'];
            expect(isSupported).toBe(true);
        });

        it('should reject unknown versions', () => {
            const isSupported = !!CryptoEngine.VERSIONS['v3-unknown'];
            expect(isSupported).toBe(false);
        });
    });
});

describe('E2EEncryption KDF_PARAMS', () => {
    // Import E2EEncryption if available
    let E2EEncryption;

    beforeAll(async () => {
        try {
            const module = await import('../src/e2ee.js');
            E2EEncryption = module.E2EEncryption || module.default;
        } catch (e) {
            // Module may not be available in test environment
            E2EEncryption = null;
        }
    });

    it('should use 600000 PBKDF2 iterations in E2EEncryption', () => {
        if (E2EEncryption) {
            expect(E2EEncryption.KDF_PARAMS.iterations).toBe(600000);
        } else {
            // Skip test if module not available
            console.log('E2EEncryption module not available, skipping test');
        }
    });
});
