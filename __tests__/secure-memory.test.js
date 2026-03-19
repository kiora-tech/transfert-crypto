/**
 * Unit Tests for SecureMemory Module
 *
 * Tests the secure memory cleanup utilities for cryptographic data.
 *
 * @jest-environment jsdom
 */

import { SecureMemory, SecureBuffer, withSecureCleanup } from '../src/secure-memory.js';

describe('SecureMemory', () => {
    beforeEach(() => {
        // Clear all registered buffers before each test
        SecureMemory.clearAll();
    });

    describe('zeroBuffer', () => {
        it('should zero an ArrayBuffer', () => {
            const buffer = new ArrayBuffer(16);
            const view = new Uint8Array(buffer);
            view.fill(0xFF); // Fill with non-zero values

            SecureMemory.zeroBuffer(buffer);

            expect(SecureMemory.isZeroed(buffer)).toBe(true);
        });

        it('should zero a Uint8Array', () => {
            const buffer = new Uint8Array(16);
            buffer.fill(0xAB); // Fill with non-zero values

            SecureMemory.zeroBuffer(buffer);

            expect(SecureMemory.isZeroed(buffer)).toBe(true);
        });

        it('should handle null input gracefully', () => {
            expect(() => SecureMemory.zeroBuffer(null)).not.toThrow();
            expect(() => SecureMemory.zeroBuffer(undefined)).not.toThrow();
        });

        it('should zero a Float32Array', () => {
            const buffer = new Float32Array(4);
            buffer.fill(3.14);

            SecureMemory.zeroBuffer(buffer);

            expect(buffer.every(v => v === 0)).toBe(true);
        });
    });

    describe('zeroBuffers', () => {
        it('should zero multiple buffers at once', () => {
            const buffer1 = new Uint8Array(8).fill(0xFF);
            const buffer2 = new Uint8Array(16).fill(0xAA);
            const buffer3 = new ArrayBuffer(4);
            new Uint8Array(buffer3).fill(0xBB);

            SecureMemory.zeroBuffers(buffer1, buffer2, buffer3);

            expect(SecureMemory.isZeroed(buffer1)).toBe(true);
            expect(SecureMemory.isZeroed(buffer2)).toBe(true);
            expect(SecureMemory.isZeroed(buffer3)).toBe(true);
        });

        it('should handle mixed null and valid buffers', () => {
            const buffer = new Uint8Array(8).fill(0xFF);

            expect(() => SecureMemory.zeroBuffers(null, buffer, undefined)).not.toThrow();
            expect(SecureMemory.isZeroed(buffer)).toBe(true);
        });
    });

    describe('registerSensitive and clearAll', () => {
        it('should register and clear sensitive buffers', () => {
            const buffer1 = new Uint8Array(8).fill(0xFF);
            const buffer2 = new Uint8Array(16).fill(0xAA);

            SecureMemory.registerSensitive(buffer1);
            SecureMemory.registerSensitive(buffer2);

            expect(SecureMemory.getRegisteredCount()).toBeGreaterThan(0);

            SecureMemory.clearAll();

            expect(SecureMemory.isZeroed(buffer1)).toBe(true);
            expect(SecureMemory.isZeroed(buffer2)).toBe(true);
            expect(SecureMemory.getRegisteredCount()).toBe(0);
        });

        it('should handle null registration gracefully', () => {
            expect(() => SecureMemory.registerSensitive(null)).not.toThrow();
        });
    });

    describe('unregisterAndZero', () => {
        it('should unregister and zero a specific buffer', () => {
            const buffer1 = new Uint8Array(8).fill(0xFF);
            const buffer2 = new Uint8Array(8).fill(0xAA);

            SecureMemory.registerSensitive(buffer1);
            SecureMemory.registerSensitive(buffer2);

            const initialCount = SecureMemory.getRegisteredCount();

            SecureMemory.unregisterAndZero(buffer1);

            expect(SecureMemory.isZeroed(buffer1)).toBe(true);
            // buffer2 should still have data until cleared
            expect(buffer2[0]).toBe(0xAA);
        });
    });

    describe('withCleanup', () => {
        it('should cleanup buffers after successful execution', async () => {
            const buffer = new Uint8Array(16).fill(0xFF);

            const result = await SecureMemory.withCleanup(
                async () => {
                    return 'success';
                },
                buffer
            );

            expect(result).toBe('success');
            expect(SecureMemory.isZeroed(buffer)).toBe(true);
        });

        it('should cleanup buffers even on error', async () => {
            const buffer = new Uint8Array(16).fill(0xFF);

            await expect(SecureMemory.withCleanup(
                async () => {
                    throw new Error('Test error');
                },
                buffer
            )).rejects.toThrow('Test error');

            expect(SecureMemory.isZeroed(buffer)).toBe(true);
        });

        it('should handle objects with clear method', async () => {
            let cleared = false;
            const mockKeyManager = {
                clear: () => { cleared = true; }
            };

            await SecureMemory.withCleanup(
                async () => 'done',
                mockKeyManager
            );

            expect(cleared).toBe(true);
        });
    });

    describe('createScope', () => {
        it('should track and cleanup all buffers in scope', () => {
            const scope = SecureMemory.createScope();

            const buffer1 = new Uint8Array(8).fill(0xFF);
            const buffer2 = new Uint8Array(16).fill(0xAA);

            scope.track(buffer1);
            scope.track(buffer2);

            // Buffers should still have data
            expect(buffer1[0]).toBe(0xFF);
            expect(buffer2[0]).toBe(0xAA);

            scope.cleanup();

            // Buffers should be zeroed
            expect(SecureMemory.isZeroed(buffer1)).toBe(true);
            expect(SecureMemory.isZeroed(buffer2)).toBe(true);
        });

        it('should handle null tracking gracefully', () => {
            const scope = SecureMemory.createScope();

            expect(() => scope.track(null)).not.toThrow();
            expect(() => scope.cleanup()).not.toThrow();
        });
    });

    describe('clearString', () => {
        it('should return empty string', () => {
            const password = 'secret_password_123';
            const result = SecureMemory.clearString(password);

            expect(result).toBe('');
        });

        it('should handle empty and null strings', () => {
            expect(SecureMemory.clearString('')).toBe('');
            expect(SecureMemory.clearString(null)).toBe('');
            expect(SecureMemory.clearString(undefined)).toBe('');
        });
    });

    describe('securePassword', () => {
        it('should allow single use of password', async () => {
            const securePassword = SecureMemory.securePassword('test_password');

            const result = await securePassword.use(async (pwd) => {
                expect(pwd).toBe('test_password');
                return 'derived_key';
            });

            expect(result).toBe('derived_key');
        });

        it('should throw on second use', async () => {
            const securePassword = SecureMemory.securePassword('test_password');

            await securePassword.use(async () => 'first');

            await expect(securePassword.use(async () => 'second'))
                .rejects.toThrow('Secure password has already been used and cleared');
        });
    });

    describe('isZeroed', () => {
        it('should return true for zeroed buffer', () => {
            const buffer = new Uint8Array(16);
            expect(SecureMemory.isZeroed(buffer)).toBe(true);
        });

        it('should return false for non-zeroed buffer', () => {
            const buffer = new Uint8Array(16);
            buffer[5] = 0xFF;
            expect(SecureMemory.isZeroed(buffer)).toBe(false);
        });

        it('should return true for null/undefined', () => {
            expect(SecureMemory.isZeroed(null)).toBe(true);
            expect(SecureMemory.isZeroed(undefined)).toBe(true);
        });
    });
});

describe('SecureBuffer', () => {
    describe('constructor', () => {
        it('should create a buffer of specified size', () => {
            const secureBuffer = new SecureBuffer(32);

            expect(secureBuffer.length).toBe(32);
            expect(SecureMemory.isZeroed(secureBuffer.buffer)).toBe(true);
        });

        it('should auto-register with SecureMemory', () => {
            const initialCount = SecureMemory.getRegisteredCount();
            const secureBuffer = new SecureBuffer(16);

            expect(SecureMemory.getRegisteredCount()).toBeGreaterThan(initialCount);

            secureBuffer.dispose();
        });
    });

    describe('from', () => {
        it('should create from Uint8Array', () => {
            const data = new Uint8Array([1, 2, 3, 4, 5]);
            const secureBuffer = SecureBuffer.from(data);

            expect(secureBuffer.length).toBe(5);
            expect(secureBuffer.at(0)).toBe(1);
            expect(secureBuffer.at(4)).toBe(5);

            secureBuffer.dispose();
        });

        it('should create from array', () => {
            const data = [10, 20, 30];
            const secureBuffer = SecureBuffer.from(data);

            expect(secureBuffer.length).toBe(3);
            expect(secureBuffer.at(1)).toBe(20);

            secureBuffer.dispose();
        });
    });

    describe('dispose', () => {
        it('should zero buffer on dispose', () => {
            const secureBuffer = new SecureBuffer(16);
            const bufferRef = secureBuffer.buffer;

            // Set some data
            secureBuffer.set(0, 0xFF);
            secureBuffer.set(5, 0xAA);

            secureBuffer.dispose();

            expect(secureBuffer.isDisposed).toBe(true);
            expect(SecureMemory.isZeroed(bufferRef)).toBe(true);
        });

        it('should throw on buffer access after dispose', () => {
            const secureBuffer = new SecureBuffer(16);
            secureBuffer.dispose();

            expect(() => secureBuffer.buffer).toThrow('SecureBuffer has been disposed');
            expect(() => secureBuffer.at(0)).toThrow('SecureBuffer has been disposed');
            expect(() => secureBuffer.set(0, 1)).toThrow('SecureBuffer has been disposed');
        });

        it('should handle multiple dispose calls gracefully', () => {
            const secureBuffer = new SecureBuffer(16);

            expect(() => {
                secureBuffer.dispose();
                secureBuffer.dispose();
                secureBuffer.dispose();
            }).not.toThrow();
        });
    });
});

describe('withSecureCleanup', () => {
    it('should create a wrapped function that cleans up parameters', async () => {
        const originalFn = async (key, data) => {
            // Simulate some operation
            return 'result';
        };

        const buffer = new Uint8Array(16).fill(0xFF);

        const wrappedFn = withSecureCleanup(originalFn, [1]);
        const result = await wrappedFn(null, buffer);

        expect(result).toBe('result');
        expect(SecureMemory.isZeroed(buffer)).toBe(true);
    });

    it('should cleanup even on error', async () => {
        const originalFn = async (data) => {
            throw new Error('Operation failed');
        };

        const buffer = new Uint8Array(8).fill(0xAB);
        const wrappedFn = withSecureCleanup(originalFn, [0]);

        await expect(wrappedFn(buffer)).rejects.toThrow('Operation failed');
        expect(SecureMemory.isZeroed(buffer)).toBe(true);
    });
});
