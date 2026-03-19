/**
 * SecureLogger Unit Tests
 *
 * Tests for the SecureLogger module that sanitizes sensitive cryptographic data.
 */

import { createLogger, sanitizeValue, isSensitiveField } from '../src/secure-logger.js';

describe('SecureLogger', () => {
    describe('isSensitiveField', () => {
        test('identifies sensitive field names', () => {
            expect(isSensitiveField('key')).toBe(true);
            expect(isSensitiveField('encryptionKey')).toBe(true);
            expect(isSensitiveField('secretKey')).toBe(true);
            expect(isSensitiveField('password')).toBe(true);
            expect(isSensitiveField('iv')).toBe(true);
            expect(isSensitiveField('salt')).toBe(true);
            expect(isSensitiveField('nonce')).toBe(true);
            expect(isSensitiveField('token')).toBe(true);
            expect(isSensitiveField('privateKey')).toBe(true);
            expect(isSensitiveField('hash')).toBe(true);
            expect(isSensitiveField('encrypted')).toBe(true);
            expect(isSensitiveField('rawKey')).toBe(true);
            expect(isSensitiveField('bufferData')).toBe(true);
        });

        test('does not flag non-sensitive field names', () => {
            expect(isSensitiveField('filename')).toBe(false);
            expect(isSensitiveField('size')).toBe(false);
            expect(isSensitiveField('mimeType')).toBe(false);
            expect(isSensitiveField('chunkIndex')).toBe(false);
            expect(isSensitiveField('progress')).toBe(false);
        });

        test('handles non-string inputs', () => {
            expect(isSensitiveField(null)).toBe(false);
            expect(isSensitiveField(undefined)).toBe(false);
            expect(isSensitiveField(123)).toBe(false);
            expect(isSensitiveField({})).toBe(false);
        });
    });

    describe('sanitizeValue', () => {
        test('redacts sensitive field values', () => {
            expect(sanitizeValue('secret123', 'password')).toBe('[REDACTED]');
            expect(sanitizeValue('abcdef', 'key')).toBe('[REDACTED]');
            expect(sanitizeValue('random', 'iv')).toBe('[REDACTED]');
        });

        test('sanitizes ArrayBuffer', () => {
            const buffer = new ArrayBuffer(32);
            const result = sanitizeValue(buffer);
            expect(result).toBe('[Binary data: 32 bytes]');
        });

        test('sanitizes Uint8Array', () => {
            const array = new Uint8Array(16);
            const result = sanitizeValue(array);
            expect(result).toBe('[Binary data: 16 bytes]');
        });

        test('sanitizes hex strings', () => {
            const hex = 'abcdef0123456789abcdef0123456789';
            const result = sanitizeValue(hex);
            expect(result).toBe('[Hex data: 32 chars]');
        });

        test('sanitizes base64 strings', () => {
            const base64 = 'SGVsbG8gV29ybGQgVGhpcyBpcyBhIHRlc3Q=';
            const result = sanitizeValue(base64);
            expect(result).toBe('[Base64 data: 36 chars]');
        });

        test('sanitizes truncated encoded data', () => {
            const truncatedHex = 'abcdef01234567...';
            const result = sanitizeValue(truncatedHex);
            expect(result).toBe('[Truncated encoded data]');
        });

        test('passes through regular values', () => {
            expect(sanitizeValue('hello')).toBe('hello');
            expect(sanitizeValue(123)).toBe(123);
            expect(sanitizeValue(true)).toBe(true);
            expect(sanitizeValue(null)).toBe(null);
            expect(sanitizeValue(undefined)).toBe(undefined);
        });

        test('sanitizes objects recursively', () => {
            const obj = {
                filename: 'test.txt',
                secretKey: 'mysecret',
                size: 1024
            };
            const result = sanitizeValue(obj);
            expect(result.filename).toBe('test.txt');
            expect(result.secretKey).toBe('[REDACTED]');
            expect(result.size).toBe(1024);
        });

        test('sanitizes arrays', () => {
            const arr = [new Uint8Array(8), 'hello', 123];
            const result = sanitizeValue(arr);
            expect(result[0]).toBe('[Binary data: 8 bytes]');
            expect(result[1]).toBe('hello');
            expect(result[2]).toBe(123);
        });
    });

    describe('createLogger', () => {
        let logger;
        let consoleSpy;

        beforeEach(() => {
            // Force disable debug mode for consistent testing
            logger = createLogger('TestModule', { forceDisable: true });
            consoleSpy = {
                log: jest.spyOn(console, 'log').mockImplementation(),
                debug: jest.spyOn(console, 'debug').mockImplementation(),
                info: jest.spyOn(console, 'info').mockImplementation(),
                warn: jest.spyOn(console, 'warn').mockImplementation(),
                error: jest.spyOn(console, 'error').mockImplementation()
            };
        });

        afterEach(() => {
            jest.restoreAllMocks();
        });

        test('creates logger with module name', () => {
            expect(logger).toBeDefined();
            expect(logger.module).toBe('TestModule');
        });

        test('debug mode is disabled when forceDisable is true', () => {
            expect(logger.isDebugMode()).toBe(false);
        });

        test('debug mode is enabled when forceEnable is true', () => {
            const enabledLogger = createLogger('Test', { forceEnable: true });
            expect(enabledLogger.isDebugMode()).toBe(true);
        });

        test('debug/info/log do not output when debug mode is disabled', () => {
            logger.debug('test message');
            logger.info('test message');
            logger.log('test message');

            expect(consoleSpy.debug).not.toHaveBeenCalled();
            expect(consoleSpy.info).not.toHaveBeenCalled();
            expect(consoleSpy.log).not.toHaveBeenCalled();
        });

        test('warn/error always output (sanitized)', () => {
            logger.warn('warning message');
            logger.error('error message');

            expect(consoleSpy.warn).toHaveBeenCalledWith('[TestModule]', 'warning message');
            expect(consoleSpy.error).toHaveBeenCalledWith('[TestModule]', 'error message');
        });

        test('sanitizes sensitive data in warn/error', () => {
            const sensitiveData = new Uint8Array(32);
            logger.warn('Processing data:', sensitiveData);

            expect(consoleSpy.warn).toHaveBeenCalledWith(
                '[TestModule]',
                'Processing data:',
                '[Binary data: 32 bytes]'
            );
        });

        test('child logger inherits options', () => {
            const childLogger = logger.child('SubModule');
            expect(childLogger.module).toBe('TestModule:SubModule');
            expect(childLogger.isDebugMode()).toBe(false);
        });

        describe('with debug mode enabled', () => {
            beforeEach(() => {
                logger = createLogger('TestModule', { forceEnable: true });
            });

            test('debug outputs when debug mode is enabled', () => {
                logger.debug('debug message');
                expect(consoleSpy.debug).toHaveBeenCalledWith('[TestModule]', 'debug message');
            });

            test('info outputs when debug mode is enabled', () => {
                logger.info('info message');
                expect(consoleSpy.info).toHaveBeenCalledWith('[TestModule]', 'info message');
            });

            test('log outputs when debug mode is enabled', () => {
                logger.log('log message');
                expect(consoleSpy.log).toHaveBeenCalledWith('[TestModule]', 'log message');
            });

            test('timing logs performance', () => {
                const startTime = performance.now() - 100;
                logger.timing('Operation', startTime);

                expect(consoleSpy.log).toHaveBeenCalled();
                const call = consoleSpy.log.mock.calls[0];
                expect(call[0]).toBe('[TestModule]');
                expect(call[1]).toMatch(/Operation completed in \d+\.\d+ms/);
            });

            test('group creates console group', () => {
                const groupSpy = jest.spyOn(console, 'group').mockImplementation();
                const groupEndSpy = jest.spyOn(console, 'groupEnd').mockImplementation();

                logger.group('Test Group', () => {
                    logger.log('inside group');
                });

                expect(groupSpy).toHaveBeenCalledWith('[TestModule]', 'Test Group');
                expect(groupEndSpy).toHaveBeenCalled();
            });
        });
    });
});
