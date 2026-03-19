/**
 * Crypto Module - Usage Examples
 *
 * Demonstrates how to use the encryption modules for file uploads and downloads.
 * These examples show integration patterns with Dropzone.js chunked uploads.
 *
 * @module crypto/examples
 */

import { CryptoEngine, isCryptoSupported } from '../src/encryption.js';
import { KeyManager, EncryptionMode } from '../src/key-manager.js';
import { ChunkProcessor } from '../src/chunk-processor.js';

/**
 * Example 1: Basic Upload Flow with Auto Encryption
 *
 * Demonstrates encrypting a file in chunks and preparing for upload.
 */
export async function exampleAutoEncryption() {
    console.log('=== Example 1: Auto Encryption ===');

    // Check browser support
    if (!isCryptoSupported()) {
        console.error('Web Crypto API not supported');
        return;
    }

    // Initialize crypto components
    const engine = new CryptoEngine();
    const keyManager = new KeyManager(engine, EncryptionMode.AUTO);
    const processor = new ChunkProcessor(engine);

    // Generate random encryption key
    await keyManager.generateRandomKey();
    console.log('Encryption key generated');

    // Export key for URL (to share with recipient)
    const keyForUrl = await keyManager.exportKeyForUrl();
    console.log('Key for URL fragment:', keyForUrl.substring(0, 20) + '...');

    // Simulate file chunks (5MB each)
    const chunkSize = 5 * 1024 * 1024; // 5MB
    const mockChunks = [
        new Blob(['Mock chunk 1 data '.repeat(1000)]),
        new Blob(['Mock chunk 2 data '.repeat(1000)]),
        new Blob(['Mock chunk 3 data '.repeat(1000)])
    ];

    // Encrypt each chunk
    const encryptedChunks = [];
    for (let i = 0; i < mockChunks.length; i++) {
        const { encryptedBlob, iv, size } = await processor.encryptChunkForUpload(
            keyManager.getKey(),
            mockChunks[i],
            i
        );
        console.log(`Chunk ${i} encrypted: ${size} bytes, IV: ${iv.length} bytes`);
        encryptedChunks.push(encryptedBlob);
    }

    // Get all chunk IVs for metadata
    const chunkIVs = processor.getChunkIVs();
    console.log(`Total chunk IVs: ${chunkIVs.length}`);

    // Create encrypted metadata
    const metadata = {
        originalName: 'example-file.pdf',
        size: mockChunks.reduce((sum, chunk) => sum + chunk.size, 0),
        mimeType: 'application/pdf',
        chunkIVs: chunkIVs
    };

    const encryptedMetadata = await engine.encryptMetadata(keyManager.getKey(), metadata);
    console.log('Metadata encrypted:', encryptedMetadata.substring(0, 40) + '...');

    // URL to share (key in fragment)
    const downloadUrl = `https://example.com/download/abc123#${keyForUrl}`;
    console.log('Share URL:', downloadUrl);

    console.log('\n');
}

/**
 * Example 2: Download Flow with Auto Encryption
 *
 * Demonstrates decrypting downloaded chunks using key from URL.
 */
export async function exampleAutoDecryption() {
    console.log('=== Example 2: Auto Decryption ===');

    // Simulate receiving key from URL fragment
    const urlFragment = 'QzRCN0Y5NjdBOEQyRTNGNEE1QjZDN0Q4RTlGMEExQjJDM0Q0RTVGNkE3QjhDOUQw';

    // Initialize crypto components
    const engine = new CryptoEngine();
    const keyManager = new KeyManager(engine, EncryptionMode.AUTO);
    const processor = new ChunkProcessor(engine);

    // Import key from URL
    await keyManager.importKeyFromUrl(urlFragment);
    console.log('Decryption key imported from URL');

    // Simulate encrypted metadata from server
    const encryptedMetadata = 'mock_encrypted_metadata_from_server';

    try {
        // In real scenario, decrypt metadata first
        // const metadata = await engine.decryptMetadata(keyManager.getKey(), encryptedMetadata);
        console.log('Metadata would be decrypted here');

        // Simulate downloading and decrypting chunks
        const mockEncryptedChunks = [
            // In reality, these would come from server
            new Blob(['encrypted chunk 1']),
            new Blob(['encrypted chunk 2'])
        ];

        const decryptedChunks = [];
        for (let i = 0; i < mockEncryptedChunks.length; i++) {
            // In real scenario with IV prefix
            // const decryptedBuffer = await processor.decryptDownloadedChunk(
            //     keyManager.getKey(),
            //     mockEncryptedChunks[i]
            // );
            console.log(`Chunk ${i} would be decrypted here`);
        }

        // Reassemble file
        // const completeFile = new Blob(decryptedChunks, { type: metadata.mimeType });
        console.log('File would be reassembled and downloaded');

    } catch (error) {
        console.error('Decryption failed:', error.message);
    }

    console.log('\n');
}

/**
 * Example 3: Password-Based Encryption
 *
 * Demonstrates using password instead of random key.
 */
export async function examplePasswordEncryption() {
    console.log('=== Example 3: Password Encryption ===');

    const userPassword = 'MySecurePassword123!';

    // Initialize crypto components
    const engine = new CryptoEngine();
    const keyManager = new KeyManager(engine, EncryptionMode.PASSWORD);
    const processor = new ChunkProcessor(engine);

    // Derive key from password
    const { key, salt } = await keyManager.deriveKeyFromPassword(userPassword);
    console.log('Key derived from password');

    // Get salt as base64url for storage
    const saltB64 = keyManager.getSaltAsBase64Url();
    console.log('Salt (must be stored):', saltB64);

    // Encrypt chunk
    const mockChunk = new Blob(['Sensitive data'.repeat(1000)]);
    const { encryptedBlob, iv } = await processor.encryptChunkForUpload(key, mockChunk, 0);
    console.log('Chunk encrypted with password-derived key');

    // For decryption, recipient needs:
    // 1. Password (entered by user)
    // 2. Salt (stored with file metadata)
    console.log('\nRecipient needs: password + salt to decrypt');

    console.log('\n');
}

/**
 * Example 4: Password-Based Decryption
 *
 * Demonstrates decrypting with password.
 */
export async function examplePasswordDecryption() {
    console.log('=== Example 4: Password Decryption ===');

    const userPassword = 'MySecurePassword123!';
    const saltB64 = 'mock_salt_from_metadata'; // Retrieved from file metadata

    // Initialize crypto components
    const engine = new CryptoEngine();
    const keyManager = new KeyManager(engine, EncryptionMode.PASSWORD);

    // Import salt
    try {
        // keyManager.importSaltFromBase64Url(saltB64);

        // Derive same key from password + salt
        // await keyManager.deriveKeyFromPassword(userPassword);
        console.log('Key re-derived from password and salt');

        // Now can decrypt chunks
        console.log('Ready to decrypt file chunks');

    } catch (error) {
        console.error('Wrong password or corrupted data');
    }

    console.log('\n');
}

/**
 * Example 5: Integration with Dropzone.js
 *
 * Demonstrates integrating encryption with Dropzone chunked uploads.
 */
export function exampleDropzoneIntegration() {
    console.log('=== Example 5: Dropzone Integration ===');

    const integrationCode = `
// In your upload page script
import { CryptoEngine, KeyManager, ChunkProcessor, EncryptionMode } from './crypto/index.js';

// Initialize encryption
const engine = new CryptoEngine();
const keyManager = new KeyManager(engine, EncryptionMode.AUTO);
await keyManager.generateRandomKey();
const processor = new ChunkProcessor(engine);

// Configure Dropzone
const dropzone = new Dropzone('#file-upload', {
    url: '/api/upload/chunk',
    chunking: true,
    chunkSize: 5 * 1024 * 1024, // 5MB chunks
    parallelChunkUploads: false,

    // Encrypt before upload
    transformFile: async function(file, done) {
        const chunkIndex = this.currentChunk || 0;

        // Encrypt chunk
        const { encryptedBlob } = await processor.encryptChunkForUpload(
            keyManager.getKey(),
            file,
            chunkIndex
        );

        // Return encrypted blob
        done(encryptedBlob);
    }
});

// After all chunks uploaded
dropzone.on('complete', async function(file) {
    // Get metadata
    const metadata = {
        originalName: file.name,
        size: file.size,
        mimeType: file.type,
        chunkIVs: processor.getChunkIVs()
    };

    // Encrypt metadata
    const encryptedMetadata = await engine.encryptMetadata(
        keyManager.getKey(),
        metadata
    );

    // Send to server
    await fetch('/api/upload/complete', {
        method: 'POST',
        body: JSON.stringify({
            transferToken: 'abc123',
            encryptedMetadata: encryptedMetadata
        })
    });

    // Get shareable URL
    const keyForUrl = await keyManager.exportKeyForUrl();
    const shareUrl = \`/download/abc123#\${keyForUrl}\`;
    console.log('Share this URL:', shareUrl);
});
`;

    console.log(integrationCode);
    console.log('\n');
}

/**
 * Example 6: Error Handling
 *
 * Demonstrates proper error handling patterns.
 */
export async function exampleErrorHandling() {
    console.log('=== Example 6: Error Handling ===');

    const engine = new CryptoEngine();

    try {
        // Wrong key length
        await engine.importKeyFromUrl('invalid_key');
    } catch (error) {
        console.log('✓ Caught invalid key error:', error.message);
    }

    try {
        // Wrong password
        const keyManager = new KeyManager(engine, EncryptionMode.PASSWORD);
        await keyManager.deriveKeyFromPassword('short'); // Too short
    } catch (error) {
        console.log('✓ Caught weak password error:', error.message);
    }

    try {
        // Missing key
        const processor = new ChunkProcessor(engine);
        await processor.encryptChunkForUpload(null, new Blob(['test']), 0);
    } catch (error) {
        console.log('✓ Caught missing key error:', error.message);
    }

    console.log('\nAll errors handled gracefully');
    console.log('\n');
}

/**
 * Example 7: Memory Cleanup
 *
 * Demonstrates proper cleanup of sensitive data.
 */
export async function exampleMemoryCleanup() {
    console.log('=== Example 7: Memory Cleanup ===');

    const engine = new CryptoEngine();
    const keyManager = new KeyManager(engine, EncryptionMode.AUTO);
    const processor = new ChunkProcessor(engine);

    await keyManager.generateRandomKey();
    console.log('Key generated and in memory');

    // Use for encryption...
    const chunk = new Blob(['test data']);
    await processor.encryptChunkForUpload(keyManager.getKey(), chunk, 0);

    // Clean up when done
    keyManager.clearKey();
    processor.clearChunkIVs();
    console.log('Sensitive data cleared from memory');

    console.log('\n');
}

/**
 * Example 8: Performance Testing
 *
 * Demonstrates measuring encryption performance.
 */
export async function examplePerformanceTesting() {
    console.log('=== Example 8: Performance Testing ===');

    const engine = new CryptoEngine();
    const keyManager = new KeyManager(engine, EncryptionMode.AUTO);
    const processor = new ChunkProcessor(engine);

    await keyManager.generateRandomKey();

    // Create 5MB chunk
    const chunkSize = 5 * 1024 * 1024;
    const mockData = new Uint8Array(chunkSize);
    crypto.getRandomValues(mockData);
    const chunk = new Blob([mockData]);

    // Measure encryption time
    const startTime = performance.now();
    const { encryptedBlob } = await processor.encryptChunkForUpload(
        keyManager.getKey(),
        chunk,
        0
    );
    const encryptTime = performance.now() - startTime;

    console.log(`Chunk size: ${(chunk.size / 1024 / 1024).toFixed(2)} MB`);
    console.log(`Encrypted size: ${(encryptedBlob.size / 1024 / 1024).toFixed(2)} MB`);
    console.log(`Encryption time: ${encryptTime.toFixed(2)} ms`);
    console.log(`Throughput: ${(chunk.size / 1024 / 1024 / (encryptTime / 1000)).toFixed(2)} MB/s`);

    // Check if under 500ms target
    if (encryptTime < 500) {
        console.log('✓ Performance target met (<500ms)');
    } else {
        console.log('⚠ Performance target not met (>500ms)');
    }

    console.log('\n');
}

/**
 * Run all examples
 */
export async function runAllExamples() {
    if (!isCryptoSupported()) {
        console.error('Web Crypto API not supported in this browser');
        return;
    }

    await exampleAutoEncryption();
    await exampleAutoDecryption();
    await examplePasswordEncryption();
    await examplePasswordDecryption();
    exampleDropzoneIntegration();
    await exampleErrorHandling();
    await exampleMemoryCleanup();
    await examplePerformanceTesting();

    console.log('All examples completed!');
}

// Auto-run if loaded directly
if (typeof window !== 'undefined' && window.location.search.includes('run-examples')) {
    runAllExamples().catch(console.error);
}
