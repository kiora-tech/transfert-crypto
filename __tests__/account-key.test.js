/**
 * @jest-environment node
 *
 * Node environment on purpose: jsdom does not ship a working WebCrypto,
 * Node >= 20 does. PBKDF2 iterations are lowered to keep the suite fast —
 * the iteration count is a parameter, not the behaviour under test.
 */
import { describe, expect, test } from '@jest/globals';

import {
    ACCOUNT_KEY_VERSION,
    enrollAccount,
    generateAccountKey,
    issueRecoveryEnvelope,
    recoverAccount,
    rotatePassphrase,
    unlockAccount,
} from '../src/account-key.js';
import { decryptKeyWithKey, encryptKeyWithKey, exportKeyAsB64Url } from '../src/master-key.js';

const ITER = 1000;
const SUBJECT = 'oidc-sub-1234567890';
const SALT_PREFIX = 'zerotrust-test-account-v1-';
const PASSPHRASE = 'correct horse battery staple 9!';

describe('account-key', () => {
    test('enroll → unlock roundtrip restores the same K_account', async () => {
        const enrolled = await enrollAccount(PASSPHRASE, SUBJECT, SALT_PREFIX, ITER);

        expect(enrolled.version).toBe(ACCOUNT_KEY_VERSION);
        expect(typeof enrolled.passphraseEnvelope).toBe('string');
        expect(enrolled.recoveryCode).toMatch(/^[0-9A-Z]{4}(-[0-9A-Z]{4})+$/);

        const { accountKey } = await unlockAccount(PASSPHRASE, SUBJECT, SALT_PREFIX, enrolled.passphraseEnvelope, ITER);

        expect(await exportKeyAsB64Url(accountKey)).toBe(await exportKeyAsB64Url(enrolled.accountKey));
    });

    test('wrong passphrase fails fast with AccountUnlockError (the verifier)', async () => {
        const { passphraseEnvelope } = await enrollAccount(PASSPHRASE, SUBJECT, SALT_PREFIX, ITER);

        await expect(
            unlockAccount('wrong passphrase entirely', SUBJECT, SALT_PREFIX, passphraseEnvelope, ITER),
        ).rejects.toMatchObject({ name: 'AccountUnlockError' });
    });

    test('recovery code restores K_account, with lenient formatting', async () => {
        const enrolled = await enrollAccount(PASSPHRASE, SUBJECT, SALT_PREFIX, ITER);

        // lowercase, no dashes, ambiguous chars: normalizeRecoveryCode territory
        const messy = enrolled.recoveryCode.toLowerCase().replaceAll('-', '');
        const accountKey = await recoverAccount(messy, SUBJECT, SALT_PREFIX, enrolled.recoveryEnvelope, ITER);

        expect(await exportKeyAsB64Url(accountKey)).toBe(await exportKeyAsB64Url(enrolled.accountKey));
    });

    test('wrong recovery code fails with AccountUnlockError', async () => {
        const enrolled = await enrollAccount(PASSPHRASE, SUBJECT, SALT_PREFIX, ITER);
        const wrong = enrolled.recoveryCode.replace(/^..../, 'AAAA');

        await expect(
            recoverAccount(wrong, SUBJECT, SALT_PREFIX, enrolled.recoveryEnvelope, ITER),
        ).rejects.toMatchObject({ name: 'AccountUnlockError' });
    });

    test('passphrase rotation re-wraps K_account without touching data keys', async () => {
        const enrolled = await enrollAccount(PASSPHRASE, SUBJECT, SALT_PREFIX, ITER);

        // a data key wrapped under K_account before rotation…
        const dataKey = await generateAccountKey();
        const wrappedDataKey = await encryptKeyWithKey(enrolled.accountKey, dataKey);

        const rotated = await rotatePassphrase('a brand new passphrase 7?', SUBJECT, SALT_PREFIX, enrolled.accountKey, ITER);

        // …is still unwrappable after unlocking with the NEW envelope,
        const { accountKey } = await unlockAccount('a brand new passphrase 7?', SUBJECT, SALT_PREFIX, rotated.passphraseEnvelope, ITER);
        const unwrappedDataKey = await decryptKeyWithKey(accountKey, wrappedDataKey);
        expect(await exportKeyAsB64Url(unwrappedDataKey)).toBe(await exportKeyAsB64Url(dataKey));

        // and the old passphrase no longer opens the new envelope.
        await expect(
            unlockAccount(PASSPHRASE, SUBJECT, SALT_PREFIX, rotated.passphraseEnvelope, ITER),
        ).rejects.toMatchObject({ name: 'AccountUnlockError' });
    });

    test('recovery rotation: new code works, old envelope is independent', async () => {
        const enrolled = await enrollAccount(PASSPHRASE, SUBJECT, SALT_PREFIX, ITER);

        const reissued = await issueRecoveryEnvelope(enrolled.accountKey, SUBJECT, SALT_PREFIX, ITER);
        expect(reissued.recoveryCode).not.toBe(enrolled.recoveryCode);

        const accountKey = await recoverAccount(reissued.recoveryCode, SUBJECT, SALT_PREFIX, reissued.recoveryEnvelope, ITER);
        expect(await exportKeyAsB64Url(accountKey)).toBe(await exportKeyAsB64Url(enrolled.accountKey));
    });

    test('domain separation: a recovery code used as passphrase opens nothing', async () => {
        const enrolled = await enrollAccount(PASSPHRASE, SUBJECT, SALT_PREFIX, ITER);

        await expect(
            unlockAccount(enrolled.recoveryCode, SUBJECT, SALT_PREFIX, enrolled.recoveryEnvelope, ITER),
        ).rejects.toMatchObject({ name: 'AccountUnlockError' });
    });

    test('garbage recovery input is rejected before any KDF work', async () => {
        await expect(
            recoverAccount('not!a@code', SUBJECT, SALT_PREFIX, 'whatever', ITER),
        ).rejects.toMatchObject({ name: 'AccountUnlockError' });
    });
});
