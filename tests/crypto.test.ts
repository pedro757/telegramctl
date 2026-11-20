import test from 'node:test';
import assert from 'node:assert/strict';
import {
  generateKeyPairSync,
  privateDecrypt,
  constants,
  pbkdf2Sync,
  createHash,
} from 'node:crypto';
import {
  aesIge,
  xor,
  sha256,
  fromBE,
  toBE,
  modPow,
  secretModPow,
  createDh,
  validateDh,
  DH_PRIME,
  dhInRange,
  passwordCheck,
} from '../src/crypto.ts';
import {
  factorPQ,
  rsaPad,
  validateServerKeys,
  authenticateKey,
} from '../src/wire.ts';
import { encode } from '../src/tl.ts';
import { isSecurityError } from '../src/common.ts';
import { SERVER_KEYS } from '../src/protocol/keys.ts';

test(
  'AES-256-IGE matches an independent OpenSSL AES_ige_encrypt' + ' vector',
  () => {
    // Fixture generated with libcrypto AES_set_encrypt_key/AES_ige_encrypt,
    // not with this adapter. The tests themselves require only Node.
    const key = Buffer.from(Array.from({ length: 32 }, (_, index) => index));
    const iv = Buffer.from(
      Array.from({ length: 32 }, (_, index) => index + 32),
    );
    const plain = Buffer.from(Array.from({ length: 64 }, (_, index) => index));
    const expected = Buffer.from(
      '42e66e1a756cccf5b27acc47523ad074ee39bf54e3db37bbdf415df6b400' +
        'fca977f708327c9e9341cc3dc8efd31e76463daa65b1f0d0252f790d77f1' +
        '824a662c',
      'hex',
    );
    assert.deepEqual(aesIge(plain, key, iv), expected);
    assert.deepEqual(aesIge(expected, key, iv, true), plain);
    assert.throws(() => aesIge(Buffer.alloc(17), key, iv), isSecurityError);
  },
);
test('Only the Telegram production RSA fingerprint is pinned', () => {
  assert.deepEqual(
    [...SERVER_KEYS.keys()],
    [BigInt.asIntN(64, 0xd09d1d85de64fd85n)],
  );
  assert.doesNotThrow(validateServerKeys);
});
test(
  'Modern Telegram RSA padding decrypts and authenticates with' +
    ' independent native RSA',
  () => {
    const { privateKey, publicKey } = generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicExponent: 65537,
    });
    const n = fromBE(
      Buffer.from(publicKey.export({ format: 'jwk' }).n, 'base64url'),
    );
    const inner = Buffer.from('offline fake key-exchange inner data');
    const ciphertext = rsaPad(inner, n);
    const data = privateDecrypt(
      { key: privateKey, padding: constants.RSA_NO_PADDING },
      ciphertext,
    );
    const encrypted = data.subarray(32),
      key = xor(data.subarray(0, 32), sha256(encrypted));
    const clear = aesIge(encrypted, key, Buffer.alloc(32), true),
      padded = Buffer.from(clear.subarray(0, 192)).reverse();
    assert.deepEqual(padded.subarray(0, inner.length), inner);
    assert.deepEqual(clear.subarray(192), sha256(key, padded));
    assert.throws(() => rsaPad(Buffer.alloc(145), n), isSecurityError);
  },
);
test('Bounded native-bigint PQ factoring validates prime factors', async () => {
  const p = 1_000_000_007n,
    q = 1_000_000_009n;
  const factors = await factorPQ(toBE(p * q));
  assert.equal(fromBE(factors.p), p);
  assert.equal(fromBE(factors.q), q);
  await assert.rejects(factorPQ(Buffer.alloc(9)), isSecurityError);
  await assert.rejects(factorPQ(Buffer.from([0, 8])), isSecurityError);
});
test(
  'Native DH agrees on a secret and rejects unpinned' +
    ' primes/generators/unsafe public values',
  () => {
    const a = Buffer.alloc(256, 7),
      A = secretModPow(3n, a),
      client = createDh(3, A);
    assert.deepEqual(client.authKey, secretModPow(fromBE(client.publicKey), a));
    assert.ok(dhInRange(fromBE(client.publicKey)));
    assert.throws(() => validateDh(Buffer.alloc(256), 3), isSecurityError);
    assert.throws(() => validateDh(DH_PRIME, 2), isSecurityError);
    assert.throws(
      () => validateDh(DH_PRIME, 3, Buffer.from([1])),
      isSecurityError,
    );
  },
);
test(
  'Pinned DH generator rules reject 5 even with a safe-range' + ' public value',
  () => {
    const p = fromBE(DH_PRIME),
      A = secretModPow(3n, Buffer.alloc(256, 7));
    assert.equal(p % 5n, 3n);
    assert.ok(dhInRange(fromBE(A)));
    assert.throws(() => validateDh(DH_PRIME, 5, A), isSecurityError);
    assert.throws(() => createDh(5, A), isSecurityError);
    for (const generator of [3, 4, 7]) {
      assert.doesNotThrow(() => validateDh(DH_PRIME, generator, A));
      assert.equal(modPow(BigInt(generator), (p - 1n) / 2n, p), 1n);
    }
  },
);
for (const generator of [3, 5])
  test(`SRP generator ${generator} matches a fake server proof`, async () => {
    const digest = (...parts) => {
      const state = createHash('sha256');
      for (const part of parts) state.update(part);
      return state.digest();
    };
    const password = Buffer.from('  fake password with significant spaces  '),
      salt1 = Buffer.from('fake salt 1'),
      salt2 = Buffer.from('fake salt 2');
    const p = fromBE(DH_PRIME),
      g = BigInt(generator),
      gBytes = toBE(g, 256),
      b = 987654321123456789n;
    const h1 = digest(salt1, password, salt1),
      h2 = digest(salt2, h1, salt2);
    const x = fromBE(
      digest(salt2, pbkdf2Sync(h2, salt1, 100_000, 64, 'sha512'), salt2),
    );
    const v = modPow(g, x, p),
      k = fromBE(digest(DH_PRIME, gBytes));
    const B = (k * v + modPow(g, b, p)) % p,
      bBytes = toBE(B, 256);
    const info = {
      hasPassword: true,
      currentAlgo: {
        _: 'PasswordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow',
        salt1,
        salt2,
        p: DH_PRIME,
        g: generator,
      },
      srp_B: bBytes,
      srpId: 12n,
    };
    const proof = await passwordCheck(info, password),
      u = fromBE(digest(proof.A, bBytes));
    const secret = modPow((fromBE(proof.A) * modPow(v, u, p)) % p, b, p);
    const expected = digest(
      xor(digest(DH_PRIME), digest(gBytes)),
      digest(salt1),
      digest(salt2),
      proof.A,
      bBytes,
      digest(toBE(secret, 256)),
    );
    assert.deepEqual(proof.M1, expected);
    assert.equal(proof.srpId, 12n);
    assert.equal(
      password.toString(),
      '  fake password with significant spaces  ',
    );
    await assert.rejects(
      passwordCheck({ ...info, srp_B: Buffer.alloc(256) }, password),
      isSecurityError,
    );
    await assert.rejects(
      passwordCheck(
        { ...info, currentAlgo: { ...info.currentAlgo, p: Buffer.alloc(256) } },
        password,
      ),
      isSecurityError,
    );
  });
test(
  'Key exchange rejects a fake server nonce before trusting or' +
    ' factoring its answer',
  async () => {
    let sends = 0;
    const transport = {
      async send(bytes) {
        sends++;
        assert.equal(bytes.readBigUInt64LE(), 0n);
      },
      async receive() {
        const response = encode({
          _: 'ResPQ',
          nonce: Buffer.alloc(16),
          serverNonce: Buffer.alloc(16),
          pq: Buffer.from([1, 1]),
          serverPublicKeyFingerprints: [],
        });
        const header = Buffer.alloc(20);
        header.writeBigUInt64LE(3n, 8);
        header.writeInt32LE(response.length, 16);
        return Buffer.concat([header, response]);
      },
    };
    await assert.rejects(
      authenticateKey(transport, () => 4n, 2),
      /nonce/,
    );
    assert.equal(sends, 1);
  },
);
