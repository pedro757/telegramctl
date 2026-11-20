// Telegram's published transport and SRP formulas use Node/OpenSSL primitives.
import {
  createHash,
  createCipheriv,
  createDecipheriv,
  createDiffieHellman,
  pbkdf2,
  randomBytes,
  timingSafeEqual,
  type Hash,
} from 'node:crypto';
import { promisify } from 'node:util';
import { securityError } from './common.ts';

export { randomBytes };
type HashInput = Parameters<Hash['update']>[0];
export const hash = (algorithm: string, ...parts: HashInput[]) => {
  const digest = createHash(algorithm);
  for (const part of parts) digest.update(part);
  return digest.digest();
};
export const sha1 = (...parts: HashInput[]) => hash('sha1', ...parts);
export const sha256 = (...parts: HashInput[]) => hash('sha256', ...parts);
export const equal = (a: unknown, b: unknown) =>
  Buffer.isBuffer(a) &&
  Buffer.isBuffer(b) &&
  a.length === b.length &&
  timingSafeEqual(a, b);
export const fromBE = (bytes: Buffer) =>
  bytes.length ? BigInt(`0x${bytes.toString('hex')}`) : 0n;
export function toBE(value: bigint, length?: number) {
  if (typeof value !== 'bigint' || value < 0n)
    throw securityError('Invalid unsigned integer');
  let hex = value.toString(16);
  if (hex.length % 2) hex = `0${hex}`;
  const bytes = Buffer.from(hex, 'hex');
  if (length === undefined) return bytes;
  if (bytes.length > length)
    throw securityError('Integer exceeds expected size');
  return Buffer.concat([Buffer.alloc(length - bytes.length), bytes]);
}
export function longBytes(value: bigint) {
  const bytes = Buffer.alloc(8);
  bytes.writeBigUInt64LE(BigInt.asUintN(64, value));
  return bytes;
}
export const randomLong = () => randomBytes(8).readBigInt64LE();
export function xor(a: Buffer, b: Buffer) {
  if (a.length !== b.length) throw securityError('XOR length mismatch');
  const result = Buffer.alloc(a.length);
  for (let i = 0; i < result.length; i++) result[i] = a[i] ^ b[i];
  return result;
}

export function modPow(base: bigint, exponent: bigint, modulus: bigint) {
  // For public-input RSA encryption and factoring, not secret DH/SRP exponents.
  if (modulus <= 1n || exponent < 0n)
    throw securityError('Invalid modular arithmetic');
  let result = 1n;
  base = ((base % modulus) + modulus) % modulus;
  while (exponent) {
    if (exponent & 1n) result = (result * base) % modulus;
    base = (base * base) % modulus;
    exponent >>= 1n;
  }
  return result;
}

// Known DH prime from Telegram's authorization key exchange specification.
export const DH_PRIME = Buffer.from(
  'c71caeb9c6b1c9048e6c522f70f13f73980d40238e3e21c14934d037563d930f' +
    '48198a0aa7c14058229493d22530f4dbfa336f6e0ac925139543aed44cce7c37' +
    '20fd51f69458705ac68cd4fe6b6b13abdc9746512969328454f18faf8c595f64' +
    '2477fe96bb2a941d5bcd1d4ac8cc49880708fa9b378e3c4f3a9060bee67cf9a4' +
    'a4a695811051907e162753b56b0f6b410dba74d8a84b2a14b3144e0ef1284754' +
    'fd17ed950d5965b4b9dd46582db1178d169c6bc465b0d6ff9ca3928fef5b9ae4' +
    'e418fc15e83ebea0f87fa9ff5eed70050ded2849f47bf959d956850ce929851f' +
    '0d8115f635b105ee2e4e15d04b2454bf6f4fadf034b10403119cd8e3b92fcc5b',
  'hex',
);
const PRIME = fromBE(DH_PRIME);
const MARGIN = 1n << 1984n;
export const dhInRange = (value: bigint) =>
  value > MARGIN && value < PRIME - MARGIN;
export function validateDh(
  prime: Buffer,
  generator: number,
  publicValue?: Buffer,
) {
  // For this pinned prime only 3, 4 and 7 satisfy Telegram's DH residue
  // rules. In particular p % 5 == 3, so 5 is not a valid DH generator.
  if (!equal(prime, DH_PRIME) || ![3, 4, 7].includes(generator))
    throw securityError(
      'Unrecognized DH prime/generator; refusing automatic trust expansion',
    );
  if (publicValue !== undefined && !dhInRange(fromBE(publicValue)))
    throw securityError('Unsafe DH public value');
}
function validateSrp(prime: Buffer, generator: number) {
  // Password SRP has its own supported parameters; its generator allowlist
  // must not accidentally relax the authorization-key DH rules.
  if (!equal(prime, DH_PRIME) || ![3, 4, 5, 7].includes(generator))
    throw securityError(
      'Unrecognized SRP prime/generator; refusing automatic trust expansion',
    );
}
export function secretModPow(base: bigint, exponent: Buffer, generator = 3) {
  // Use native DH for all secret modular exponentiation, including SRP.
  const dh = createDiffieHellman(DH_PRIME, generator);
  dh.setPrivateKey(exponent);
  return dh.computeSecret(toBE(base, 256));
}
export function createDh(generator: number, serverPublic: Buffer) {
  validateDh(DH_PRIME, generator, serverPublic);
  for (let tries = 0; tries < 16; tries++) {
    const dh = createDiffieHellman(DH_PRIME, generator);
    // Telegram specifies a fresh 256-byte random exponent; do not rely on an
    // OpenSSL default private-exponent length chosen for a generic DH group.
    const exponent = randomBytes(256);
    let publicKey;
    try {
      dh.setPrivateKey(exponent);
      publicKey = dh.generateKeys();
    } finally {
      exponent.fill(0);
    }
    if (dhInRange(fromBE(publicKey)))
      return { publicKey, authKey: dh.computeSecret(serverPublic) };
  }
  throw securityError('Could not generate a safe DH public value');
}

export function aesIge(data: Buffer, key: Buffer, iv: Buffer, decrypt = false) {
  if (key.length !== 32 || iv.length !== 32 || !data.length || data.length % 16)
    throw securityError('Invalid AES-IGE sizes');
  const cipher = (decrypt ? createDecipheriv : createCipheriv)(
    'aes-256-ecb',
    key,
    null,
  );
  cipher.setAutoPadding(false);
  const output = Buffer.alloc(data.length);
  let previousCipher: Buffer = Buffer.from(iv.subarray(0, 16));
  let previousPlain: Buffer = Buffer.from(iv.subarray(16));
  for (let offset = 0; offset < data.length; offset += 16) {
    const input = data.subarray(offset, offset + 16);
    const block = decrypt
      ? xor(cipher.update(xor(input, previousPlain)), previousCipher)
      : xor(cipher.update(xor(input, previousCipher)), previousPlain);
    block.copy(output, offset);
    previousCipher = decrypt ? Buffer.from(input) : block;
    previousPlain = decrypt ? block : Buffer.from(input);
  }
  cipher.final();
  previousCipher.fill(0);
  previousPlain.fill(0);
  return output;
}

// Temporary AES key and IV for the authorization key exchange.
export function temporaryAes(serverNonce: Buffer, newNonce: Buffer) {
  const keyPrefix = sha1(newNonce, serverNonce);
  const shared = sha1(serverNonce, newNonce);
  const ivMiddle = sha1(newNonce, newNonce);
  return {
    key: Buffer.concat([keyPrefix, shared.subarray(0, 12)]),
    iv: Buffer.concat([shared.subarray(12), ivMiddle, newNonce.subarray(0, 4)]),
  };
}
// Direction-dependent AES key and IV for encrypted messages.
export function messageAes(authKey: Buffer, msgKey: Buffer, incoming: boolean) {
  const offset = incoming ? 8 : 0;
  const first = sha256(msgKey, authKey.subarray(offset, offset + 36));
  const second = sha256(authKey.subarray(offset + 40, offset + 76), msgKey);
  const combine = (outer: Buffer, inner: Buffer) =>
    Buffer.concat([
      outer.subarray(0, 8),
      inner.subarray(8, 24),
      outer.subarray(24),
    ]);
  return {
    key: combine(first, second),
    iv: combine(second, first),
  };
}

const pbkdf2Async = promisify(pbkdf2);
const saltedSha256 = (data: Buffer, salt: Buffer) => sha256(salt, data, salt);

// PH2 from https://core.telegram.org/api/srp
async function passwordHash(password: Buffer, salt1: Buffer, salt2: Buffer) {
  const inner = saltedSha256(password, salt1);
  const ph1 = saltedSha256(inner, salt2);
  inner.fill(0);
  try {
    const stretched = await pbkdf2Async(ph1, salt1, 100_000, 64, 'sha512');
    try {
      return saltedSha256(stretched, salt2);
    } finally {
      stretched.fill(0);
    }
  } finally {
    ph1.fill(0);
  }
}
export type PasswordParameters = {
  hasPassword?: boolean;
  currentAlgo?: {
    _: string;
    p: Buffer;
    g: number;
    salt1: Buffer;
    salt2: Buffer;
  };
  srp_B?: Buffer;
  srpId?: bigint;
};
export async function passwordCheck(
  info: PasswordParameters,
  password: Buffer,
) {
  const algo = info.currentAlgo;
  if (
    !info.hasPassword ||
    algo?._ !==
      'PasswordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow'
  )
    throw securityError('Unsupported Telegram password algorithm');
  validateSrp(algo.p, algo.g);
  if (
    !Buffer.isBuffer(algo.salt1) ||
    !Buffer.isBuffer(algo.salt2) ||
    algo.salt1.length > 256 ||
    algo.salt2.length > 256 ||
    !Buffer.isBuffer(info.srp_B) ||
    info.srp_B.length > 256 ||
    typeof info.srpId !== 'bigint'
  )
    throw securityError('Invalid SRP parameters');
  const serverValue = fromBE(info.srp_B);
  if (serverValue <= 0n || serverValue >= PRIME)
    throw securityError('Unsafe SRP server value');

  const { g, salt1, salt2 } = algo;
  const generator = BigInt(g);
  const generatorBytes = toBE(generator, 256);
  const serverPublic = toBE(serverValue, 256);
  const x = await passwordHash(password, salt1, salt2);
  const secrets = [x];
  try {
    const verifier = secretModPow(generator, x, g);
    secrets.push(verifier);
    const multiplier = fromBE(sha256(DH_PRIME, generatorBytes));
    const maskedVerifier = (multiplier * fromBE(verifier)) % PRIME;
    const base = (serverValue - maskedVerifier + PRIME) % PRIME;
    if (!dhInRange(base)) throw securityError('Unsafe SRP derived value');

    const privateValue = randomBytes(256);
    secrets.push(privateValue);
    const clientPublic = secretModPow(generator, privateValue, g);
    if (!dhInRange(fromBE(clientPublic)))
      throw securityError('Unsafe SRP client value');
    const scramble = fromBE(sha256(clientPublic, serverPublic));
    if (!scramble) throw securityError('Invalid SRP scrambling parameter');
    const exponent = toBE(fromBE(privateValue) + scramble * fromBE(x));
    secrets.push(exponent);
    const shared = secretModPow(base, exponent, g);
    secrets.push(shared);
    const sessionHash = sha256(shared);
    secrets.push(sessionHash);
    const proof = sha256(
      xor(sha256(DH_PRIME), sha256(generatorBytes)),
      sha256(salt1),
      sha256(salt2),
      clientPublic,
      serverPublic,
      sessionHash,
    );
    return {
      _: 'InputCheckPasswordSRP',
      srpId: info.srpId,
      A: clientPublic,
      M1: proof,
    };
  } finally {
    for (const secret of secrets) secret.fill(0);
  }
}
