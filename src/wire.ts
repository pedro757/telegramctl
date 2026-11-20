import { checkPrimeSync } from 'node:crypto';
import { createConnection, type Socket, type NetConnectOpts } from 'node:net';
import { setImmediate as yieldLoop } from 'node:timers/promises';
import {
  epochSeconds,
  isProtocolError,
  isSecurityError,
  protocolError,
  securityError,
} from './common.ts';
import {
  randomBytes,
  fromBE,
  toBE,
  equal,
  xor,
  sha1,
  sha256,
  modPow,
  aesIge,
  temporaryAes,
  createDh,
  validateDh,
  messageAes,
  longBytes,
} from './crypto.ts';
import { SERVER_KEYS } from './protocol/keys.ts';
import {
  encode,
  decode,
  createReader,
  readValue,
  remaining,
  tlBytes,
  MAX_BYTES,
  type TLObject,
} from './tl.ts';

// Intermediate TCP framing and pinned endpoints.
export const DC_ADDRESSES = Object.freeze({
  1: '149.154.175.50',
  2: '149.154.167.51',
  3: '149.154.175.100',
  4: '149.154.167.91',
  5: '149.154.171.5',
});
export const MAX_FRAME = 8 * 1024 * 1024 + 2048;

export type Transport = {
  connect(): Promise<void>;
  close(): void;
  receive(timeout?: number): Promise<Buffer>;
  send(data: Buffer): Promise<void>;
};
type Waiter = { resolve(): void; reject(error: unknown): void };

export function createTcpTransport(
  dcId: number,
  {
    socketFactory = createConnection,
  }: {
    socketFactory?: (options: NetConnectOpts) => Socket;
  } = {},
): Transport {
  if (!Object.hasOwn(DC_ADDRESSES, dcId))
    throw protocolError('Unknown Telegram DC');
  const host = DC_ADDRESSES[dcId as keyof typeof DC_ADDRESSES];
  let socket: Socket | undefined, waiter: Waiter | undefined;
  let failure: unknown;
  let chunks: (Buffer | undefined)[] = [],
    head = 0,
    offset = 0,
    size = 0,
    reading = false;

  async function connect() {
    if (socket || failure)
      throw protocolError('Transport instances cannot be reused');
    const connection = (socket = socketFactory({ host, port: 443 }));
    connection.setNoDelay(true);
    connection.setKeepAlive(true, 30_000);
    // Connect/read/write operations have their own absolute deadlines. A
    // global socket-idle timeout would kill legitimate OTP/2FA prompts.
    connection.on('error', () =>
      fail(protocolError('Telegram connection failed')),
    );
    connection.on('close', () =>
      fail(protocolError('Telegram connection closed')),
    );
    connection.on('data', (chunk: Buffer) => {
      if (
        size + chunk.length > MAX_FRAME + 4 ||
        chunks.length - head > 65_536
      ) {
        fail(protocolError('Telegram receive buffer exceeded limit'));
        return;
      }
      chunks.push(chunk);
      size += chunk.length;
      waiter?.resolve();
      waiter = undefined;
    });
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        reject(protocolError('Telegram connect timed out'));
        close();
      }, 20_000);
      connection.once('connect', () => {
        clearTimeout(timer);
        resolve(undefined);
      });
      connection.once('close', () => {
        clearTimeout(timer);
        reject(protocolError('Could not connect to Telegram'));
      });
    });
    await write(Buffer.from([0xee, 0xee, 0xee, 0xee]));
  }

  function fail(error: unknown) {
    if (!failure) failure = error;
    waiter?.reject(failure);
    waiter = undefined;
    if (socket && !socket.destroyed) socket.destroy();
  }

  function close() {
    fail(protocolError('Telegram transport closed'));
  }

  function consume(length: number) {
    offset += length;
    if (offset === chunks[head]!.length) {
      // Release consumed socket buffers immediately.
      chunks[head++] = undefined;
      offset = 0;
    }
  }

  async function take(length: number, deadline: number) {
    while (size < length) {
      if (failure) throw failure;
      const timeout = deadline - performance.now();
      if (timeout <= 0) throw protocolError('Telegram response timed out');
      await new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
          waiter = undefined;
          reject(protocolError('Telegram response timed out'));
        }, timeout);
        waiter = {
          resolve: () => {
            clearTimeout(timer);
            resolve(undefined);
          },
          reject: (error) => {
            clearTimeout(timer);
            reject(error);
          },
        };
      });
    }
    let data;
    const first = chunks[head]!;
    if (first.length - offset >= length) {
      data = first.subarray(offset, offset + length);
      consume(length);
    } else {
      data = Buffer.allocUnsafe(length);
      for (let written = 0; written < length;) {
        const chunk = chunks[head]!,
          count = Math.min(length - written, chunk.length - offset);
        chunk.copy(data, written, offset, offset + count);
        consume(count);
        written += count;
      }
    }
    size -= length;
    if (head === chunks.length) {
      chunks.length = 0;
      head = 0;
    }
    if (head > 1024) {
      chunks = chunks.slice(head);
      head = 0;
    }
    return data;
  }

  async function receive(timeout = 30_000) {
    if (reading)
      throw protocolError('Concurrent frame reads are not supported');
    reading = true;
    const deadline = performance.now() + timeout;
    try {
      const length = (await take(4, deadline)).readInt32LE();
      if (length < 4 || length > MAX_FRAME || length % 4)
        throw protocolError('Invalid Telegram frame length');
      return await take(length, deadline);
    } catch (error) {
      fail(error);
      throw error;
    } finally {
      reading = false;
    }
  }

  async function write(data: Buffer) {
    if (failure || !socket)
      throw failure || protocolError('Transport is not connected');
    const connection = socket;
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        reject(protocolError('Telegram write timed out'));
        close();
      }, 20_000);
      connection.write(data, (error) => {
        clearTimeout(timer);
        if (error) reject(protocolError('Telegram write failed'));
        else resolve(undefined);
      });
    });
  }

  async function send(data: Buffer) {
    if (
      !Buffer.isBuffer(data) ||
      !data.length ||
      data.length > MAX_FRAME ||
      data.length % 4
    )
      throw protocolError('Invalid outgoing frame');
    const header = Buffer.alloc(4);
    header.writeInt32LE(data.length);
    await write(Buffer.concat([header, data]));
  }

  return { connect, send, receive, close };
}

// Authorization key exchange and encrypted packets.
function gcd(a: bigint, b: bigint) {
  while (b) [a, b] = [b, a % b];
  return a;
}
export async function factorPQ(bytes: Buffer) {
  if (!Buffer.isBuffer(bytes) || bytes.length < 2 || bytes.length > 8)
    throw securityError('Invalid PQ size');
  const n = fromBE(bytes);
  if (n < 9n || !(n & 1n)) throw securityError('Invalid PQ value');
  for (let attempt = 0; attempt < 24; attempt++) {
    const c = (fromBE(randomBytes(8)) % (n - 1n)) + 1n;
    let x = (fromBE(randomBytes(8)) % (n - 2n)) + 2n,
      y = x,
      divisor = 1n;
    for (let step = 0; step < 131_072 && divisor === 1n; step++) {
      x = (x * x + c) % n;
      y = (y * y + c) % n;
      y = (y * y + c) % n;
      divisor = gcd(x > y ? x - y : y - x, n);
      if (step % 16_384 === 16_383) await yieldLoop();
    }
    if (divisor === 1n || divisor === n) continue;
    const p = divisor < n / divisor ? divisor : n / divisor,
      q = n / p;
    if (
      p * q !== n ||
      p >= 1n << 32n ||
      q >= 1n << 32n ||
      !checkPrimeSync(toBE(p), { checks: 32 }) ||
      !checkPrimeSync(toBE(q), { checks: 32 })
    )
      throw securityError('PQ factors are not valid primes');
    return { p: toBE(p), q: toBE(q) };
  }
  throw securityError('PQ factoring budget exceeded');
}

export function rsaPad(inner: Buffer, modulus: bigint) {
  if (inner.length > 144) throw securityError('RSA inner data exceeds limit');
  const padded = Buffer.concat([inner, randomBytes(192 - inner.length)]);
  try {
    for (let attempt = 0; attempt < 32; attempt++) {
      const key = randomBytes(32);
      const block = Buffer.concat([
        Buffer.from(padded).reverse(),
        sha256(key, padded),
      ]);
      const encrypted = aesIge(block, key, Buffer.alloc(32));
      const data = Buffer.concat([xor(key, sha256(encrypted)), encrypted]);
      key.fill(0);
      block.fill(0);
      const value = fromBE(data);
      if (value < modulus) return toBE(modPow(value, 65537n, modulus), 256);
    }
    throw securityError('RSA padding retry budget exceeded');
  } finally {
    padded.fill(0);
  }
}

export function validateServerKeys() {
  for (const [fingerprint, modulus] of SERVER_KEYS) {
    const computed = sha1(tlBytes(toBE(modulus)), tlBytes(toBE(65537n)))
      .subarray(12)
      .readBigInt64LE();
    if (computed !== fingerprint)
      throw securityError('Pinned RSA fingerprint mismatch');
  }
}
validateServerKeys();

type Nonces = { _: string; nonce: Buffer; serverNonce: Buffer };
type PqResponse = Nonces & {
  pq: Buffer;
  serverPublicKeyFingerprints: bigint[];
};
type DhResponse = Nonces & { encryptedAnswer: Buffer };
type DhInner = Nonces & {
  dhPrime: Buffer;
  g: number;
  gA: Buffer;
  serverTime: number;
};
type DhConfirmation = Nonces & { newNonceHash1: Buffer };

export async function authenticateKey(
  transport: Pick<Transport, 'send' | 'receive'>,
  nextId: () => bigint,
  dcId: number,
) {
  const nonce = randomBytes(16),
    newNonce = randomBytes(32);
  let temporary;
  const plain = async <T extends Nonces>(request: TLObject) => {
    const body = encode(request),
      header = Buffer.alloc(20);
    header.writeBigUInt64LE(nextId(), 8);
    header.writeInt32LE(body.length, 16);
    await transport.send(Buffer.concat([header, body]));
    const packet = await transport.receive();
    if (
      packet.length < 24 ||
      packet.length > 1024 * 1024 ||
      packet.readBigUInt64LE() !== 0n ||
      packet.readBigUInt64LE(8) === 0n ||
      !(packet.readBigUInt64LE(8) & 1n) ||
      packet.readInt32LE(16) !== packet.length - 20
    )
      throw securityError('Invalid unencrypted authentication response');
    return decode<T>(packet.subarray(20));
  };
  try {
    const pq = await plain<PqResponse>({ _: 'ReqPqMulti', nonce });
    if (
      pq._ !== 'ResPQ' ||
      !equal(pq.nonce, nonce) ||
      pq.serverNonce?.length !== 16 ||
      pq.serverPublicKeyFingerprints.length > 64
    )
      throw securityError('Invalid PQ response/nonce');
    const fingerprint = pq.serverPublicKeyFingerprints.find((value) =>
      SERVER_KEYS.has(value),
    );
    if (fingerprint === undefined)
      throw securityError('Telegram did not offer a pinned RSA key');
    const { p, q } = await factorPQ(pq.pq);
    const inner = encode({
      _: 'PQInnerDataDc',
      pq: pq.pq,
      p,
      q,
      nonce,
      serverNonce: pq.serverNonce,
      newNonce,
      dc: dcId,
    });
    const answer = await plain<DhResponse>({
      _: 'ReqDHParams',
      nonce,
      serverNonce: pq.serverNonce,
      p,
      q,
      publicKeyFingerprint: fingerprint,
      encryptedData: rsaPad(inner, SERVER_KEYS.get(fingerprint)!),
    });
    if (
      answer._ !== 'ServerDHParamsOk' ||
      !equal(answer.nonce, nonce) ||
      !equal(answer.serverNonce, pq.serverNonce)
    )
      throw securityError('Invalid DH response/nonce');
    temporary = temporaryAes(pq.serverNonce, newNonce);
    if (!answer.encryptedAnswer.length || answer.encryptedAnswer.length % 16)
      throw securityError('Invalid encrypted DH answer');
    const clear = aesIge(
      answer.encryptedAnswer,
      temporary.key,
      temporary.iv,
      true,
    );
    const reader = createReader(clear.subarray(20));
    const dh = readValue(reader) as DhInner;
    if (
      !equal(
        clear.subarray(0, 20),
        sha1(clear.subarray(20, 20 + reader.offset)),
      ) ||
      remaining(reader) > 15
    )
      throw securityError('DH inner hash/padding mismatch');
    if (
      dh._ !== 'ServerDHInnerData' ||
      !equal(dh.nonce, nonce) ||
      !equal(dh.serverNonce, pq.serverNonce)
    )
      throw securityError('DH inner nonce mismatch');
    validateDh(dh.dhPrime, dh.g, dh.gA);
    const offset = dh.serverTime - epochSeconds();
    if (!Number.isInteger(offset) || Math.abs(offset) > 86400)
      throw securityError(
        'Telegram clock offset exceeds one day; check the system clock',
      );
    const { publicKey, authKey } = createDh(dh.g, dh.gA);
    const clientInner = encode({
      _: 'ClientDHInnerData',
      nonce,
      serverNonce: pq.serverNonce,
      retryId: 0n,
      gB: publicKey,
    });
    const payload = Buffer.concat([sha1(clientInner), clientInner]);
    const padded = Buffer.concat([
      payload,
      randomBytes((16 - (payload.length % 16)) % 16),
    ]);
    const result = await plain<DhConfirmation>({
      _: 'SetClientDHParams',
      nonce,
      serverNonce: pq.serverNonce,
      encryptedData: aesIge(padded, temporary.key, temporary.iv),
    });
    const expected = sha1(
      newNonce,
      Buffer.from([1]),
      sha1(authKey).subarray(0, 8),
    ).subarray(4, 20);
    if (
      result._ !== 'DhGenOk' ||
      !equal(result.nonce, nonce) ||
      !equal(result.serverNonce, pq.serverNonce) ||
      !equal(result.newNonceHash1, expected)
    ) {
      authKey.fill(0);
      throw securityError('Telegram DH key confirmation failed');
    }
    clear.fill(0);
    padded.fill(0);
    payload.fill(0);
    clientInner.fill(0);
    inner.fill(0);
    return {
      authKey,
      timeOffset: offset,
      salt: xor(
        newNonce.subarray(0, 8),
        pq.serverNonce.subarray(0, 8),
      ).readBigInt64LE(),
    };
  } catch (error) {
    if (isSecurityError(error) || isProtocolError(error)) throw error;
    throw securityError('Telegram key exchange failed');
  } finally {
    nonce.fill(0);
    newNonce.fill(0);
    temporary?.key.fill(0);
    temporary?.iv.fill(0);
  }
}

export type Packet = {
  salt: bigint;
  msgId: bigint;
  seqNo: number;
  body: Buffer;
};
type PacketToSend = Packet & {
  authKey: Buffer;
  sessionId: Buffer;
  incoming?: boolean;
};

export function encryptPacket({
  authKey,
  sessionId,
  salt,
  msgId,
  seqNo,
  body,
  incoming = false,
}: PacketToSend) {
  if (
    authKey.length !== 256 ||
    sessionId.length !== 8 ||
    !Buffer.isBuffer(body) ||
    body.length > MAX_BYTES ||
    body.length % 4 ||
    seqNo < 0 ||
    !Number.isInteger(seqNo)
  )
    throw securityError('Invalid outgoing Telegram packet');
  const header = Buffer.alloc(32);
  longBytes(salt).copy(header);
  sessionId.copy(header, 8);
  header.writeBigUInt64LE(BigInt.asUintN(64, msgId), 16);
  header.writeInt32LE(seqNo, 24);
  header.writeInt32LE(body.length, 28);
  const padding =
    12 +
    ((16 - ((32 + body.length + 12) % 16)) % 16) +
    (randomBytes(1)[0] % 8) * 16;
  const clear = Buffer.concat([header, body, randomBytes(padding)]);
  const x = incoming ? 8 : 0;
  const msgKey = sha256(authKey.subarray(88 + x, 120 + x), clear).subarray(
    8,
    24,
  );
  const { key, iv } = messageAes(authKey, msgKey, incoming);
  try {
    return Buffer.concat([
      sha1(authKey).subarray(12),
      msgKey,
      aesIge(clear, key, iv),
    ]);
  } finally {
    clear.fill(0);
    key.fill(0);
    iv.fill(0);
  }
}

export function decryptPacket(
  packet: Buffer,
  authKey: Buffer,
  sessionId: Buffer,
  incoming = true,
): Packet {
  if (
    authKey.length !== 256 ||
    sessionId.length !== 8 ||
    packet.length < 72 ||
    packet.length > MAX_BYTES + 1080 ||
    (packet.length - 24) % 16
  )
    throw securityError('Invalid encrypted packet size');
  if (!equal(packet.subarray(0, 8), sha1(authKey).subarray(12)))
    throw securityError('Telegram auth key ID mismatch');
  const msgKey = packet.subarray(8, 24),
    { key, iv } = messageAes(authKey, msgKey, incoming);
  const clear = aesIge(packet.subarray(24), key, iv, true);
  key.fill(0);
  iv.fill(0);
  try {
    const x = incoming ? 8 : 0;
    if (
      !equal(
        msgKey,
        sha256(authKey.subarray(88 + x, 120 + x), clear).subarray(8, 24),
      )
    )
      throw securityError('Telegram message authentication failed');
    if (!equal(sessionId, clear.subarray(8, 16)))
      throw securityError('Telegram session ID mismatch');
    const length = clear.readInt32LE(28),
      padding = clear.length - 32 - length;
    const msgId = clear.readBigUInt64LE(16),
      seqNo = clear.readInt32LE(24);
    if (
      length < 4 ||
      length > MAX_BYTES ||
      length % 4 ||
      padding < 12 ||
      padding > 1024 ||
      seqNo < 0 ||
      (incoming && !(msgId & 1n))
    )
      throw securityError('Invalid Telegram message header or padding');
    return {
      salt: clear.readBigInt64LE(),
      msgId,
      seqNo,
      body: Buffer.from(clear.subarray(32, 32 + length)),
    };
  } finally {
    clear.fill(0);
  }
}
