import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { isProtocolError, isSecurityError } from '../src/common.ts';
import { encode } from '../src/tl.ts';
import {
  createTcpTransport,
  MAX_FRAME,
  DC_ADDRESSES,
  encryptPacket,
  decryptPacket,
} from '../src/wire.ts';

function createSocket() {
  const socket = new EventEmitter(),
    writes = [];
  return Object.assign(socket, {
    writes,
    destroyed: false,
    setNoDelay() {},
    setKeepAlive() {},
    write(data, callback) {
      writes.push(Buffer.from(data));
      queueMicrotask(() => callback());
      return true;
    },
    destroy() {
      if (!socket.destroyed) {
        socket.destroyed = true;
        socket.emit('close');
      }
    },
  });
}
async function setup(t) {
  const socket = createSocket();
  const transport = createTcpTransport(2, {
    socketFactory(options) {
      assert.deepEqual(options, { host: DC_ADDRESSES[2], port: 443 });
      queueMicrotask(() => socket.emit('connect'));
      return socket;
    },
  });
  t.after(() => transport.close());
  await transport.connect();
  assert.equal(socket.writes[0].toString('hex'), 'eeeeeeee');
  return { socket, transport };
}
const frame = (body) => {
  const header = Buffer.alloc(4);
  header.writeInt32LE(body.length);
  return Buffer.concat([header, body]);
};
test(
  'Intermediate TCP framing handles fragmentation/coalescing' +
    ' and keeps endpoints pinned',
  async (t) => {
    const { socket, transport } = await setup(t),
      a = Buffer.from([1, 2, 3, 4]),
      b = Buffer.alloc(8, 5);
    const bytes = Buffer.concat([frame(a), frame(b)]),
      pending = transport.receive();
    for (let index = 0; index < bytes.length; index += 3)
      socket.emit('data', bytes.subarray(index, index + 3));
    assert.deepEqual(await pending, a);
    assert.deepEqual(await transport.receive(), b);
    await transport.send(a);
    assert.deepEqual(socket.writes.at(-1), frame(a));
    assert.throws(() => createTcpTransport(999), isProtocolError);
  },
);
test(
  'Transport rejects oversized/negative frames, incomplete' +
    ' connections and buffer flooding',
  async (t) => {
    for (const length of [-404, MAX_FRAME + 4, 3, 0]) {
      const { socket, transport } = await setup(t),
        header = Buffer.alloc(4);
      header.writeInt32LE(length);
      const pending = transport.receive();
      socket.emit('data', header);
      await assert.rejects(pending, isProtocolError);
      assert.ok(socket.destroyed);
    }
    const { socket, transport } = await setup(t),
      pending = transport.receive();
    socket.emit('data', Buffer.alloc(MAX_FRAME + 5));
    await assert.rejects(pending, isProtocolError);
  },
);
test(
  'Transport deadline cannot be extended indefinitely with' +
    ' partial-byte trickles',
  async (t) => {
    const { socket, transport } = await setup(t),
      bytes = frame(Buffer.alloc(4));
    let index = 0;
    const interval = setInterval(() => {
      if (index < bytes.length)
        socket.emit('data', bytes.subarray(index, ++index));
    }, 15);
    try {
      await assert.rejects(transport.receive(25), /timed out/);
    } finally {
      clearInterval(interval);
    }
  },
);

const authKey = Buffer.from(Array.from({ length: 256 }, (_, index) => index)),
  sessionId = Buffer.alloc(8, 3),
  body = encode({ _: 'MsgsAck', msgIds: [7n] });
test(
  'Packet encryption authenticates both directions and validates' +
    ' session/header',
  () => {
    for (const incoming of [true, false]) {
      const packet = encryptPacket({
        authKey,
        sessionId,
        salt: 123n,
        msgId: incoming ? 3n : 4n,
        seqNo: 1,
        body,
        incoming,
      });
      const decoded = decryptPacket(packet, authKey, sessionId, incoming);
      assert.deepEqual(decoded.body, body);
      assert.equal(decoded.salt, 123n);
      assert.throws(
        () => decryptPacket(packet, authKey, Buffer.alloc(8, 4), incoming),
        isSecurityError,
      );
      for (const offset of [0, 8, 23, 24, packet.length - 1]) {
        const tampered = Buffer.from(packet);
        tampered[offset] ^= 1;
        assert.throws(
          () => decryptPacket(tampered, authKey, sessionId, incoming),
          isSecurityError,
        );
      }
    }
  },
);
test(
  'Packet decryption rejects truncated ciphertext, wrong direction, wrong' +
    ' auth key and even server IDs',
  () => {
    const packet = encryptPacket({
      authKey,
      sessionId,
      salt: 123n,
      msgId: 3n,
      seqNo: 1,
      body,
      incoming: true,
    });
    assert.throws(
      () =>
        decryptPacket(
          packet.subarray(0, packet.length - 1),
          authKey,
          sessionId,
        ),
      isSecurityError,
    );
    assert.throws(
      () => decryptPacket(packet, authKey, sessionId, false),
      isSecurityError,
    );
    assert.throws(
      () => decryptPacket(packet, Buffer.alloc(256, 8), sessionId),
      isSecurityError,
    );
    const even = encryptPacket({
      authKey,
      sessionId,
      salt: 123n,
      msgId: 4n,
      seqNo: 1,
      body,
      incoming: true,
    });
    assert.throws(
      () => decryptPacket(even, authKey, sessionId),
      isSecurityError,
    );
  },
);
