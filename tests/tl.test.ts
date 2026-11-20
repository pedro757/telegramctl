import test from 'node:test';
import assert from 'node:assert/strict';
import { gzipSync } from 'node:zlib';
import { randomBytes } from 'node:crypto';
import {
  encode,
  decode,
  createReader,
  readBytes,
  tlBytes,
  MAX_BYTES,
  definitionFor,
  requestDefinition,
} from '../src/tl.ts';
import { isProtocolError } from '../src/common.ts';

test(
  'TL has a deterministic native-bigint fixture, including' +
    ' signed access hashes',
  () => {
    assert.equal(
      encode({ _: 'InputPeerChat', chatId: 42n }).toString('hex'),
      'b95ca9352a00000000000000',
    );
    const value = decode(
      encode({ _: 'InputPeerUser', userId: 123n, accessHash: -456n }),
    );
    assert.equal(value.userId, 123n);
    assert.equal(value.accessHash, -456n);
    assert.equal(Object.getPrototypeOf(value), null);
  },
);
test(
  'TL flags, two flag words, Unicode and optional false Bool' + ' round-trip',
  () => {
    const message = {
      _: 'Message',
      id: 2,
      out: true,
      offline: true,
      peerId: { _: 'PeerUser', userId: 5n },
      date: 1_800_000_000,
      message: 'Hello 🌍\n<untrusted>',
      replyTo: { _: 'MessageReplyHeader', replyToMsgId: 1 },
    };
    const value = decode(encode(message));
    assert.equal(value.message, message.message);
    assert.equal(value.offline, true);
    assert.equal(value.out, true);
    assert.equal(value.replyTo.replyToMsgId, 1);
    assert.equal(value.fromId, undefined);
    const settings = decode(
      encode({ _: 'InputPeerNotifySettings', silent: false, muteUntil: 0 }),
    );
    assert.equal(settings.silent, false);
    assert.equal(settings.muteUntil, 0);
  },
);
test('TL supports typed vectors and bounded compressed objects', () => {
  const encoded = encode(
    [{ _: 'User', id: 5n, firstName: 'Test' }],
    'Vector<User>',
  );
  assert.equal(decode(encoded, 'Vector<User>')[0].firstName, 'Test');
  const header = Buffer.from('a1cf7230', 'hex');
  const compressed = Buffer.concat([
    header,
    tlBytes(gzipSync(encode({ _: 'InputPeerChat', chatId: 7n }))),
  ]);
  assert.equal(decode(compressed).chatId, 7n);
});

test(
  'TL byte headers, zero padding and size limits survive writer' + ' growth',
  () => {
    for (const size of [
      0,
      1,
      127,
      128,
      253,
      254,
      255,
      512 * 1024 + 1,
      MAX_BYTES - 4,
    ]) {
      const bytes = Buffer.alloc(size, 0xab),
        encoded = tlBytes(bytes);
      const header = size < 254 ? 1 : 4;
      assert.equal(encoded[0], size < 254 ? size : 254);
      if (size >= 254) assert.equal(encoded.readUIntLE(1, 3), size);
      assert.equal(encoded.length, Math.ceil((size + header) / 4) * 4);
      assert.ok(encoded.subarray(size + header).every((byte) => byte === 0));
      assert.deepEqual(decode(encoded, 'bytes'), bytes);
    }
    assert.throws(() => tlBytes(Buffer.alloc(MAX_BYTES - 3)), isProtocolError);
    const object = {
      _: 'PQInnerDataDc',
      pq: Buffer.alloc(16 * 1024 + 1, 0x50),
      p: Buffer.alloc(16 * 1024 + 2, 0x60),
      q: Buffer.from([7]),
      nonce: Buffer.alloc(16),
      serverNonce: Buffer.alloc(16),
      newNonce: Buffer.alloc(32),
      dc: 2,
    };
    assert.deepEqual({ ...decode(encode(object)) }, object);
  },
);
test(
  'TL rejects missing shared-flag fields, incorrect types,' +
    ' unknown methods and IDs',
  () => {
    assert.throws(
      () => encode({ _: 'InputPeerChat', chatId: 42 }),
      isProtocolError,
    );
    assert.throws(
      () => encode({ _: 'InputPeerChat', chatId: 42n, ignoredParameter: true }),
      /Unknown TL field/,
    );
    assert.throws(
      () =>
        encode({
          _: 'Message',
          id: 2,
          peerId: { _: 'PeerUser', userId: 1n },
          date: 1,
          message: '',
          views: 2,
        }),
      /forwards/,
    );
    assert.throws(
      () => requestDefinition('payments.SendStarsForm'),
      /allowlist/,
    );
    assert.equal(definitionFor('messages.EditChatCreator').method, true);
    assert.equal(definitionFor('channels.EditCreator'), undefined);
    assert.throws(
      () => decode(Buffer.from('ffffffff', 'hex')),
      isProtocolError,
    );
    assert.throws(() => decode(encode({ _: 'auth.LogOut' })), isProtocolError);
  },
);
test(
  'TL rejects malformed lengths, vector markers/counts, padding' +
    ' and trailing bytes',
  () => {
    assert.throws(
      () => readBytes(createReader(Buffer.from([255]))),
      isProtocolError,
    );
    assert.throws(
      () => readBytes(createReader(Buffer.from([254, 1, 0, 0]))),
      isProtocolError,
    );
    assert.throws(
      () => readBytes(createReader(Buffer.from([1, 65, 1, 0]))),
      isProtocolError,
    );
    assert.throws(
      () => decode(Buffer.from('15c4b51cffffffff', 'hex'), 'Vector<User>'),
      isProtocolError,
    );
    assert.throws(
      () => decode(Buffer.from('15c4b51ca1860100', 'hex'), 'Vector<User>'),
      isProtocolError,
    );
    assert.throws(
      () => decode(Buffer.alloc(8), 'Vector<User>'),
      isProtocolError,
    );
    assert.throws(
      () =>
        decode(
          Buffer.concat([encode({ _: 'InputPeerEmpty' }), Buffer.alloc(4)]),
        ),
      isProtocolError,
    );
    assert.throws(
      () => createReader(Buffer.alloc(MAX_BYTES + 1)),
      isProtocolError,
    );
    const unknownFlag = encode({ _: 'InputPeerNotifySettings', muteUntil: 0 });
    unknownFlag.writeUInt32LE(0x80000004, 4);
    assert.throws(() => decode(unknownFlag), /Unsupported TL flag/);
  },
);
test('TL decompression bombs and deep recursion are bounded', () => {
  const bomb = Buffer.concat([
    Buffer.from('a1cf7230', 'hex'),
    tlBytes(gzipSync(Buffer.alloc(MAX_BYTES + 1))),
  ]);
  assert.throws(() => decode(bomb), isProtocolError);
  let object = { _: 'InputPeerUser', userId: 1n, accessHash: 1n };
  for (let i = 0; i < 100; i++)
    object = {
      _: 'InputPeerUserFromMessage',
      peer: object,
      msgId: 1,
      userId: 1n,
    };
  assert.throws(() => encode(object), isProtocolError);
  const compressed = Buffer.concat([
    Buffer.from('a1cf7230', 'hex'),
    tlBytes(gzipSync(encode({ _: 'InputPeerChat', chatId: 1n }))),
  ]);
  assert.throws(
    () => decode(compressed, 'Object', { nodes: 0, inflated: MAX_BYTES - 1 }),
    isProtocolError,
  );
  assert.throws(
    () =>
      decode(encode({ _: 'InputPeerChat', chatId: 1n }), 'Object', {
        nodes: 249_999,
        inflated: 0,
      }),
    isProtocolError,
  );
});
test(
  'TL random malformed-input probes fail without escaping the' +
    ' checked decoder',
  () => {
    for (let i = 0; i < 500; i++) {
      try {
        decode(randomBytes(i % 128));
      } catch (error) {
        assert.ok(isProtocolError(error), error.name);
      }
    }
  },
);
