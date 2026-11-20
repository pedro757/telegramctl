import test from 'node:test';
import assert from 'node:assert/strict';
import { gzipSync } from 'node:zlib';
import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { createMediaRpc, createRpcClient } from '../src/rpc.ts';
import { aesIge, messageAes } from '../src/crypto.ts';
import { encryptPacket, decryptPacket } from '../src/wire.ts';
import {
  encode,
  decode,
  createReader,
  readValue,
  readBytes,
  readUint,
  readInt,
  readLong,
  finish,
  tlBytes,
  definitionFor,
  LAYER,
} from '../src/tl.ts';
import {
  now,
  isSecurityError,
  protocolError,
  isProtocolError,
  isRpcError,
  isAmbiguousMutationError,
} from '../src/common.ts';
import { scratch, session } from './support.ts';
import { createTelegram } from '../src/telegram.ts';
import { openAttachment } from '../src/files.ts';

const uint = (value) => {
  const bytes = Buffer.alloc(4);
  bytes.writeUInt32LE(value);
  return bytes;
};
const long = (value) => {
  const bytes = Buffer.alloc(8);
  bytes.writeBigInt64LE(value);
  return bytes;
};
function rpcResult(id, payload) {
  return Buffer.concat([uint(0xf35c6d01), long(id), payload]);
}

function createServer(data, handler) {
  const queue = [],
    requests = [],
    acks = [];
  let serial = 0n;
  function incoming(
    body,
    { sessionId = server.sessionId, salt = data.salt, seqNo = 1, msgId } = {},
  ) {
    serial += 4n;
    const id =
      msgId ??
      (((now().epochNanoseconds << 32n) / 1_000_000_000n) & ~3n) + serial + 1n;
    return encryptPacket({
      authKey: data.authKey,
      sessionId,
      salt,
      msgId: id,
      seqNo,
      body,
      incoming: true,
    });
  }
  async function send(packet) {
    const { key, iv } = messageAes(data.authKey, packet.subarray(8, 24), false);
    const clear = aesIge(packet.subarray(24), key, iv, true);
    server.sessionId = Buffer.from(clear.subarray(8, 16));
    clear.fill(0);
    key.fill(0);
    iv.fill(0);
    const decoded = decryptPacket(
      packet,
      data.authKey,
      server.sessionId,
      false,
    );
    if (decoded.body.readUInt32LE() === definitionFor('MsgsAck').id) {
      acks.push(decode(decoded.body));
      if (server.failAcks) throw protocolError('fake ACK failure');
      return;
    }
    requests.push(decoded);
    await server.handler(decoded, server);
  }
  async function receive() {
    if (!queue.length) throw protocolError('fake response missing');
    return queue.shift();
  }
  const server = {
    data,
    handler,
    queue,
    requests,
    acks,
    incoming,
    send,
    receive,
    async connect() {},
    close() {},
  };
  return server;
}
async function setup(t, handler, overrides = {}) {
  const data = { ...session(), ...overrides };
  data.authKey = Buffer.from(Array.from({ length: 256 }, (_, index) => index));
  const server = createServer(data, handler),
    client = createRpcClient(data, { transportFactory: () => server });
  await client.open();
  t.after(() => client.close());
  return { client, server, data };
}
const users = () =>
  encode(
    [{ _: 'User', id: 1n, firstName: 'Fake', self: true }],
    'Vector<User>',
  );

test(
  'RPC client initializes the negotiated layer once, decodes typed' +
    ' RPC results and ACKs content',
  async (t) => {
    const { client, server } = await setup(t, (request, fake) =>
      fake.queue.push(fake.incoming(rpcResult(request.msgId, users()))),
    );
    assert.equal(
      (
        await client.invoke('users.GetUsers', { id: [{ _: 'InputUserSelf' }] })
      )[0].id,
      1n,
    );
    const reader = createReader(server.requests[0].body);
    assert.equal(readUint(reader), definitionFor('InvokeWithLayer').id);
    assert.equal(readInt(reader), LAYER);
    assert.equal(readUint(reader), definitionFor('InitConnection').id);
    assert.equal(readUint(reader), 0);
    assert.equal(readInt(reader), 12345);
    assert.equal(readValue(reader, 'string'), 'telegram-cli'); // deviceModel
    assert.equal(
      readValue(reader, 'string'),
      `Node.js ${process.version} ${process.platform}`,
    );
    for (let index = 0; index < 4; index++) readValue(reader, 'string');
    assert.equal(readUint(reader), definitionFor('InvokeWithoutUpdates').id);
    assert.equal(readUint(reader), definitionFor('users.GetUsers').id);
    await client.invoke('users.GetUsers', { id: [{ _: 'InputUserSelf' }] });
    assert.equal(
      server.requests[1].body.readUInt32LE(),
      definitionFor('InvokeWithoutUpdates').id,
    );
    assert.equal(server.acks.length, 2);
    assert.ok(server.requests[0].seqNo % 2 === 1);
    assert.ok(server.requests[1].msgId > server.requests[0].msgId);
  },
);
test('Image lookup and download use typed encrypted replies', async (t) => {
  const dir = await scratch(t);
  const bytes = Buffer.from('89504e470d0a1a0a00010203', 'hex');
  const { client, data, server } = await setup(t, (request, fake) => {
    let payload;
    if (fake.requests.length === 1) payload = users();
    else {
      const reader = createReader(request.body);
      assert.equal(readUint(reader), definitionFor('InvokeWithoutUpdates').id);
      if (fake.requests.length === 2) {
        assert.equal(readUint(reader), 0x63c66506);
        assert.equal(readUint(reader), 0x1cb5c415);
        assert.equal(readInt(reader), 1);
        assert.equal(readValue(reader, 'InputMessage').id, 7);
        payload = encode({
          _: 'messages.Messages',
          messages: [
            {
              _: 'Message',
              id: 7,
              peerId: { _: 'PeerUser', userId: 1n },
              date: 100,
              message: 'Saved image',
              media: {
                _: 'MessageMediaDocument',
                document: {
                  _: 'Document',
                  id: 8n,
                  accessHash: 9n,
                  fileReference: Buffer.from([10]),
                  date: 100,
                  mimeType: 'image/png',
                  size: BigInt(bytes.length),
                  dcId: data.dcId,
                  attributes: [],
                },
              },
            },
          ],
          topics: [],
          chats: [],
          users: [],
        });
      } else {
        assert.equal(readUint(reader), 0xbe5335be);
        assert.equal(readUint(reader), 0); // Don't opt in to CDN redirects.
        const location = readValue(reader, 'InputFileLocation');
        assert.equal(location._, 'InputDocumentFileLocation');
        assert.equal(location.id, 8n);
        assert.equal(readLong(reader), 0n);
        assert.equal(readInt(reader), 524_288);
        payload = encode({
          _: 'upload.File',
          type: { _: 'storage.FilePng' },
          mtime: 100,
          bytes,
        });
      }
      finish(reader);
    }
    fake.queue.push(fake.incoming(rpcResult(request.msgId, payload)));
  });
  const telegram = createTelegram(client, {
    mediaRpc: createMediaRpc(client, data, assert.fail, assert.fail),
  });
  await telegram.me();
  const result = await telegram.downloadMedia('self', 7, dir);
  assert.deepEqual(await readFile(result.path), bytes);
  assert.equal(server.requests.length, 3);
  await assert.rejects(
    client.invoke('DestroyAuthKey', {}, { mutation: true }),
    /saved session key/,
  );
  assert.equal(server.requests.length, 3);
});

test(
  'An attachment crosses the encrypted connection before' +
    ' one correlated media publication',
  async (t) => {
    const filename = join(await scratch(t), 'fixture.bin'),
      bytes = Buffer.from([0, 1, 127, 128, 255]);
    await writeFile(filename, bytes);
    const attachment = await openAttachment(filename);
    t.after(() => attachment.close());
    let fileId;
    const { client, server } = await setup(t, (request, fake) => {
      let payload;
      if (fake.requests.length === 1) payload = users();
      else {
        const reader = createReader(request.body);
        assert.equal(
          readUint(reader),
          definitionFor('InvokeWithoutUpdates').id,
        );
        if (fake.requests.length === 2) {
          assert.equal(readUint(reader), 0xb304a621);
          fileId = readLong(reader);
          assert.notEqual(fileId, 0n);
          assert.equal(readInt(reader), 0);
          assert.deepEqual(readBytes(reader), bytes);
          payload = encode(true, 'Bool');
        } else {
          assert.equal(readUint(reader), 0x0330e77f);
          assert.equal(readUint(reader), 0); // No optional sendMedia flags.
          assert.equal(readValue(reader, 'InputPeer')._, 'InputPeerSelf');
          const media = readValue(reader, 'InputMedia');
          assert.equal(media._, 'InputMediaUploadedDocument');
          assert.ok(media.forceFile);
          assert.equal(media.file.id, fileId);
          assert.equal(media.file.parts, 1);
          assert.equal(media.attributes[0].fileName, 'fixture.bin');
          assert.equal(readValue(reader, 'string'), 'Fake caption');
          const randomId = readLong(reader);
          payload = encode(
            {
              _: 'UpdateShort',
              update: { _: 'UpdateMessageID', id: 42, randomId },
              date: 1,
            },
            'Updates',
          );
        }
        finish(reader);
      }
      fake.queue.push(fake.incoming(rpcResult(request.msgId, payload)));
    });
    const result = await createTelegram(client).send('self', 'Fake caption', {
      attachment,
    });
    assert.equal(result.messageId, 42);
    assert.equal(server.requests.length, 3);
    assert.equal(server.acks.length, 3);
  },
);
test(
  'Authenticated correlated clock rejections recover' +
    ' positive/negative stale offsets',
  async (t) => {
    for (const timeOffset of [600, -600]) {
      const { client, server } = await setup(
        t,
        (request, fake) => {
          if (fake.requests.length === 1)
            fake.queue.push(
              fake.incoming(
                encode({
                  _: 'BadMsgNotification',
                  badMsgId: request.msgId,
                  badMsgSeqno: request.seqNo,
                  errorCode: timeOffset > 0 ? 17 : 16,
                }),
              ),
            );
          else
            fake.queue.push(fake.incoming(rpcResult(request.msgId, users())));
        },
        { timeOffset },
      );
      assert.equal(
        (
          await client.invoke('users.GetUsers', {
            id: [{ _: 'InputUserSelf' }],
          })
        )[0].id,
        1n,
      );
      assert.equal(server.requests.length, 2);
      assert.ok(Math.abs(client.exportSession().timeOffset) < 5);
      const seconds = Number(server.requests[1].msgId >> 32n);
      assert.ok(
        Math.abs(seconds - Number(now().epochNanoseconds / 1000000000n)) < 5,
      );
    }
  },
);
test(
  'Clock recovery does not bypass salt, session,' +
    ' request/sequence, code, bounds or ordinary freshness checks',
  async (t) => {
    for (const attack of [
      'salt',
      'session',
      'request',
      'sequence',
      'code',
      'direction',
      'bounds',
      'ordinary',
    ]) {
      const { client, server } = await setup(
        t,
        (request, fake) => {
          const body =
            attack === 'ordinary'
              ? rpcResult(request.msgId, users())
              : encode({
                  _: 'BadMsgNotification',
                  badMsgId:
                    attack === 'request' ? request.msgId + 4n : request.msgId,
                  badMsgSeqno:
                    attack === 'sequence' ? request.seqNo + 2 : request.seqNo,
                  errorCode:
                    attack === 'code' ? 32 : attack === 'direction' ? 16 : 17,
                });
          fake.queue.push(
            fake.incoming(body, {
              ...(attack === 'salt' ? { salt: 999n } : {}),
              ...(attack === 'session'
                ? { sessionId: Buffer.alloc(8, 9) }
                : {}),
              ...(attack === 'bounds'
                ? {
                    msgId:
                      ((now().epochNanoseconds / 1000000000n - 90000n) << 32n) |
                      1n,
                  }
                : {}),
            }),
          );
        },
        { timeOffset: 600 },
      );
      await assert.rejects(
        client.invoke('users.GetUsers', { id: [{ _: 'InputUserSelf' }] }),
        attack === 'code' ? isProtocolError : isSecurityError,
        attack,
      );
      assert.equal(server.requests.length, 1);
      assert.equal(client.exportSession().timeOffset, 600);
    }
  },
);
test(
  'RPC client decodes gzip-wrapped vectors and does not' +
    ' confuse a known success with failed ACK delivery',
  async (t) => {
    const { client, server } = await setup(t, (request, fake) => {
      const compressed = Buffer.concat([
        uint(0x3072cfa1),
        tlBytes(gzipSync(users())),
      ]);
      fake.queue.push(fake.incoming(rpcResult(request.msgId, compressed)));
    });
    server.failAcks = true;
    assert.equal(
      (
        await client.invoke('users.GetUsers', { id: [{ _: 'InputUserSelf' }] })
      )[0].firstName,
      'Fake',
    );
  },
);
test(
  'RPC client accepts correlated explicit salt rejection, retries' +
    ' at most boundedly and preserves request bytes',
  async (t) => {
    const { client, server } = await setup(t, (request, fake) => {
      if (fake.requests.length === 1)
        fake.queue.push(
          fake.incoming(
            encode({
              _: 'BadServerSalt',
              badMsgId: request.msgId,
              badMsgSeqno: request.seqNo,
              errorCode: 48,
              newServerSalt: 999n,
            }),
            { salt: 999n },
          ),
        );
      else
        fake.queue.push(
          fake.incoming(rpcResult(request.msgId, users()), { salt: 999n }),
        );
    });
    await client.invoke('users.GetUsers', { id: [{ _: 'InputUserSelf' }] });
    assert.equal(server.requests.length, 2);
    assert.deepEqual(server.requests[0].body, server.requests[1].body);
    assert.equal(client.exportSession().salt, 999n);
  },
);
test(
  'An imported unknown salt accepts only a correlated rejection' +
    ' under the requested zero salt',
  async (t) => {
    const data = { ...session(), salt: 0n };
    const server = createServer(data, (request, fake) => {
      if (fake.requests.length === 1)
        fake.queue.push(
          fake.incoming(
            encode({
              _: 'BadServerSalt',
              badMsgId: request.msgId,
              badMsgSeqno: request.seqNo,
              errorCode: 48,
              newServerSalt: 999n,
            }),
            { salt: 0n },
          ),
        );
      else
        fake.queue.push(
          fake.incoming(rpcResult(request.msgId, users()), { salt: 999n }),
        );
    });
    const client = createRpcClient(data, { transportFactory: () => server });
    t.after(() => client.close());
    await client.open();
    assert.equal(
      (
        await client.invoke('users.GetUsers', { id: [{ _: 'InputUserSelf' }] })
      )[0].id,
      1n,
    );
    assert.equal(server.requests.length, 2);
    assert.equal(client.exportSession().salt, 999n);
  },
);
test(
  'RPC client validates correlated new-session/container messages' +
    ' and nested RPC results',
  async (t) => {
    const { client } = await setup(t, (request, fake) => {
      const outerId =
        (((now().epochNanoseconds << 32n) / 1_000_000_000n) & ~3n) + 101n;
      const inner = [
        encode({
          _: 'NewSessionCreated',
          firstMsgId: request.msgId,
          uniqueId: 1n,
          serverSalt: 999n,
        }),
        rpcResult(request.msgId, users()),
      ];
      const packed = Buffer.concat([
        uint(0x73f1f8dc),
        uint(2),
        ...inner.flatMap((body, index) => [
          long(outerId - BigInt(8 - index * 4)),
          uint(1),
          uint(body.length),
          body,
        ]),
      ]);
      fake.queue.push(fake.incoming(packed, { msgId: outerId, seqNo: 0 }));
    });
    assert.equal(
      (
        await client.invoke('users.GetUsers', { id: [{ _: 'InputUserSelf' }] })
      )[0].id,
      1n,
    );
    assert.equal(client.exportSession().salt, 999n);
  },
);
test(
  'RPC client propagates safe errors without request secrets' +
    ' and does not auto-retry flood waits',
  async (t) => {
    const { client, server } = await setup(t, (request, fake) =>
      fake.queue.push(
        fake.incoming(
          rpcResult(
            request.msgId,
            encode({
              _: 'RpcError',
              errorCode: 420,
              errorMessage: 'FLOOD_WAIT_90',
            }),
          ),
        ),
      ),
    );
    await assert.rejects(
      client.invoke('users.GetUsers', { id: [{ _: 'InputUserSelf' }] }),
      (error) => isRpcError(error) && error.errorMessage === 'FLOOD_WAIT_90',
    );
    assert.equal(server.requests.length, 1);
  },
);
test(
  'RPC client rejects wrong session IDs, unknown salts and stale' +
    ' authenticated packets',
  async (t) => {
    for (const attack of ['session', 'salt', 'time']) {
      const { client } = await setup(t, (request, fake) =>
        fake.queue.push(
          fake.incoming(rpcResult(request.msgId, users()), {
            ...(attack === 'session' ? { sessionId: Buffer.alloc(8, 9) } : {}),
            ...(attack === 'salt' ? { salt: 456n } : {}),
            ...(attack === 'time'
              ? {
                  msgId:
                    (BigInt(
                      Math.floor(
                        Number(now().epochNanoseconds / 1_000_000_000n),
                      ) - 600,
                    ) <<
                      32n) |
                    1n,
                }
              : {}),
          }),
        ),
      );
      await assert.rejects(
        client.invoke('users.GetUsers', { id: [{ _: 'InputUserSelf' }] }),
        isSecurityError,
        attack,
      );
    }
  },
);
test(
  'RPC client never automatically repeats an ambiguous mutation' +
    ' after a transport failure',
  async (t) => {
    for (const failure of [
      protocolError('fake broken connection'),
      Object.assign(new Error('fake failure'), { name: 'RpcError' }),
    ]) {
      const { client, server } = await setup(t, () => {
        throw failure;
      });
      await assert.rejects(
        client.invoke(
          'messages.SendMessage',
          {
            peer: { _: 'InputPeerChat', chatId: 1n },
            message: 'FAKE_PRIVATE_MESSAGE',
            randomId: 1n,
          },
          { mutation: true },
        ),
        isAmbiguousMutationError,
      );
      assert.equal(server.requests.length, 1);
    }
  },
);
test(
  'Internal wrappers/raw unknown RPCs and' +
    ' closed-instance reuse are rejected',
  async (t) => {
    const { client } = await setup(t, () => {});
    await assert.rejects(
      client.invoke('payments.SendStarsForm'),
      isProtocolError,
    );
    await assert.rejects(client.invoke('InitConnection', {}), isProtocolError);
    await assert.rejects(client.invoke('auth.LogOut'), /explicitly classified/);
    for (const name of ['messages.DeleteMessages', 'channels.DeleteMessages'])
      await assert.rejects(client.invoke(name), /explicitly classified/);
    client.close();
    await assert.rejects(client.open(), /cannot be reused/);
  },
);
test(
  'Authenticated duplicate packets are ignored, but reusing an' +
    ' ID for different content is rejected',
  async (t) => {
    let previous;
    const { client, server } = await setup(t, (request, fake) => {
      if (previous) fake.queue.push(previous);
      const packet = fake.incoming(rpcResult(request.msgId, users()));
      fake.queue.push(packet);
      previous = packet;
    });
    await client.invoke('users.GetUsers', { id: [{ _: 'InputUserSelf' }] });
    assert.equal(
      (
        await client.invoke('users.GetUsers', { id: [{ _: 'InputUserSelf' }] })
      )[0].id,
      1n,
    );
    assert.equal(server.requests.length, 2);
    const old = previous;
    server.handler = (request, fake) => {
      const decoded = decryptPacket(
        old,
        fake.data.authKey,
        fake.sessionId,
        true,
      );
      fake.queue.push(
        fake.incoming(rpcResult(request.msgId, users()), {
          msgId: decoded.msgId,
        }),
      );
    };
    await assert.rejects(
      client.invoke('users.GetUsers', { id: [{ _: 'InputUserSelf' }] }),
      /different content/,
    );
  },
);

test('Replay cache evicts by message ID, not arrival order', async (t) => {
  const base = ((now().epochNanoseconds / 1_000_000_000n) << 32n) | 1n;
  const id = (index) => base + 4n * BigInt(index);
  const pong = encode({ _: 'Pong', msgId: 1n, pingId: 1n });
  const { client } = await setup(t, (request, fake) => {
    const page = fake.requests.length - 1;
    if (page < 4) {
      const inner = Array.from({ length: 1024 }, (_, i) => [
        long(id(page * 1024 + 1023 - i)),
        uint(0),
        uint(pong.length),
        pong,
      ]).flat();
      const packed = Buffer.concat([uint(0x73f1f8dc), uint(1024), ...inner]);
      fake.queue.push(
        fake.incoming(packed, { msgId: id(5000 + page), seqNo: 0 }),
      );
    } else if (page === 4) {
      // First comes an authenticated duplicate that must remain in the cache.
      // Then an ID between the eviction floor and the oldest retained ID.
      fake.queue.push(
        fake.incoming(pong, { msgId: id(200), seqNo: 0 }),
        fake.incoming(pong, { msgId: id(8) - 2n, seqNo: 0 }),
      );
    } else {
      fake.queue.push(fake.incoming(pong, { msgId: id(0), seqNo: 0 }));
    }
    fake.queue.push(
      fake.incoming(rpcResult(request.msgId, users()), {
        msgId: id(6000 + page),
      }),
    );
  });
  const getUsers = () =>
    client.invoke('users.GetUsers', { id: [{ _: 'InputUserSelf' }] });
  for (let page = 0; page < 5; page++)
    assert.equal((await getUsers())[0].id, 1n);
  await assert.rejects(
    getUsers(),
    /Rejected stale, future, or invalid server message ID/,
  );
});
