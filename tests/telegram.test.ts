import test from 'node:test';
import assert from 'node:assert/strict';
import {
  createTelegram,
  parsePeerId,
  peerKey,
  inputPeer,
  rememberEntity,
} from '../src/telegram.ts';
import {
  isSecurityError,
  rpcError,
  ambiguousMutationError,
  isAmbiguousMutationError,
  epochSeconds,
} from '../src/common.ts';
import { encode, decode } from '../src/tl.ts';
import { fakeRpc, user, channel, chat } from './support.ts';

const dialog = (entity) => ({
  _: 'Dialog',
  peer: {
    _:
      entity._ === 'User'
        ? 'PeerUser'
        : entity._ === 'Chat'
          ? 'PeerChat'
          : 'PeerChannel',
    [entity._ === 'User'
      ? 'userId'
      : entity._ === 'Chat'
        ? 'chatId'
        : 'channelId']: entity.id,
  },
  topMessage: 1,
  unreadCount: 3,
});
const message = (id, peer = 1n, extra = {}) => ({
  _: 'Message',
  id,
  date: epochSeconds(),
  peerId: { _: 'PeerChannel', channelId: peer },
  message: `Message ${id}`,
  ...extra,
});
function withEntities(rpc, entities, options = {}) {
  const telegram = createTelegram(rpc, options);
  for (const entity of entities) rememberEntity(telegram.entities, entity);
  return telegram;
}

test('Deletes one verified message with explicit scope', async () => {
  const cases = [
    [user(2), { _: 'PeerUser', userId: 2n }, 'me'],
    [chat(2), { _: 'PeerChat', chatId: 2n }, 'everyone'],
    [channel(2), { _: 'PeerChannel', channelId: 2n }, 'everyone'],
  ] as const;
  for (const [entity, peer, scope] of cases) {
    const isChannel = entity._ === 'Channel';
    const chatId = peerKey(entity);
    const audits = [];
    const rpc = fakeRpc((name, args, options) => {
      if (name.endsWith('.GetMessages')) {
        assert.equal(
          name,
          isChannel ? 'channels.GetMessages' : 'messages.GetMessages',
        );
        assert.deepEqual(args.id, [{ _: 'InputMessageID', id: 42 }]);
        assert.equal(options, undefined);
        if (isChannel) assert.equal(args.channel.channelId, 2n);
        return {
          messages: [
            message(42, 2n, {
              peerId: peer,
              message: 'FAKE_PRIVATE_BODY',
            }),
          ],
        };
      }
      assert.equal(
        name,
        isChannel ? 'channels.DeleteMessages' : 'messages.DeleteMessages',
      );
      assert.deepEqual(
        args,
        isChannel
          ? {
              channel: { _: 'InputChannel', channelId: 2n, accessHash: 102n },
              id: [42],
            }
          : { id: [42], revoke: scope === 'everyone' },
      );
      assert.equal(options?.mutation, true);
      return decode(
        encode({ _: 'messages.AffectedMessages', pts: 5, ptsCount: 1 }),
        'messages.AffectedMessages',
      );
    });
    const telegram = withEntities(rpc, [entity], {
      audit: async (entry) => audits.push(entry),
    });
    const result = await telegram.deleteMessage(chatId, 42, scope);
    assert.deepEqual(result, { success: true, chatId, messageId: 42, scope });
    assert.equal(rpc.calls.filter((call) => call.options?.mutation).length, 1);
    assert.deepEqual(
      audits.map((entry) => entry.status),
      ['requested', 'succeeded'],
    );
    assert.ok(audits.every((entry) => entry.account === 'user:1'));
    assert.ok(!JSON.stringify(audits).includes('FAKE_PRIVATE_BODY'));
  }
});

test('Delete rejects messages missing from the selected chat', async () => {
  for (const messages of [
    [],
    [message(42, 3n, { peerId: { _: 'PeerUser', userId: 3n } })],
    [message(43, 2n, { peerId: { _: 'PeerUser', userId: 2n } })],
    [{ _: 'MessageEmpty', id: 42 }],
    [message(42, 2n, { _: 'MessageService' })],
  ]) {
    const rpc = fakeRpc(() => ({ messages }));
    const telegram = withEntities(rpc, [user(2)], { audit: assert.fail });
    await assert.rejects(
      telegram.deleteMessage('user:2', 42, 'everyone'),
      /not found in the specified chat/,
    );
    assert.deepEqual(
      rpc.calls.map(({ name }) => name),
      ['messages.GetMessages'],
    );
  }
  const rpc = fakeRpc(assert.fail);
  const telegram = withEntities(rpc, [channel(2)], { audit: assert.fail });
  await assert.rejects(
    telegram.deleteMessage('channel:2', 42, 'me'),
    /require --for-everyone/,
  );
  assert.deepEqual(rpc.calls, []);
});

test('Records an uncertain deletion without submitting it again', async () => {
  const audits = [];
  const rpc = fakeRpc((name) => {
    if (name === 'channels.GetMessages') return { messages: [message(42, 2n)] };
    throw ambiguousMutationError();
  });
  const telegram = withEntities(rpc, [channel(2)], {
    audit: async (entry) => audits.push(entry),
  });
  await assert.rejects(
    telegram.deleteMessage('channel:2', 42, 'everyone'),
    isAmbiguousMutationError,
  );
  assert.equal(rpc.calls.filter((call) => call.options?.mutation).length, 1);
  assert.deepEqual(
    audits.map((entry) => entry.status),
    ['requested', 'unknown'],
  );
});

test(
  'Peer identifiers are type-qualified, native-bigint and' + ' numeric-first',
  () => {
    assert.deepEqual(parsePeerId('-1001234567890'), {
      kind: 'channel',
      id: 1234567890n,
      key: 'channel:1234567890',
    });
    assert.equal(parsePeerId('-123').key, 'chat:123');
    assert.equal(parsePeerId('123').key, 'user:123');
    assert.equal(parsePeerId('channel:123').key, 'channel:123');
    assert.equal(parsePeerId('Finance'), null);
    for (const id of [
      '0',
      '0001',
      'user:0',
      'channel:abc',
      '-1000000000000',
      '9999999999999999999999999999',
    ])
      assert.throws(() => parsePeerId(id), isSecurityError, id);
    assert.throws(() => inputPeer(user(1, { min: true })), isSecurityError);
    assert.throws(
      () => inputPeer(user(1, { accessHash: undefined })),
      isSecurityError,
    );
  },
);

test(
  'Dialog previews and pagination match both peer and message' +
    ' ID and preserve Unicode',
  async () => {
    const chats = Array.from({ length: 100 }, (_, i) => channel(i + 1));
    const date = epochSeconds(),
      text = '🌍'.repeat(160);
    const rpc = fakeRpc((name, args) => {
      assert.equal(name, 'messages.GetDialogs');
      if (!args.offsetId)
        return {
          _: 'messages.DialogsSlice',
          chats,
          dialogs: chats.map(dialog),
          messages: [
            message(1, 100n, { message: text + '!', date }),
            message(1, 1n, { message: text, date: date - 1 }),
          ],
        };
      assert.equal(args.offsetId, 1);
      assert.equal(args.offsetDate, date);
      assert.equal(args.offsetPeer.channelId, 100n);
      return { _: 'messages.Dialogs', chats: [], dialogs: [], messages: [] };
    });
    const result = await createTelegram(rpc).dialogs({ limit: 101 });
    assert.equal(result.length, 100);
    assert.equal(result[0].lastMessage, text);
    assert.equal(result[0].previewTruncated, false);
    assert.equal(result.at(-1).lastMessage, text);
    assert.equal(result.at(-1).previewTruncated, true);
    assert.equal(result[1].lastMessage, undefined);
    assert.equal(rpc.calls.length, 2);
  },
);
test(
  'A numeric-looking attacker title cannot shadow a real' +
    ' numeric-ID destination',
  async () => {
    const victim = user(123),
      attacker = channel(99, { title: '123' }),
      audits = [];
    const rpc = fakeRpc((name, args) => {
      if (name === 'messages.GetDialogs')
        return {
          _: 'messages.Dialogs',
          users: [victim],
          chats: [attacker],
          dialogs: [dialog(attacker), dialog(victim)],
          messages: [],
        };
      if (name === 'messages.SendMessage') {
        assert.equal(args.peer._, 'InputPeerUser');
        assert.equal(args.peer.userId, 123n);
        return { _: 'UpdateShortSentMessage', id: 7 };
      }
      throw new Error(name);
    });
    const telegram = createTelegram(rpc, {
      audit: async (entry) => audits.push(entry),
    });
    const sent = await telegram.send('123', 'FAKE_PRIVATE_TEXT');
    assert.equal(sent.chatId, 'user:123');
    assert.equal(audits[0].peers[0], 'user:123');
    assert.equal(rpc.calls.at(-1).options.mutation, true);
  },
);
test(
  'Duplicate exact names and partial matches fail closed' + ' without sending',
  async () => {
    const a = channel(1, { title: 'Finance' }),
      b = channel(2, { title: 'Finance' });
    const rpc = fakeRpc(() => ({
      _: 'messages.Dialogs',
      users: [],
      chats: [a, b],
      dialogs: [dialog(a), dialog(b)],
      messages: [],
    }));
    const telegram = createTelegram(rpc);
    await assert.rejects(telegram.send('Finance', 'private'), /Ambiguous/);
    await assert.rejects(telegram.resolve('Fin'), /exact name/);
    assert.ok(rpc.calls.every((call) => call.name === 'messages.GetDialogs'));
  },
);
test(
  'Explicit @numeric collectible usernames remain usernames,' +
    ' never dialog-title or numeric-ID guesses',
  async () => {
    const rpc = fakeRpc((name, args) => {
      assert.equal(name, 'contacts.ResolveUsername');
      assert.equal(args.username, '1234');
      return {
        peer: { _: 'PeerUser', userId: 2n },
        users: [user(2, { username: '1234' })],
      };
    });
    const entity = await createTelegram(rpc).resolve('@1234');
    assert.equal(peerKey(entity), 'user:2');
    assert.equal(rpc.calls.length, 1);
  },
);
test(
  'Direct account changes retain input validation before any' +
    ' remote mutation',
  async () => {
    const rpc = fakeRpc(() => {
      throw new Error('No remote mutation should run');
    });
    const telegram = createTelegram(rpc);
    rememberEntity(telegram.entities, user(2));
    rememberEntity(telegram.entities, channel(3));
    for (const perform of [
      () => telegram.mute('user:2', NaN),
      () => telegram.kick('user:2', 'user:2'),
      () => telegram.promote('channel:3', 'user:2', { rights: [] }),
    ])
      await assert.rejects(perform(), isSecurityError);
    assert.equal(rpc.calls.length, 0);
  },
);
for (const replyTo of [undefined, 123]) {
  const action = replyTo ? 'Reply' : 'Send';
  test(`${action} submits directly without confirmation`, async () => {
    const audits = [];
    const rpc = fakeRpc((name, args, options) => {
      assert.equal(name, 'messages.SendMessage');
      assert.equal(args.peer.userId, 2n);
      assert.equal(args.message, 'FAKE_PRIVATE_BODY');
      assert.equal(args.replyTo?.replyToMsgId, replyTo);
      assert.equal(args.noWebpage, true);
      assert.equal(options.mutation, true);
      return { _: 'UpdateShortSentMessage', id: 456 };
    });
    const telegram = createTelegram(rpc, {
      audit: async (entry) => audits.push(entry),
    });
    rememberEntity(telegram.entities, user(2));
    const sent = await telegram.send('user:2', 'FAKE_PRIVATE_BODY', {
      replyTo,
    });
    assert.equal(sent.messageId, 456);
    assert.equal(sent.chatId, 'user:2');
    assert.equal(
      rpc.calls.filter((call) => call.name === 'messages.SendMessage').length,
      1,
    );
    assert.deepEqual(
      audits.map((entry) => entry.status),
      ['requested', 'succeeded'],
    );
    assert.ok(
      audits.every(
        (entry) =>
          entry.command === (replyTo ? 'reply' : 'send') &&
          entry.account === 'user:1',
      ),
    );
    assert.ok(!JSON.stringify(audits).includes('FAKE_PRIVATE_BODY'));
  });
}
test(
  'Direct remote changes retain failure auditing and never' +
    ' retry ambiguous submissions',
  async () => {
    for (const command of ['send', 'unmute', 'kick', 'logout'])
      for (const error of [
        rpcError(400, 'FAKE_REJECTION'),
        ambiguousMutationError(),
      ]) {
        const audits = [],
          rpc = fakeRpc(() => {
            throw error;
          });
        const telegram = withEntities(rpc, [user(2), channel(3)], {
          audit: async (entry) => audits.push(entry),
        });
        const perform = {
          send: () => telegram.send('user:2', 'FAKE_PRIVATE_BODY'),
          unmute: () => telegram.mute('user:2', 0),
          kick: () => telegram.kick('channel:3', 'user:2'),
          logout: () => telegram.logout(),
        };
        await assert.rejects(perform[command](), (caught) => caught === error);
        assert.equal(
          rpc.calls.filter((call) => call.options?.mutation).length,
          1,
        );
        assert.deepEqual(
          audits.map((entry) => entry.status),
          ['requested', isAmbiguousMutationError(error) ? 'unknown' : 'failed'],
        );
      }
  },
);
test(
  'Self-removal is rejected by stable account ID even when a' +
    ' cached profile omits its self flag',
  async () => {
    const rpc = fakeRpc(() => {
      throw new Error('No mutation should run');
    });
    const telegram = withEntities(rpc, [channel(2), user(1)]);
    await assert.rejects(
      telegram.kick('channel:2', 'user:1'),
      /different user/,
    );
    assert.ok(rpc.calls.every((call) => call.name === 'users.GetUsers'));
  },
);
test(
  'Authorization, inbox and contact info use projected data,' +
    ' not raw credentials/hashes',
  async () => {
    const me = user(1, { self: true }),
      person = user(2, { username: 'example', phone: 'FAKE_PHONE' });
    const rpc = fakeRpc((name) => {
      if (name === 'users.GetUsers') return [me];
      if (name === 'messages.GetDialogs')
        return {
          _: 'messages.Dialogs',
          users: [person],
          chats: [],
          dialogs: [dialog(person)],
          messages: [],
        };
      if (name === 'users.GetFullUser')
        return { fullUser: { about: 'Fake bio' }, users: [person] };
      throw new Error(name);
    });
    const telegram = createTelegram(rpc);
    assert.equal((await telegram.whoami()).id, 'user:1');
    assert.equal((await telegram.dialogs({ unread: true }))[0].unreadCount, 3);
    const contact = await telegram.contact('user:2');
    assert.equal(contact.bio, 'Fake bio');
    assert.equal(contact.accessHash, undefined);
  },
);
test(
  'History paginates through service-only batches and advances' +
    ' by raw oldest IDs',
  async () => {
    let page = 0;
    const rpc = fakeRpc((name, args) => {
      assert.equal(name, 'messages.GetHistory');
      page++;
      if (page === 1)
        return {
          messages: Array.from({ length: 100 }, (_, index) =>
            message(201 - index, 1n, {
              _: 'MessageService',
              action: { _: 'MessageActionEmpty' },
            }),
          ),
        };
      assert.equal(args.offsetId, 102);
      return { messages: [message(101)] };
    });
    const result = await withEntities(rpc, [channel(1)]).read('channel:1', {
      limit: 5,
    });
    assert.equal(result.messages.length, 1);
    assert.equal(result.messages[0].id, 101);
    assert.equal(page, 2);
  },
);
test(
  'History validates identity/date bounds and preserves media' +
    ' metadata without downloading it',
  async () => {
    const now = epochSeconds(),
      media = {
        _: 'MessageMediaDocument',
        document: {
          _: 'Document',
          size: 512n,
          mimeType: 'application/pdf',
          attributes: [
            { _: 'DocumentAttributeFilename', fileName: 'untrusted.pdf' },
          ],
        },
      };
    const rpc = fakeRpc(() => ({
      messages: [
        message(3, 1n, { date: now + 1 }),
        message(2, 1n, { date: now, media }),
        message(1, 1n, { date: now - 100 }),
      ],
    }));
    const telegram = withEntities(rpc, [channel(1)]);
    const result = await telegram.read('channel:1', {
      since: now - 10,
      until: now,
    });
    assert.equal(result.messages.length, 1);
    assert.equal(result.messages[0].media.fileName, 'untrusted.pdf');
    const wrong = withEntities(
      fakeRpc(() => ({ messages: [message(2, 999n)] })),
      [channel(1)],
    );
    await assert.rejects(wrong.read('channel:1'), /different chat/);
  },
);
test(
  'Outgoing private messages without fromId use the' +
    ' authenticated sender, never the recipient',
  async () => {
    const outgoing = decode(
      encode(
        message(1, 1n, { out: true, peerId: { _: 'PeerUser', userId: 2n } }),
      ),
    );
    const rpc = fakeRpc((name) => {
      if (name === 'messages.GetHistory' || name === 'messages.Search')
        return { messages: [outgoing] };
      throw new Error(name);
    });
    const telegram = withEntities(rpc, [user(2), channel(3), user(4)]);
    assert.equal(
      telegram.message(outgoing).senderId,
      undefined,
      'an unknown account must not be guessed',
    );
    await telegram.me();
    for (const projected of [
      (await telegram.read('user:2')).messages[0],
      (await telegram.search('fake', { chat: 'user:2' })).messages[0],
    ]) {
      assert.equal(projected.senderId, 'user:1');
      assert.equal(projected.sender, 'User 1');
      assert.equal(projected.chatId, 'user:2');
    }
    assert.equal(
      telegram.message({ ...outgoing, out: false }).senderId,
      'user:2',
    );
    assert.equal(
      telegram.message({ ...outgoing, fromId: { _: 'PeerUser', userId: 4n } })
        .senderId,
      'user:4',
    );
    assert.equal(
      telegram.message({
        ...outgoing,
        post: true,
        peerId: { _: 'PeerChannel', channelId: 3n },
      }).senderId,
      'channel:3',
    );
    assert.equal(
      telegram.message({ ...outgoing, peerId: { _: 'PeerChat', chatId: 3n } })
        .senderId,
      undefined,
    );
  },
);
test(
  'Inclusive until survives exclusive server date offsets at' +
    ' ordinary and signed-int boundaries',
  async () => {
    for (const until of [0, 1780000000, 2147483646, 2147483647]) {
      const rpc = fakeRpc((name, args) => {
        assert.equal(name, 'messages.GetHistory');
        assert.equal(args.offsetDate, until < 2147483647 ? until + 1 : 0);
        const messages = [
          message(2, 1n, { date: until }),
          ...(until ? [message(1, 1n, { date: until - 1 })] : []),
        ];
        return {
          messages: messages.filter(
            (item) => !args.offsetDate || item.date < args.offsetDate,
          ),
        };
      });
      const result = await withEntities(rpc, [channel(1)]).read('channel:1', {
        since: until,
        until,
      });
      assert.deepEqual(
        result.messages.map((item) => item.id),
        [2],
      );
      assert.equal(
        result.messages[0].date,
        Temporal.Instant.fromEpochNanoseconds(
          BigInt(until) * 1000000000n,
        ).toString(),
      );
    }
    const rpc = fakeRpc(() => {
      throw new Error('Invalid dates must fail before RPC');
    });
    const telegram = withEntities(rpc, [channel(1)]);
    await assert.rejects(
      telegram.read('channel:1', { until: 2147483648 }),
      /Invalid history date/,
    );
    await assert.rejects(
      telegram.read('channel:1', { since: 2147483648 }),
      /Invalid history date/,
    );
  },
);
test(
  'Global search carries peer identity and next-rate cursor' + ' across pages',
  async () => {
    let pages = 0;
    const rpc = fakeRpc((name, args) => {
      assert.equal(name, 'messages.SearchGlobal');
      pages++;
      if (pages === 1)
        return {
          messages: Array.from({ length: 100 }, (_, index) =>
            message(200 - index),
          ),
          chats: [channel(1)],
          users: [],
          nextRate: 44,
        };
      assert.equal(args.offsetRate, 44);
      assert.equal(args.offsetId, 101);
      assert.equal(args.offsetPeer.channelId, 1n);
      return { messages: [message(100)], chats: [channel(1)] };
    });
    const result = await createTelegram(rpc).search('keyword', { limit: 101 });
    assert.equal(result.messages.length, 101);
    assert.equal(result.messages[0].chatId, 'channel:1');
  },
);
test(
  'A completed global search does not demand an unnecessary' +
    ' next-page peer access hash',
  async () => {
    const rpc = fakeRpc(() => ({ messages: [message(1)], chats: [] }));
    const result = await createTelegram(rpc).search('keyword', { limit: 1 });
    assert.equal(result.messages.length, 1);
    assert.equal(rpc.calls.length, 1);
  },
);
test(
  'Participants/admins paginate and basic-group owner roles are' + ' retained',
  async () => {
    let page = 0;
    const rpc = fakeRpc((name, args) => {
      if (name === 'messages.GetFullChat')
        return {
          fullChat: {
            participants: {
              _: 'ChatParticipants',
              participants: [
                { _: 'ChatParticipantCreator', userId: 1n },
                { _: 'ChatParticipant', userId: 2n },
              ],
            },
          },
          users: [user(1), user(2)],
        };
      assert.equal(name, 'channels.GetParticipants');
      page++;
      const size = page === 1 ? 200 : 50,
        start = args.offset;
      return {
        participants: Array.from({ length: size }, (_, index) => ({
          _: 'ChannelParticipantAdmin',
          userId: BigInt(start + index + 1),
        })),
        users: Array.from({ length: size }, (_, index) =>
          user(start + index + 1),
        ),
      };
    });
    const telegram = withEntities(rpc, [channel(1), chat(2)]);
    assert.equal(
      (await telegram.members('channel:1', { admins: true, limit: 250 }))
        .members.length,
      250,
    );
    const basic = await telegram.members('chat:2', { admins: true });
    assert.equal(basic.members.length, 1);
    assert.equal(basic.members[0].role, 'owner');
  },
);
test(
  'Mute/unmute, kick and promotion submit directly with stable' +
    ' IDs and requested audits',
  async () => {
    const audits = [];
    const rpc = fakeRpc((name, args, options) => {
      assert.equal(options.mutation, true);
      if (name === 'account.UpdateNotifySettings') {
        assert.ok([0, 2_147_483_647].includes(args.settings.muteUntil));
        return true;
      }
      if (name === 'channels.EditBanned') {
        assert.equal(args.participant.userId, 2n);
        assert.equal(args.bannedRights.viewMessages, true);
        return { _: 'UpdatesTooLong' };
      }
      if (name === 'channels.EditAdmin') {
        assert.equal(args.adminRights.pinMessages, true);
        assert.equal(args.adminRights.addAdmins, undefined);
        assert.equal(args.adminRights.banUsers, undefined);
        return { _: 'UpdatesTooLong' };
      }
      throw new Error(name);
    });
    const telegram = withEntities(rpc, [channel(1), user(2)], {
      audit: async (entry) => audits.push(entry),
    });
    await telegram.mute('channel:1');
    await telegram.mute('channel:1', 0);
    await telegram.kick('channel:1', 'user:2');
    await telegram.promote('channel:1', 'user:2', { rights: ['pinMessages'] });
    assert.deepEqual(
      audits
        .filter((entry) => entry.status === 'requested')
        .map((entry) => entry.command),
      ['mute', 'unmute', 'kick', 'promote'],
    );
    assert.equal(
      audits.filter((entry) => entry.status === 'succeeded').length,
      4,
    );
    assert.ok(
      audits.every(
        (entry) =>
          entry.account === 'user:1' &&
          entry.peers[0] === 'channel:1' &&
          entry.status !== 'approved',
      ),
    );
    await assert.rejects(
      telegram.promote('channel:1', 'user:2', { rights: ['everything'] }),
      /explicit nonempty/,
    );
  },
);
test(
  'Reply IDs are validated and no raw message is accepted into' +
    ' the audit metadata',
  async () => {
    const audits = [];
    const rpc = fakeRpc((name, args) => {
      assert.equal(args.replyTo.replyToMsgId, 123);
      return { _: 'UpdateShortSentMessage', id: 456 };
    });
    const telegram = withEntities(rpc, [user(1)], {
      audit: async (entry) => audits.push(entry),
    });
    await assert.rejects(
      telegram.send('user:1', 'private', { replyTo: NaN }),
      /Invalid reply/,
    );
    await telegram.send('user:1', 'FAKE_PRIVATE_BODY', { replyTo: 123 });
    assert.deepEqual(
      audits.map((entry) => entry.status),
      ['requested', 'succeeded'],
    );
    assert.ok(!JSON.stringify(audits).includes('FAKE_PRIVATE_BODY'));
  },
);
test(
  'Audit preparation failure prevents writes; post-success' +
    ' audit failure does not encourage replay',
  async () => {
    let writes = 0,
      warnings = 0;
    const rpc = fakeRpc(() => {
      writes++;
      return { _: 'UpdateShortSentMessage', id: 1 };
    });
    const blocked = withEntities(rpc, [user(1)], {
      audit: async () => {
        throw new Error('fake disk full');
      },
    });
    await assert.rejects(blocked.send('user:1', 'fake'), /disk full/);
    assert.equal(writes, 0);
    const allowed = withEntities(rpc, [user(1)], {
      audit: async (entry) => {
        if (entry.status === 'succeeded') throw new Error('fake disk full');
      },
      warning: () => warnings++,
    });
    assert.equal((await allowed.send('user:1', 'fake')).success, true);
    assert.equal(writes, 1);
    assert.equal(warnings, 1);
  },
);
test(
  'Direct folder edits preserve unrelated flags/peers and' +
    ' reject concurrent changes',
  async () => {
    const filter = {
      _: 'DialogFilter',
      id: 2,
      title: { _: 'TextWithEntities', text: 'Work', entities: [] },
      groups: true,
      pinnedPeers: [{ _: 'InputPeerChat', chatId: 3n }],
      includePeers: [],
      excludePeers: [{ _: 'InputPeerUser', userId: 1n, accessHash: 101n }],
    };
    let updated;
    const rpc = fakeRpc((name, args) => {
      if (name === 'messages.GetDialogFilters') return { filters: [filter] };
      updated = args.filter;
      return true;
    });
    const telegram = withEntities(rpc, [user(1)]);
    await telegram.changeFolder('folder:2', 'user:1', true);
    assert.equal(updated.groups, true);
    assert.equal(updated.pinnedPeers[0].chatId, 3n);
    assert.equal(updated.includePeers[0].userId, 1n);
    assert.equal(updated.excludePeers.length, 0);
    const concurrent = withEntities(rpc, [user(1)], {
      audit: async (entry) => {
        if (entry.status === 'requested') filter.color = 7;
      },
    });
    await assert.rejects(
      concurrent.changeFolder('Work', 'user:1', false),
      /changed before update/,
    );
  },
);
test(
  'Folder creation and server-side logout are explicit' +
    ' mutations, not local-only success',
  async () => {
    const me = user(1, { self: true });
    let logouts = 0;
    const rpc = fakeRpc((name, args, options) => {
      if (name === 'users.GetUsers') return [me];
      if (name === 'messages.GetDialogFilters') return { filters: [] };
      if (name === 'messages.UpdateDialogFilter') {
        if (
          !args.filter.includePeers.length &&
          !['contacts', 'nonContacts', 'groups', 'broadcasts', 'bots'].some(
            (name) => args.filter[name],
          )
        )
          throw rpcError(400, 'FILTER_INCLUDE_EMPTY');
        assert.equal(args.filter.id, 2);
        assert.equal(options.mutation, true);
        return true;
      }
      if (name === 'auth.LogOut') {
        logouts++;
        return { _: 'auth.LoggedOut' };
      }
      throw new Error(name);
    });
    const telegram = withEntities(rpc, []);
    await assert.rejects(telegram.createFolder('Work'), /explicit initial/);
    assert.equal(
      (await telegram.createFolder('Work', { categories: ['groups'] }))
        .folderId,
      'folder:2',
    );
    assert.equal((await telegram.logout()).revoked, true);
    assert.equal(logouts, 1);
  },
);
test(
  'Adding an already-pinned chat preserves its pin and removal' +
    ' alone unpins it',
  async () => {
    const target = { _: 'InputPeerUser', userId: 2n, accessHash: 102n };
    let filter = {
      _: 'DialogFilter',
      id: 2,
      title: { _: 'TextWithEntities', text: 'Work', entities: [] },
      groups: true,
      pinnedPeers: [target],
      includePeers: [target],
      excludePeers: [],
    };
    const rpc = fakeRpc((name, args) => {
      if (name === 'messages.GetDialogFilters') return { filters: [filter] };
      filter = args.filter;
      return true;
    });
    const telegram = withEntities(rpc, [user(2)]);
    await telegram.changeFolder('folder:2', 'user:2', true);
    assert.deepEqual(filter.pinnedPeers, [target]);
    assert.equal(filter.includePeers.length, 1);
    await telegram.changeFolder('folder:2', 'user:2', false);
    assert.equal(filter.pinnedPeers.length, 0);
    assert.equal(filter.includePeers.length, 0);
    assert.equal(filter.excludePeers[0].userId, 2n);
  },
);
test(
  'Direct folder creation uses explicit resolved' +
    ' peers/categories and rejects invalid selection',
  async () => {
    const audits = [];
    const rpc = fakeRpc((name, args) => {
      if (name === 'messages.GetDialogFilters') return { filters: [] };
      assert.equal(args.filter.includePeers[0].userId, 2n);
      assert.equal(args.filter.contacts, true);
      assert.equal(args.filter.groups, undefined);
      return true;
    });
    const telegram = withEntities(rpc, [user(2)], {
      audit: async (entry) => audits.push(entry),
    });
    await assert.rejects(
      telegram.createFolder('Work', { categories: ['everything'] }),
      /explicit initial/,
    );
    assert.equal(
      (
        await telegram.createFolder('Work', {
          peers: ['user:2', 'user:2'],
          categories: ['contacts'],
        })
      ).success,
      true,
    );
    assert.deepEqual(
      audits.map((entry) => entry.status),
      ['requested', 'succeeded'],
    );
    assert.deepEqual(audits[0].peers, ['user:2']);
  },
);
test(
  'Direct folder creation rejects a concurrent folder ID/name' + ' collision',
  async () => {
    let reads = 0;
    const rpc = fakeRpc((name) => {
      assert.equal(name, 'messages.GetDialogFilters');
      return {
        filters:
          ++reads === 1
            ? []
            : [
                {
                  _: 'DialogFilter',
                  id: 2,
                  title: { _: 'TextWithEntities', text: 'Work', entities: [] },
                  groups: true,
                  pinnedPeers: [],
                  includePeers: [],
                  excludePeers: [],
                },
              ],
      };
    });
    await assert.rejects(
      createTelegram(rpc).createFolder('Work', { categories: ['groups'] }),
      /changed before creation/,
    );
    assert.equal(reads, 2);
    assert.ok(!rpc.calls.some((call) => call.options?.mutation));
  },
);
test(
  'A member without a username or dialog is resolved by numeric' +
    ' ID from authenticated group metadata',
  async () => {
    let discovery = 0;
    const rpc = fakeRpc((name, args) => {
      if (name === 'messages.GetDialogs')
        return {
          _: 'messages.Dialogs',
          dialogs: [],
          users: [],
          chats: [],
          messages: [],
        };
      if (name === 'channels.GetParticipants') {
        discovery++;
        return {
          participants: [{ _: 'ChannelParticipant', userId: 2n }],
          users: [user(2)],
        };
      }
      assert.equal(name, 'channels.EditBanned');
      assert.equal(args.participant.userId, 2n);
      assert.equal(args.participant.accessHash, 102n);
      return { _: 'UpdatesTooLong' };
    });
    const telegram = withEntities(rpc, [channel(1)]);
    assert.equal((await telegram.kick('channel:1', 'user:2')).success, true);
    assert.equal(discovery, 1);
  },
);
test(
  'Saved Messages peers in folders are resolved to the' +
    ' authorized account ID',
  async () => {
    const rpc = fakeRpc(() => ({
      filters: [
        {
          _: 'DialogFilter',
          id: 2,
          title: { _: 'TextWithEntities', text: 'Work', entities: [] },
          includePeers: [{ _: 'InputPeerSelf' }],
          pinnedPeers: [],
          excludePeers: [],
        },
      ],
    }));
    const result = await createTelegram(rpc).folders();
    assert.deepEqual(result[0].included, ['user:1']);
  },
);
