import test from 'node:test';
import assert from 'node:assert/strict';
import {
  mkdir,
  writeFile,
  readFile,
  readdir,
  stat,
  symlink,
  chmod,
  unlink,
} from 'node:fs/promises';
import { join } from 'node:path';
import { syncHistory, MAX_SYNC_CHATS, MAX_META_BYTES } from '../src/export.ts';
import {
  createTelegram,
  peerKey,
  summarizePeer,
  rememberEntity,
} from '../src/telegram.ts';
import { isSecurityError } from '../src/common.ts';
import { atomicPrivateWrite, privateDirectory } from '../src/files.ts';
import {
  scratch,
  channel,
  user,
  fakeRpc,
  windows,
  directoryLink,
  publicWindowsRead,
} from './support.ts';

function source(entities, messages, account = 1) {
  const cache = new Map();
  for (const entity of entities) rememberEntity(cache, entity);
  const observed = [];
  return {
    observed,
    async me() {
      return user(account, { self: true });
    },
    async allDialogs() {
      return entities.map((entity) => summarizePeer(entity));
    },
    async resolve(id) {
      const entity = cache.get(id);
      if (!entity) throw new Error('unknown fake peer');
      return entity;
    },
    async *history(entity, options) {
      observed.push({ id: peerKey(entity), ...options });
      for (const message of messages[peerKey(entity)] ?? []) yield message;
    },
  };
}
const message = (id, peer = 1, extra = {}) => ({
  id,
  chatId: `channel:${peer}`,
  date: '2026-11-05T12:00:00Z',
  text: `Fake private message ${id}`,
  outgoing: false,
  ...extra,
});
const records = (bytes) =>
  bytes
    .trimEnd()
    .split('\n')
    .map((line) => JSON.parse(line));

test(
  'Exports use private stable-ID JSONL filenames; remote titles' +
    ' cannot overwrite instructions or each other',
  async (t) => {
    const root = await scratch(t),
      output = join(root, 'export');
    const telegram = source(
      [
        channel(1, { title: '../../AGENTS' }),
        channel(2, { title: '../../AGENTS' }),
      ],
      { 'channel:1': [message(1)], 'channel:2': [message(1, 2)] },
    );
    const result = await syncHistory(telegram, { output, all: true });
    assert.equal(result.chats.length, 2);
    if (!windows) assert.equal((await stat(output)).mode & 0o777, 0o700);
    assert.deepEqual((await readdir(output)).sort(), [
      'chat-channel-1.jsonl',
      'chat-channel-2.jsonl',
      'sync-meta.json',
    ]);
    for (const name of [
      'chat-channel-1.jsonl',
      'chat-channel-2.jsonl',
      'sync-meta.json',
    ])
      if (!windows)
        assert.equal((await stat(join(output, name))).mode & 0o777, 0o600);
    const data = records(
      await readFile(join(output, 'chat-channel-1.jsonl'), 'utf8'),
    );
    assert.equal(data[0].untrusted, true);
    assert.equal(data[0].chat.id, 'channel:1');
    assert.equal(data[1].text, 'Fake private message 1');
  },
);
test(
  'Resume derives its cursor from committed data, not' +
    ' stale/forged metadata, and avoids duplicate messages',
  async (t) => {
    const root = await scratch(t),
      output = join(root, 'export');
    await syncHistory(
      source([channel(1)], { 'channel:1': [message(2), message(1)] }),
      { output, all: true },
    );
    await writeFile(
      join(output, 'sync-meta.json'),
      JSON.stringify({
        format: 'telegram-cli-sync-meta',
        version: 2,
        accountId: 'user:1',
        chats: {
          'channel:1': {
            lastMessageId: 9999999,
            file: 'chat-channel-1.jsonl',
            exportedAt: '2026-11-05T12:00:00Z',
          },
        },
      }),
    );
    const telegram = source([channel(1)], {
      'channel:1': [message(3), message(3), message(2)],
    });
    await syncHistory(telegram, { output, all: true, resume: true });
    assert.equal(telegram.observed[0].minId, 2);
    const data = records(
      await readFile(join(output, 'chat-channel-1.jsonl'), 'utf8'),
    );
    assert.deepEqual(
      data.slice(1).map((item) => item.id),
      [2, 1, 3],
    );
  },
);
test(
  'An existing archive is not silently replaced without' + ' explicit resume',
  async (t) => {
    const root = await scratch(t),
      output = join(root, 'export'),
      telegram = source([channel(1)], { 'channel:1': [message(1)] });
    await syncHistory(telegram, { output });
    const before = await readFile(join(output, 'chat-channel-1.jsonl'));
    await assert.rejects(
      syncHistory(telegram, { output }),
      /never silently overwritten/,
    );
    assert.deepEqual(
      await readFile(join(output, 'chat-channel-1.jsonl')),
      before,
    );
  },
);
test(
  'An unrelated file using the reserved metadata name is not' + ' overwritten',
  async (t) => {
    const root = await scratch(t),
      output = join(root, 'export');
    const filename = join(output, 'sync-meta.json');
    await atomicPrivateWrite(
      output,
      'sync-meta.json',
      '{"unrelated":"user work"}',
    );
    const telegram = source([channel(1)], { 'channel:1': [message(1)] });
    await assert.rejects(
      syncHistory(telegram, { output }),
      /Unrecognized sync metadata/,
    );
    assert.equal(await readFile(filename, 'utf8'), '{"unrelated":"user work"}');
    assert.equal(telegram.observed.length, 0);
  },
);
test(
  'Export count/byte limits reject partial replacement and' +
    ' remove only their own temporary files',
  async (t) => {
    const root = await scratch(t),
      output = join(root, 'export'),
      telegram = source([channel(1)], {
        'channel:1': [message(1), message(2), message(3)],
      });
    await assert.rejects(
      syncHistory(telegram, { output, all: true, maxMessages: 2 }),
      /budget exceeded/,
    );
    assert.deepEqual(await readdir(output), []);
    const large = source([channel(1)], {
      'channel:1': [message(1, 1, { text: 'x'.repeat(2000) })],
    });
    await assert.rejects(
      syncHistory(large, { output, all: true, maxBytes: 1024 }),
      /size budget/,
    );
    assert.deepEqual(await readdir(output), []);
  },
);
test(
  'An exactly bounded complete archive succeeds, but bad' +
    ' identities/symlinks/modes are rejected',
  async (t) => {
    const root = await scratch(t),
      output = join(root, 'export');
    await syncHistory(
      source([channel(1)], { 'channel:1': [message(1), message(2)] }),
      { output, all: true, maxMessages: 2 },
    );
    const before = await readFile(join(output, 'chat-channel-1.jsonl'));
    await assert.rejects(
      syncHistory(source([channel(1)], { 'channel:1': [message(3, 999)] }), {
        output,
        resume: true,
        all: true,
      }),
      /different chat/,
    );
    assert.deepEqual(
      await readFile(join(output, 'chat-channel-1.jsonl')),
      before,
    );
    const archive = join(output, 'chat-channel-1.jsonl');
    if (windows) publicWindowsRead(archive, true);
    else await chmod(archive, 0o644);
    await assert.rejects(
      syncHistory(source([channel(1)], {}), { output, resume: true }),
      isSecurityError,
    );
    const outside = join(root, 'outside');
    await mkdir(outside, { mode: 0o700 });
    await symlink(outside, join(root, 'alias'), directoryLink);
    await assert.rejects(
      syncHistory(source([channel(1)], {}), { output: join(root, 'alias') }),
      isSecurityError,
    );
    assert.deepEqual(await readdir(outside), []);
  },
);
test(
  'Truncated or duplicate existing JSONL records fail rather' +
    ' than corrupting an archive',
  async (t) => {
    const root = await scratch(t),
      output = join(root, 'export'),
      telegram = source([channel(1)], {});
    await privateDirectory(output);
    const header =
      JSON.stringify({
        format: 'telegram-cli-export',
        version: 2,
        accountId: 'user:1',
        untrusted: true,
        chat: { id: 'channel:1' },
      }) + '\n';
    const row = JSON.stringify(message(1)) + '\n',
      filename = join(output, 'chat-channel-1.jsonl');
    for (const contents of [header + row + row, header + row.trimEnd()]) {
      await atomicPrivateWrite(output, 'chat-channel-1.jsonl', contents);
      await assert.rejects(
        syncHistory(telegram, { output, resume: true }),
        /Invalid or duplicate existing export record|truncated final record/,
      );
      assert.equal(await readFile(filename, 'utf8'), contents);
    }
  },
);
test(
  'Archives and metadata are account-bound even if a peer ID is' +
    ' shared or metadata is missing',
  async (t) => {
    const root = await scratch(t),
      output = join(root, 'export');
    await syncHistory(
      source(
        [user(9)],
        {
          'user:9': [
            message(100, 1, {
              chatId: 'user:9',
              text: 'Account A conversation',
            }),
          ],
        },
        1,
      ),
      { output, all: true },
    );
    const filename = join(output, 'chat-user-9.jsonl'),
      before = await readFile(filename);
    const other = source(
      [user(9)],
      {
        'user:9': [
          message(101, 1, { chatId: 'user:9' }),
          message(99, 1, { chatId: 'user:9' }),
        ],
      },
      2,
    );
    await assert.rejects(
      syncHistory(other, { output, all: true, resume: true }),
      /account mismatch/,
    );
    assert.equal(other.observed.length, 0);
    await unlink(join(output, 'sync-meta.json'));
    await assert.rejects(
      syncHistory(other, { output, all: true, resume: true }),
      /account identity mismatch/,
    );
    assert.equal(other.observed.length, 0);
    assert.deepEqual(await readFile(filename), before);
    const header = records(before.toString())[0];
    assert.equal(header.accountId, 'user:1');
    assert.equal(header.version, 2);
  },
);
test(
  'Legacy or unbound metadata/headers cannot be silently' +
    ' assigned to the active account',
  async (t) => {
    const root = await scratch(t),
      output = join(root, 'export');
    const telegram = source([channel(1)], {}),
      filename = join(output, 'chat-channel-1.jsonl');
    for (const version of [1, 2]) {
      const contents =
        JSON.stringify({
          format: 'telegram-cli-export',
          version,
          untrusted: true,
          chat: { id: 'channel:1' },
        }) + '\n';
      await atomicPrivateWrite(output, 'chat-channel-1.jsonl', contents);
      await assert.rejects(
        syncHistory(telegram, { output, resume: true }),
        /legacy\/unbound archives/,
      );
      assert.equal(await readFile(filename, 'utf8'), contents);
    }
    for (const version of [1, 2]) {
      await atomicPrivateWrite(
        output,
        'sync-meta.json',
        JSON.stringify({
          format: 'telegram-cli-sync-meta',
          version,
          chats: {},
        }),
      );
      await assert.rejects(
        syncHistory(telegram, { output, resume: true }),
        isSecurityError,
      );
    }
    assert.equal(telegram.observed.length, 0);
  },
);
test(
  'Metadata round-trips 10,000 worst-case peer IDs within' +
    ' identical read/write limits',
  async (t) => {
    const root = await scratch(t),
      output = join(root, 'export');
    const chats = Object.create(null);
    for (let i = 0; i < MAX_SYNC_CHATS; i++) {
      const id = (9223372036854775807n - BigInt(i)).toString();
      chats[`channel:${id}`] = {
        file: `chat-channel-${id}.jsonl`,
        lastMessageId: 2147483647,
        exportedAt: '2026-11-05T12:00:00.123456789Z',
      };
    }
    const filename = join(output, 'sync-meta.json');
    await atomicPrivateWrite(
      output,
      'sync-meta.json',
      JSON.stringify(
        {
          format: 'telegram-cli-sync-meta',
          version: 2,
          accountId: 'user:1',
          chats,
        },
        null,
        2,
      ),
    );
    assert.ok((await stat(filename)).size > 1024 * 1024);
    const telegram = source([], {});
    await syncHistory(telegram, { output, resume: true });
    assert.ok((await stat(filename)).size <= MAX_META_BYTES);
    await syncHistory(telegram, { output, resume: true });
    assert.equal(
      Object.keys(JSON.parse(await readFile(filename, 'utf8')).chats).length,
      MAX_SYNC_CHATS,
    );
    chats['user:1'] = {
      file: 'chat-user-1.jsonl',
      lastMessageId: 0,
      exportedAt: '2026-11-05T12:00:00Z',
    };
    await writeFile(
      filename,
      JSON.stringify({
        format: 'telegram-cli-sync-meta',
        version: 2,
        accountId: 'user:1',
        chats,
      }),
    );
    await assert.rejects(
      syncHistory(telegram, { output, resume: true }),
      /chat count exceeds/,
    );
  },
);
test(
  'Bounded exports include the final second and correctly' +
    ' attribute outgoing private messages',
  async (t) => {
    const root = await scratch(t),
      output = join(root, 'export'),
      until = 1780000000;
    const rpc = fakeRpc((name, args) => {
      assert.equal(name, 'messages.GetHistory');
      const messages = [
        {
          _: 'Message',
          id: 1,
          out: true,
          peerId: { _: 'PeerUser', userId: 2n },
          date: until,
          message: 'Sent by account 1',
        },
      ];
      return {
        messages: messages.filter(
          (item) => !args.offsetDate || item.date < args.offsetDate,
        ),
      };
    });
    const telegram = createTelegram(rpc);
    rememberEntity(telegram.entities, user(2));
    await syncHistory(telegram, {
      output,
      chat: 'user:2',
      since: until,
      until,
    });
    const archive = records(
      await readFile(join(output, 'chat-user-2.jsonl'), 'utf8'),
    );
    assert.equal(archive.length, 2);
    assert.equal(archive[1].senderId, 'user:1');
    assert.equal(archive[1].chatId, 'user:2');
  },
);
