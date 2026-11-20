import test from 'node:test';
import assert from 'node:assert/strict';
import {
  appendFile,
  readdir,
  symlink,
  truncate,
  writeFile,
} from 'node:fs/promises';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { main, parseCommand } from '../src/cli.ts';
import { createTelegram, rememberEntity } from '../src/telegram.ts';
import { createRpcClient } from '../src/rpc.ts';
import { MAX_UPLOAD_MIB, openAttachment } from '../src/files.ts';
import {
  isSecurityError,
  ambiguousMutationError,
  isAmbiguousMutationError,
} from '../src/common.ts';
import { encode } from '../src/tl.ts';
import {
  directoryLink,
  fakeCredentials,
  fakeRpc,
  scratch,
  session,
  user,
  windows,
} from './support.ts';

const PART = 512 * 1024;

test(
  'Attachment aliases work on send/reply only and reject' +
    ' multiple files or caption sources',
  () => {
    for (const args of [
      ['send', 'self'],
      ['reply', 'self', '456'],
    ]) {
      assert.equal(
        parseCommand([...args, '-f', '/tmp/a report.pdf', '-m', 'Caption'])
          .values.file,
        '/tmp/a report.pdf',
      );
      assert.equal(
        parseCommand([...args, '--file=/tmp/a report.pdf', '--stdin']).values
          .stdin,
        true,
      );
      assert.throws(
        () => parseCommand([...args, '-f', 'a', '--file', 'b']),
        /Duplicate options/,
      );
      assert.throws(
        () => parseCommand([...args, '-f', 'a', '-m', 'caption', '--stdin']),
        /Choose one message input source/,
      );
      assert.throws(
        () => parseCommand([...args, '--file=']),
        /cannot be empty/,
      );
      assert.throws(() => parseCommand([...args, '-f']));
    }
    assert.throws(() => parseCommand(['read', 'self', '-f', 'file']));
  },
);

test(
  'Small file-only send streams exact binary parts and uses the' +
    ' document basename and checksum',
  async (t) => {
    const directory = await scratch(t),
      path = join(directory, 'fake résumé.bin'),
      data = Buffer.alloc(PART + 7, 0xa9);
    data.set([0, 255, 3], PART);
    await writeFile(path, data);
    const attachment = await openAttachment(path);
    t.after(() => attachment.close());
    const writes = [],
      audits = [];
    const rpc = fakeRpc((name, args, options) => {
      assert.equal(options.mutation, true);
      if (name === 'upload.SaveFilePart') {
        assert.equal(encode({ _: name, ...args }).readUInt32LE(), 0xb304a621);
        assert.equal(args.filePart, writes.length);
        writes.push({ id: args.fileId, bytes: Buffer.from(args.bytes) });
        assert.deepEqual(
          args.bytes,
          data.subarray(args.filePart * PART, (args.filePart + 1) * PART),
        );
        return true;
      }
      assert.equal(name, 'messages.SendMedia');
      assert.equal(encode({ _: name, ...args }).readUInt32LE(), 0x0330e77f);
      assert.equal(args.peer.userId, 2n);
      assert.equal(args.message, '');
      assert.equal(args.replyTo, undefined);
      assert.equal(args.media._, 'InputMediaUploadedDocument');
      assert.equal(args.media.forceFile, true);
      assert.equal(args.media.mimeType, 'application/octet-stream');
      assert.deepEqual(args.media.file, {
        _: 'InputFile',
        id: writes[0].id,
        parts: 2,
        name: 'fake résumé.bin',
        md5Checksum: createHash('md5').update(data).digest('hex'),
      });
      assert.deepEqual(args.media.attributes, [
        { _: 'DocumentAttributeFilename', fileName: 'fake résumé.bin' },
      ]);
      return {
        _: 'Updates',
        updates: [
          { _: 'UpdateMessageID', randomId: 0n, id: 111 },
          { _: 'UpdateMessageID', randomId: args.randomId, id: 888 },
        ],
      };
    });
    const telegram = createTelegram(rpc, {
      audit: async (entry) => audits.push(entry),
    });
    rememberEntity(telegram.entities, user(2));
    const sent = await telegram.send('user:2', '', { attachment });
    assert.equal(sent.messageId, 888);
    assert.equal(sent.chatId, 'user:2');
    assert.deepEqual(sent.file, {
      fileName: 'fake résumé.bin',
      size: data.length,
    });
    assert.deepEqual(
      writes.map(({ id }) => id),
      [writes[0].id, writes[0].id],
    );
    assert.deepEqual(
      audits.map(({ status }) => status),
      ['requested', 'succeeded'],
    );
    assert.doesNotMatch(JSON.stringify(audits), /résumé|octet-stream/);
    assert.deepEqual(await readdir(directory), ['fake résumé.bin']);
  },
);

test(
  'Large attachment reply uses numbered big parts and one media' +
    ' send with caption and reply ID',
  async (t) => {
    const directory = await scratch(t),
      path = join(directory, 'big.bin'),
      size = 10 * 1024 * 1024 + 1;
    await writeFile(path, Buffer.alloc(1));
    await truncate(path, size);
    const attachment = await openAttachment(path);
    t.after(() => attachment.close());
    let parts = 0,
      id;
    const rpc = fakeRpc((name, args) => {
      if (name === 'upload.SaveBigFilePart') {
        assert.equal(encode({ _: name, ...args }).readUInt32LE(), 0xde7b673d);
        assert.equal(args.fileTotalParts, 21);
        assert.equal(args.filePart, parts++);
        assert.equal(args.bytes.length, parts === 21 ? 1 : PART);
        id ??= args.fileId;
        assert.equal(args.fileId, id);
        return true;
      }
      assert.equal(name, 'messages.SendMedia');
      assert.equal(parts, 21);
      assert.equal(args.message, '  fake café caption\nline 2  ');
      assert.deepEqual(args.replyTo, {
        _: 'InputReplyToMessage',
        replyToMsgId: 456,
      });
      assert.deepEqual(args.media.file, {
        _: 'InputFileBig',
        id,
        parts: 21,
        name: 'big.bin',
      });
      return { _: 'UpdateShortSentMessage', id: 789 };
    });
    const telegram = createTelegram(rpc);
    rememberEntity(telegram.entities, user(2));
    assert.equal(
      (
        await telegram.send('user:2', '  fake café caption\nline 2  ', {
          attachment,
          replyTo: 456,
        })
      ).messageId,
      789,
    );
    assert.equal(
      rpc.calls.filter((call) => call.name === 'messages.SendMedia').length,
      1,
    );
  },
);

test(
  'Unsafe attachment paths and sizes fail before opening a' + ' client',
  async (t) => {
    const directory = await scratch(t),
      fake = fakeCredentials(directory);
    await fake.store.create(session());
    const empty = join(directory, 'empty'),
      big = join(directory, 'huge'),
      alias = join(directory, 'alias');
    await writeFile(empty, '');
    await writeFile(big, '');
    await truncate(big, MAX_UPLOAD_MIB * 1024 * 1024 + 1);
    if (!windows) await symlink(big, alias, 'file');
    await symlink(directory, join(directory, 'linked-parent'), directoryLink);
    for (const filename of [
      directory,
      empty,
      big,
      ...(windows ? [] : [alias]),
      join(directory, 'linked-parent', 'empty'),
      join(directory, 'not-found'),
    ]) {
      await assert.rejects(
        main(['send', 'self', '-f', filename, '--state-dir', directory], {
          makeStore: () => ({
            load() {
              assert.fail('Invalid files must not load credentials');
            },
          }),
          makeClient: () => assert.fail('Invalid files must not open a client'),
        }),
        isSecurityError,
      );
    }
  },
);

test('Attachment input rejects FIFOs without blocking', async (t) => {
  if (windows) return t.skip('POSIX FIFO fixture');
  const fifo = join(await scratch(t), 'fifo');
  const made = spawnSync('mkfifo', [fifo]);
  if (made.error?.code === 'ENOENT') {
    t.skip('Optional mkfifo fixture utility unavailable');
    return;
  }
  assert.ifError(made.error);
  assert.equal(made.status, 0);
  await assert.rejects(openAttachment(fifo), /regular file/);
});

test(
  'Rejected, interrupted or modified uploads never send a' +
    ' message; ambiguous final sends are not retried',
  async (t) => {
    const directory = await scratch(t);
    for (const mode of ['reject', 'interrupt', 'changed', 'final']) {
      const path = join(directory, mode);
      await writeFile(path, 'fixture');
      const attachment = await openAttachment(path);
      try {
        const audits = [],
          rpc = fakeRpc(async (name) => {
            if (name === 'messages.SendMedia' || mode === 'interrupt')
              throw ambiguousMutationError();
            if (mode === 'changed') await appendFile(path, 'changed');
            return mode !== 'reject';
          });
        const telegram = createTelegram(rpc, {
          audit: async (entry) => audits.push(entry),
        });
        rememberEntity(telegram.entities, user(2));
        await assert.rejects(
          telegram.send('user:2', '', { attachment }),
          mode === 'final'
            ? isAmbiguousMutationError
            : /no message was submitted/,
        );
        assert.equal(
          rpc.calls.filter((call) => call.name === 'upload.SaveFilePart')
            .length,
          1,
        );
        assert.equal(
          rpc.calls.filter((call) => call.name === 'messages.SendMedia').length,
          mode === 'final' ? 1 : 0,
        );
        assert.deepEqual(
          audits.map(({ status }) => status),
          ['requested', mode === 'final' ? 'unknown' : 'failed'],
        );
      } finally {
        await attachment.close();
      }
    }
  },
);

test('RPC client treats file parts and media sends as mutations', async () => {
  const client = createRpcClient(session(), {
    transportFactory: () => ({ close() {} }),
  });
  try {
    for (const name of [
      'upload.SaveFilePart',
      'upload.SaveBigFilePart',
      'messages.SendMedia',
    ]) {
      await assert.rejects(
        client.invoke(name),
        /mutation must be explicitly classified/,
      );
    }
  } finally {
    client.close();
  }
});

test(
  'CLI attaches a file without a terminal, with optional -m' +
    ' caption on replies',
  async (t) => {
    const directory = await scratch(t),
      path = join(directory, 'a document.txt');
    await writeFile(path, 'FAKE_FILE_CONTENT');
    const child = `
import assert from 'node:assert/strict';
import { main } from './src/cli.ts';
import { fakeCredentials, fakeRpc, session } from './tests/support.ts';
const [state, file, command] = process.argv.slice(1),
  fake = fakeCredentials(state);
await fake.store.create(session());
const rpc = fakeRpc((name, args) => {
  if (name === 'upload.SaveFilePart') {
    assert.equal(args.bytes.toString(), 'FAKE_FILE_CONTENT');
    return true;
  }
  assert.equal(name, 'messages.SendMedia');
  assert.equal(args.media.file.name, 'a document.txt');
  assert.equal(args.message, command === 'reply' ? 'FAKE_CAPTION' : '');
  assert.equal(
    args.replyTo?.replyToMsgId,
    command === 'reply' ? 123 : undefined,
  );
  return { _: 'UpdateShortSentMessage', id: 42 };
});
const flags =
  command === 'reply'
    ? ['123', '--file', file, '-m', 'FAKE_CAPTION']
    : ['-f', file];
await main([command, 'self', ...flags, '--json', '--state-dir', state], {
  makeStore: () => fake.store,
  makeClient: () => ({ ...rpc, open: async () => {}, close() {} }),
});
assert.equal(rpc.calls.filter((call) => call.options?.mutation).length, 2);
    `;
    for (const command of ['send', 'reply']) {
      const state = join(directory, command);
      const result = spawnSync(
        process.execPath,
        ['--input-type=module', '-e', child, state, path, command],
        {
          cwd: new URL('../', import.meta.url),
          encoding: 'utf8',
          detached: true,
          timeout: windows ? 20_000 : 5000,
        },
      );
      assert.equal(result.status, 0, result.stderr + result.stdout);
      assert.equal(JSON.parse(result.stdout).result.messageId, 42);
      assert.doesNotMatch(
        result.stdout + result.stderr,
        /FAKE_FILE_CONTENT|FAKE_CAPTION/,
      );
      assert.deepEqual((await readdir(state)).sort(), [
        'audit.jsonl',
        'session.json',
      ]);
    }
  },
);
