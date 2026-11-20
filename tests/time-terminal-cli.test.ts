import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
  timeFilter,
  epochSeconds,
  isoSeconds,
  muteUntil,
  safeJson,
  terminalText,
} from '../src/common.ts';
import { readFile, readdir } from 'node:fs/promises';
import { parseCommand, main } from '../src/cli.ts';
import {
  fakeCredentials,
  fakeRpc,
  scratch,
  session,
  windows,
} from './support.ts';
import { join } from 'node:path';

test(
  'All time calculations use native Temporal and preserve exact' +
    ' boundaries',
  () => {
    const reference = Temporal.Instant.from('2026-11-05T12:00:00Z');
    assert.equal(
      timeFilter('1h', reference).toString(),
      '2026-11-05T11:00:00Z',
    );
    assert.equal(
      timeFilter('7d', reference).toString(),
      '2026-10-29T12:00:00Z',
    );
    assert.equal(
      timeFilter('2026-11-01T00:00:00Z').toString(),
      '2026-11-01T00:00:00Z',
    );
    assert.equal(isoSeconds(epochSeconds(reference)), reference.toString());
    assert.equal(
      epochSeconds(Temporal.Instant.from('1969-12-31T23:59:59.9Z')),
      -1,
    );
    assert.equal(muteUntil('1h', reference), epochSeconds(reference) + 3600);
    assert.equal(muteUntil('forever', reference), 2_147_483_647);
    assert.throws(() => muteUntil('0m', reference));
    assert.throws(() => timeFilter('10000000000000000d', reference));
    assert.throws(() => timeFilter('2026-11-05'));
  },
);
test(
  'Output escapes terminal controls/bidi while machine JSON' +
    ' retains the original value',
  () => {
    const payload = '\x1b]52;c;AAAA\x07\n\u202e\u009b\u061c\u200e\u200f';
    const json = safeJson({ text: payload });
    assert.equal(JSON.parse(json).text, payload);
    // oxlint-disable-next-line no-control-regex -- Check control escaping.
    const controls = /[\x1b\x07\u009b\p{Bidi_Control}]/u;
    assert.ok(!controls.test(json));
    assert.ok(!controls.test(terminalText(payload)));
    assert.ok(!terminalText(payload).includes('\n'));
  },
);
test(
  'Native argument parser rejects implicit global search, yes' +
    ' flags, extra args and unsafe promotions',
  () => {
    assert.throws(() => parseCommand(['send', 'user:1', 'secret body']));
    assert.throws(() => parseCommand(['send', 'user:1', '--yes']));
    assert.throws(() => parseCommand(['delete', 'user:1', '42']), /--for-me/);
    assert.throws(() =>
      parseCommand(['delete', 'user:1', '42', '--for-me', '--for-everyone']),
    );
    for (const id of ['0', '-1', '2147483648', '1,2'])
      assert.throws(() => parseCommand(['delete', 'user:1', id, '--for-me']));
    assert.throws(() =>
      parseCommand(['transfer-owner', 'channel:1', 'user:2', '-y']),
    );
    assert.throws(() => parseCommand(['search', 'keyword']));
    assert.throws(() =>
      parseCommand(['search', 'keyword', '--chat', 'self', '--all']),
    );
    assert.throws(() => parseCommand(['promote', 'channel:1', 'user:2']));
    assert.throws(() => parseCommand(['sync', '--all', '--days', '7']));
    assert.throws(() =>
      parseCommand([
        'send',
        'user:1',
        '--passphrase-fd',
        '3',
        '--message-fd',
        '3',
      ]),
    );
    assert.throws(() => parseCommand(['read', 'self', '--limit', '0']));
    assert.throws(() =>
      parseCommand(['read', 'self', '--limit', '10', '--limit', '20']),
    );
    assert.throws(() => parseCommand(['read', 'self', '--passphrase-fd', '0']));
    assert.throws(() => parseCommand(['sync', '--output=']));
    assert.throws(() => parseCommand(['folder-create', 'Work']));
    assert.throws(() =>
      parseCommand(['folder-create', 'Work', '--categories', 'everything']),
    );
    assert.throws(() => parseCommand(['folder-create', 'Work', '--include=']));
    assert.equal(
      parseCommand(['folder-create', 'Work', '--categories', 'contacts,groups'])
        .values.categories,
      'contacts,groups',
    );
    assert.equal(
      parseCommand(['folder-create', 'Work', '--include', 'channel:1,user:2'])
        .values.include,
      'channel:1,user:2',
    );
    assert.equal(
      parseCommand(['read', '-1001234567890', '--json']).positionals[0],
      'channel:1234567890',
    );
    assert.equal(parseCommand(['search', 'query', '--all']).command, 'search');
  },
);
test(
  'Negative numeric queries, titles and option values are' +
    ' preserved; only peer arguments are canonicalized',
  () => {
    assert.equal(
      parseCommand(['search', '--all', '--', '-123']).positionals[0],
      '-123',
    );
    assert.equal(
      parseCommand(['search', '-123', '--all']).positionals[0],
      '-123',
    );
    assert.equal(
      parseCommand(['search', '--all', '--', '-999999999999999999999999999999'])
        .positionals[0],
      '-999999999999999999999999999999',
    );
    const scoped = parseCommand(['search', '--chat', '-123', '--', '-456']);
    assert.equal(scoped.values.chat, 'chat:123');
    assert.equal(scoped.positionals[0], '-456');
    assert.equal(
      parseCommand(['folder-create', '--categories', 'groups', '--', '-123'])
        .positionals[0],
      '-123',
    );
    const folder = parseCommand(['folder-add', '-123', '-1001234567890']);
    assert.deepEqual(folder.positionals, ['-123', 'channel:1234567890']);
    const promotion = parseCommand([
      'promote',
      '-123',
      '456',
      '--rights',
      'full',
      '--rank',
      '-789',
    ]);
    assert.equal(promotion.positionals[0], 'chat:123');
    assert.equal(promotion.values.rank, '-789');
    assert.equal(
      parseCommand(['sync', '--output', '-123', '--state-dir=-456']).values
        .output,
      '-123',
    );
    assert.equal(
      parseCommand(['sync', '--output', '-123', '--state-dir=-456']).values[
        'state-dir'
      ],
      '-456',
    );
    assert.equal(
      parseCommand(['migrate', '--from', '-123']).values.from,
      '-123',
    );
    assert.throws(() => parseCommand(['read', '-0']));
    assert.throws(() => parseCommand(['reply', '-123', '-456']));
    assert.throws(() => parseCommand(['read', 'self', '--limit', '-123']));
  },
);
test(
  'Send/reply accept -m and --message literally, with only one' +
    ' message input source',
  () => {
    const text = '  Some café 🌍\nmessage  ';
    for (const args of [
      ['send', 'user:123'],
      ['reply', 'user:123', '456'],
    ]) {
      for (const option of ['-m', '--message'])
        assert.equal(
          parseCommand([...args, option, text]).values.message,
          text,
        );
      assert.equal(
        parseCommand([...args, '--message=' + text]).values.message,
        text,
      );
      assert.equal(
        parseCommand([...args, '-m', '-123']).values.message,
        '-123',
      );
      assert.equal(
        parseCommand([...args, '--message=--quiet']).values.message,
        '--quiet',
      );
      for (const options of [
        ['-m', text, '--stdin'],
        ['--message', text, '--message-fd', '3'],
        ['--stdin', '--message-fd', '3'],
      ])
        assert.throws(
          () => parseCommand([...args, ...options]),
          /Choose one message input source/,
        );
      assert.throws(
        () => parseCommand([...args, '-m', text, '--message', text]),
        /Duplicate options/,
      );
      assert.throws(() => parseCommand([...args, '-m']));
    }
    assert.equal(
      parseCommand(['send', '-m', text, 'user:123']).values.message,
      text,
    );
    assert.throws(
      () => parseCommand(['send', '-m', text]),
      /Incorrect arguments/,
    );
    assert.throws(() => parseCommand(['read', 'user:123', '-m', text]));
  },
);
test(
  'Invalid inline messages are rejected before credential' +
    ' access or connecting',
  async (t) => {
    const directory = await scratch(t);
    const never = () => {
      throw new Error('Credentials/client must not be accessed');
    };
    for (const text of ['', 'x'.repeat(4097), '\ud800', 'FAKE_PRIVATE\0BODY']) {
      await assert.rejects(
        main(['send', 'user:123', '-m', text, '--state-dir', directory], {
          makeStore: never,
          makeClient: never,
        }),
        (error) =>
          error.name === 'SecurityError' &&
          /Message must contain/.test(error.message) &&
          !error.message.includes('FAKE_PRIVATE'),
      );
    }
    assert.throws(
      () => parseCommand(['send', 'user:123', '--message=', '--stdin']),
      /Choose one message input source/,
    );
    assert.deepEqual(await readdir(directory), []);
  },
);
test(
  'Help and version are offline and do not read/create' + ' credentials',
  async () => {
    let text = '';
    const stdout = {
      write(value) {
        text += value;
      },
    };
    await main(['--help'], { stdout });
    assert.match(text, /^telegramctl 0\.1\.0/);
    assert.match(text, /Usage: telegramctl <command>/);
    assert.match(text, /zero npm dependencies/);
    assert.match(text, /No app vault or app passphrase/);
    assert.match(text, /Node\.js 26\.0\.0\+/);
    assert.doesNotMatch(
      text,
      /EXPERIMENTAL|independently audited|interoperability tested/,
    );
    assert.match(text, /Remote account changes submit without confirmation/);
    assert.match(
      text,
      /Migration and forget-local still require terminal confirmation/,
    );
    assert.match(text, /-m <text> \| --message <text>/);
    assert.match(text, /shell history\/process listings/);
    assert.match(text, /auth login/);
    assert.match(text, /auth logout/);
    text = '';
    await main(['--version'], { stdout });
    assert.equal(text, '0.1.0\n');
  },
);
test('The npm package and command are both telegramctl', async () => {
  const pkg = JSON.parse(
    await readFile(new URL('../package.json', import.meta.url), 'utf8'),
  );
  assert.equal(pkg.name, 'telegramctl');
  assert.notEqual(pkg.private, true);
  assert.equal(pkg.engines.node, '>=26.0.0');
  assert.deepEqual(pkg.bin, { telegramctl: 'dist/bin/telegramctl.js' });
});
test('Auth group and command-specific help stay offline', async () => {
  let text = '';
  const options = {
    stdout: {
      write(value: string) {
        text += value;
      },
    },
    makeStore: () => assert.fail('Help must not access the credential store'),
  };
  for (const args of [['auth'], ['auth', '--help'], ['auth', '-h']]) {
    text = '';
    await main(args, options);
    assert.match(text, /Usage: telegramctl auth <login\|check\|logout>/);
    assert.match(text, /login\s+Login and save/);
    assert.match(text, /check\s+Check the saved session/);
    assert.match(text, /logout\s+Revoke/);
    assert.doesNotMatch(text, /Admin rights/);
  }
  text = '';
  await main(['auth', 'login', '--help'], options);
  assert.match(text, /Usage: telegramctl auth login/);
  assert.match(text, /--store keyring\|gopass/);
  assert.match(text, /--dc <id>/);
  text = '';
  await main(['auth', 'check', '--help'], options);
  assert.match(text, /Usage: telegramctl auth check/);
  assert.match(text, /does not mark messages read/);
  text = '';
  await main(['download', '--help'], options);
  assert.match(text, /system Downloads folder/);
  assert.match(text, /-o, --output/);
  assert.doesNotMatch(text, /Admin rights/);
});
test('Auth check verifies the saved account without mutations', async (t) => {
  const directory = await scratch(t);
  const fake = fakeCredentials(directory);
  await fake.store.create(session());
  const rpc = fakeRpc((name) => assert.fail(`Unexpected RPC: ${name}`));
  let text = '';
  await main(['auth', 'check', '--state-dir', directory, '--json', '--quiet'], {
    stdout: {
      write(value: string) {
        text += value;
      },
    },
    makeStore: () => fake.store,
    makeClient: () => ({ ...rpc, open: async () => {}, close() {} }),
  });
  const result = JSON.parse(text).result;
  assert.equal(result.valid, true);
  assert.equal(result.accountId, 'user:1');
  assert.equal(result.storage, 'keyring');
  assert.deepEqual(
    rpc.calls.map(({ name }) => name),
    ['users.GetUsers'],
  );
  assert.equal(fake.records.size, 1);
  assert.equal((await readdir(directory)).includes('audit.jsonl'), false);
});
test(
  'The executable reports a clean version requirement when' +
    ' Temporal is unavailable',
  () => {
    const result = spawnSync(
      process.execPath,
      [
        '--import=data:text/javascript,delete%20globalThis.Temporal',
        'bin/telegramctl.ts',
        '--help',
      ],
      { cwd: new URL('../', import.meta.url), encoding: 'utf8', timeout: 5000 },
    );
    assert.equal(result.status, 1);
    assert.equal(result.stdout, '');
    assert.equal(
      result.stderr,
      'telegramctl requires Node.js 26.0.0+ with native Temporal enabled.\n',
    );
  },
);
test(
  'Missing credential reference and invalid options fail before' +
    ' asking for secrets or connecting',
  async (t) => {
    const directory = await scratch(t);
    await assert.rejects(
      main(['auth', 'check', '--state-dir', join(directory, 'missing')]),
      /No keyring\/gopass session/,
    );
    const result = spawnSync(
      process.execPath,
      ['bin/telegramctl.ts', 'read', 'self', '--FAKE_ARG_SECRET'],
      { cwd: new URL('../', import.meta.url), encoding: 'utf8' },
    );
    assert.equal(result.status, 1);
    assert.ok(!result.stderr.includes('FAKE_ARG_SECRET'));
    assert.equal(result.stdout, '');
  },
);
test(
  'CLI send/reply accept stdin or inline text without a' +
    ' terminal or temporary message files',
  async (t) => {
    const directory = await scratch(t);
    const child = `
import assert from 'node:assert/strict';
import { main } from './src/cli.ts';
import { fakeCredentials, fakeRpc, session, user } from './tests/support.ts';
const directory = process.argv[1],
  command = process.argv[2],
  mode = process.argv[3],
  text = process.argv[4],
  fake = fakeCredentials(directory);
await fake.store.create(session());
const rpc = fakeRpc((name, args, options) => {
  if (name === 'contacts.ResolveUsername')
    return { peer: { _: 'PeerUser', userId: 2n }, users: [user(2)] };
  assert.equal(name, 'messages.SendMessage');
  assert.equal(args.peer.userId, 2n);
  assert.equal(args.message, text);
  assert.equal(
    args.replyTo?.replyToMsgId,
    command === 'reply' ? 123 : undefined,
  );
  assert.equal(options.mutation, true);
  return { _: 'UpdateShortSentMessage', id: 456 };
});
const client = { ...rpc, open: async () => {}, close() {} };
const source = mode === 'stdin' ? ['--stdin'] : [mode, text];
await main(
  [
    command,
    '@fake_recipient',
    ...(command === 'reply' ? ['123'] : []),
    ...source,
    '--json',
    '--state-dir',
    directory,
  ],
  { makeStore: () => fake.store, makeClient: () => client },
);
    `;
    for (const command of ['send', 'reply'])
      for (const mode of ['stdin', '-m', '--message']) {
        const state = join(directory, command + '-' + mode),
          text =
            mode === 'stdin'
              ? 'FAKE_PRIVATE_BODY\n'
              : '  FAKE_PRIVATE_BODY café 🌍\n\'" $() ; `backticks`  ';
        const result = spawnSync(
          process.execPath,
          ['--input-type=module', '-e', child, state, command, mode, text],
          {
            cwd: new URL('../', import.meta.url),
            encoding: 'utf8',
            detached: true,
            input: mode === 'stdin' ? text : 'UNUSED_STDIN',
            timeout: windows ? 20_000 : 5000,
          },
        );
        assert.equal(result.status, 0, result.stderr + result.stdout);
        assert.equal(JSON.parse(result.stdout).result.messageId, 456);
        assert.doesNotMatch(
          result.stdout + result.stderr,
          /Type exactly|FAKE_PRIVATE_BODY/,
        );
        const audit = (await readFile(join(state, 'audit.jsonl'), 'utf8'))
          .trim()
          .split('\n')
          .map((line) => JSON.parse(line));
        assert.deepEqual(
          audit.map((entry) => entry.status),
          ['requested', 'succeeded'],
        );
        assert.ok(
          audit.every(
            (entry) => entry.command === command && entry.peers[0] === 'user:2',
          ),
        );
        assert.deepEqual((await readdir(state)).sort(), [
          'audit.jsonl',
          'session.json',
        ]);
      }
  },
);
test(
  'CLI settings, deletion, administration, folders and logout run without' +
    ' a controlling terminal',
  async (t) => {
    const directory = await scratch(t);
    const child = `
import assert from 'node:assert/strict';
import { main } from './src/cli.ts';
import {
  fakeCredentials,
  fakeRpc,
  session,
  user,
  channel,
} from './tests/support.ts';
const directory = process.argv[1],
  args = JSON.parse(process.argv[2]),
  command = args[0] === 'auth' ? args[1] : args[0],
  fake = fakeCredentials(directory);
await fake.store.create(session());
const rpc = fakeRpc((name, params, options) => {
  if (name === 'messages.GetDialogs')
    return {
      _: 'messages.Dialogs',
      users: [user(2)],
      chats: [channel(3)],
      dialogs: [],
      messages: [],
    };
  if (name === 'messages.GetDialogFilters')
    return {
      filters:
        command === 'folder-create'
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
  if (name === 'channels.GetMessages')
    return {
      messages: [
        { _: 'Message', id: 42, peerId: { _: 'PeerChannel', channelId: 3n } },
      ],
    };
  assert.equal(options.mutation, true);
  if (name === 'channels.DeleteMessages') {
    assert.equal(params.channel.channelId, 3n);
    assert.deepEqual(params.id, [42]);
    return { _: 'messages.AffectedMessages', pts: 8, ptsCount: 1 };
  }
  if (name === 'account.UpdateNotifySettings') {
    assert.equal(
      params.settings.muteUntil,
      command === 'unmute' ? 0 : 2147483647,
    );
    return true;
  }
  if (name === 'channels.EditBanned') {
    assert.equal(params.participant.userId, 2n);
    return { _: 'UpdatesTooLong' };
  }
  if (name === 'channels.EditAdmin') {
    assert.equal(params.userId.userId, 2n);
    assert.equal(params.adminRights.pinMessages, true);
    return { _: 'UpdatesTooLong' };
  }
  if (name === 'messages.UpdateDialogFilter') return true;
  if (name === 'auth.LogOut') return { _: 'auth.LoggedOut' };
  throw new Error('Unexpected fake RPC: ' + name);
});
await main([...args, '--json', '--state-dir', directory], {
  makeStore: () => fake.store,
  makeClient: () => ({ ...rpc, open: async () => {}, close() {} }),
});
assert.equal(rpc.calls.filter((call) => call.options?.mutation).length, 1);
assert.equal(fake.records.size, command === 'logout' ? 0 : 1);
    `;
    const cases = [
      ['mute', 'user:2'],
      ['unmute', 'user:2'],
      ['delete', 'channel:3', '42', '--for-everyone'],
      ['kick', 'channel:3', 'user:2'],
      ['promote', 'channel:3', 'user:2', '--rights', 'pinMessages'],
      ['folder-create', 'Work', '--categories', 'groups'],
      ['folder-add', 'folder:2', 'user:2'],
      ['folder-remove', 'folder:2', 'user:2'],
      ['auth', 'logout'],
    ];
    for (const args of cases) {
      const verb = args[0] === 'auth' ? args[1] : args[0];
      const state = join(directory, verb);
      const result = spawnSync(
        process.execPath,
        ['--input-type=module', '-e', child, state, JSON.stringify(args)],
        {
          cwd: new URL('../', import.meta.url),
          encoding: 'utf8',
          detached: true,
          timeout: windows ? 20_000 : 5000,
        },
      );
      assert.equal(result.status, 0, result.stderr + result.stdout);
      const value = JSON.parse(result.stdout).result;
      assert.equal(
        verb === 'logout' ? value.revoked && value.localDeleted : value.success,
        true,
      );
      assert.doesNotMatch(
        result.stdout + result.stderr,
        /Type exactly|to approve/,
      );
      if (args[0] === 'delete')
        assert.deepEqual(value, {
          success: true,
          chatId: 'channel:3',
          messageId: 42,
          scope: 'everyone',
        });
      const audit = (await readFile(join(state, 'audit.jsonl'), 'utf8'))
        .trim()
        .split('\n')
        .map((line) => JSON.parse(line));
      assert.deepEqual(
        audit.map((entry) => entry.status),
        ['requested', 'succeeded'],
      );
      assert.ok(audit.every((entry) => entry.command === verb));
    }
  },
);
test(
  'CLI migration and forget-local still require confirmation' +
    ' before changing credentials',
  async (t) => {
    const directory = await scratch(t);
    const child = `
import assert from 'node:assert/strict';
import { atomicPrivateWrite } from './src/files.ts';
import { main } from './src/cli.ts';
import { fakeCredentials, session } from './tests/support.ts';
const directory = process.argv[1],
  command = process.argv[2],
  fake = fakeCredentials(directory);
const args = [command, '--state-dir', directory];
if (command === 'forget-local') await fake.store.create(session());
else {
  await fake.store.assertNew();
  const data = Buffer.alloc(263, 7);
  data[0] = 2;
  data.writeUInt16BE(443, 5);
  const source = directory + '/legacy.json',
    value = session();
  await atomicPrivateWrite(
    directory,
    'legacy.json',
    JSON.stringify({
      apiId: value.apiId,
      apiHash: value.apiHash,
      sessionString: '1' + data.toString('base64'),
    }),
  );
  args.push('--from', source);
}
await assert.rejects(
  main(args, {
    makeStore: () => fake.store,
    makeClient: () => {
      throw new Error('No network permitted');
    },
  }),
  { name: 'ApprovalError' },
);
assert.equal(fake.records.size, command === 'forget-local' ? 1 : 0);
console.log('CONFIRMATION_REQUIRED');
    `;
    for (const command of ['migrate', 'forget-local']) {
      const result = spawnSync(
        process.execPath,
        ['--input-type=module', '-e', child, join(directory, command), command],
        {
          cwd: new URL('../', import.meta.url),
          encoding: 'utf8',
          detached: true,
          timeout: windows ? 20_000 : 5000,
        },
      );
      assert.equal(result.status, 0, result.stderr + result.stdout);
      assert.equal(result.stdout, 'CONFIRMATION_REQUIRED\n');
    }
  },
);
test(
  'Secret and local-confirmation prompts fail closed without a' +
    ' controlling terminal',
  () => {
    const result = spawnSync(
      process.execPath,
      [
        '--input-type=module',
        '-e',
        `
import { secretPrompt } from './src/cli.ts';
try {
  await secretPrompt('fake secret: ');
  process.exitCode = 2;
} catch (error) {
  process.stdout.write(error.name);
}
        `,
      ],
      {
        cwd: new URL('../', import.meta.url),
        encoding: 'utf8',
        detached: true,
        timeout: 5000,
      },
    );
    assert.equal(result.status, 0);
    assert.equal(result.stdout, 'ApprovalError');
    const confirmation = spawnSync(
      process.execPath,
      [
        '--input-type=module',
        '-e',
        `
import { prompt } from './src/cli.ts';
try {
  await prompt('Type IMPORT: ');
  process.exitCode = 2;
} catch (error) {
  process.stdout.write(error.name);
}
        `,
      ],
      {
        cwd: new URL('../', import.meta.url),
        encoding: 'utf8',
        detached: true,
        timeout: 5000,
      },
    );
    assert.equal(confirmation.status, 0);
    assert.equal(confirmation.stdout, 'ApprovalError');
    assert.equal(confirmation.stderr, '');
  },
);
test(
  'Local confirmation stays on the controlling TTY with' +
    ' redirected diagnostics, and secrets remain hidden',
  { skip: windows && 'POSIX PTY fixture' },
  async (t) => {
    // Optional integration driver only: no Python package/install is required.
    // Core no-TTY/privacy tests above always run using Node alone.
    const directory = await scratch(t);
    const child = `
import { prompt, secretPrompt } from './src/cli.ts';
const answer = await prompt('Type IMPORT: ', {
  review: 'FAKE_PRIVATE_REVIEW\\n',
});
if (answer !== 'IMPORT') throw new Error('Confirmation mismatch');
const secret = await secretPrompt('FAKE HIDDEN INPUT: ');
console.log('CONFIRMED SECRET ' + secret.length);
secret.fill(0);
    `;
    const driver = String.raw`
import os, pty, select, signal, sys, time
node, code, directory = sys.argv[1:]
pid, fd = pty.fork()
if pid == 0:
    for number, name in [(1, 'stdout'), (2, 'stderr')]:
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        output = os.open(os.path.join(directory, name), flags, 0o600)
        os.dup2(output, number)
        os.close(output)
    os.execv(node, [node, '--input-type=module', '-e', code])
data = b''
confirmed = hidden = False
reaped = False
deadline = time.monotonic() + 10
def wait_timeout(signum, frame):
    raise TimeoutError('PTY child did not exit')
signal.signal(signal.SIGALRM, wait_timeout)
try:
    while time.monotonic() < deadline:
        timeout = max(0, deadline - time.monotonic())
        ready, _, _ = select.select([fd], [], [], timeout)
        if not ready: break
        try: part = os.read(fd, 65536)
        except OSError: break
        if not part: break
        data += part
        if b'Type IMPORT: ' in data and not confirmed:
            review = data.index(b'FAKE_PRIVATE_REVIEW')
            assert review < data.index(b'Type IMPORT: ')
            os.write(fd, b'IMPORT\n')
            confirmed = True
        if b'FAKE HIDDEN INPUT: ' in data and not hidden:
            os.write(fd, b'  fake hidden secret  \n')
            hidden = True
    # EOF can precede process exit briefly (especially under coverage).
    # Wait boundedly instead of treating WNOHANG's zero as a prompt failure.
    signal.alarm(3)
    try:
        _, status = os.waitpid(pid, 0)
        reaped = True
    finally: signal.alarm(0)
    assert os.waitstatus_to_exitcode(status) == 0, data
    assert confirmed and hidden and b'fake hidden secret' not in data, data
    stdout = os.path.join(directory, 'stdout')
    assert open(stdout, 'rb').read() == b'CONFIRMED SECRET 22\n'
    assert open(os.path.join(directory, 'stderr'), 'rb').read() == b''
finally:
    os.close(fd)
    if not reaped:
        try: os.kill(pid, signal.SIGKILL)
        except ProcessLookupError: pass
        os.waitpid(pid, 0)
`;
    const result = spawnSync(
      'python3',
      ['-c', driver, process.execPath, child, directory],
      {
        cwd: new URL('../', import.meta.url),
        encoding: 'utf8',
        timeout: 15000,
      },
    );
    if (result.error?.code === 'ENOENT') {
      t.skip(
        'Optional PTY integration driver unavailable; Node-only' +
          ' privacy tests still run',
      );
      return;
    }
    assert.equal(result.status, 0, result.stderr + result.stdout);
  },
);
test(
  'Auth leaves its first question visible while idle and' +
    ' advances to the hidden API hash prompt',
  { skip: windows && 'POSIX PTY fixture' },
  async (t) => {
    const directory = await scratch(t);
    const child = `
import { main } from './src/cli.ts';
import { fakeCredentials } from './tests/support.ts';
try {
  await main(['auth', 'login', '--state-dir', process.argv[1] + '/state'], {
    makeStore: (directory) => fakeCredentials(directory).store,
  });
} catch (error) {
  console.error(error.name + ': ' + error.message);
  process.exitCode = 1;
}
    `;
    const driver = String.raw`
import os, pty, select, signal, sys, time
node, code, directory = sys.argv[1:]
pid, fd = pty.fork()
if pid == 0:
    os.execv(node, [node, '--input-type=module', '-e', code, directory])
data = b''
reaped = False
def wait_timeout(signum, frame):
    raise TimeoutError('Auth did not exit after cancellation')
signal.signal(signal.SIGALRM, wait_timeout)
def idle_prompt(label):
    global data
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        ready, _, _ = select.select([fd], [], [], 0.1)
        if ready:
            try: part = os.read(fd, 65536)
            except OSError: break
            if not part: break
            data += part
        elif label in data:
            # Inspect the final visible line after readline's erase-to-end
            # redraw, not merely bytes printed and immediately erased.
            assert label in data.rsplit(b'\x1b[0J', 1)[-1], data
            return
    raise AssertionError('Expected a visible idle prompt: ' + repr(data))
try:
    idle_prompt(b'Telegram API ID from https://my.telegram.org/apps: ')
    assert b'EXPERIMENTAL' not in data and b'No independent' not in data, data
    os.write(fd, b'12345\n')  # Fake API ID only; no credential/network use.
    idle_prompt(b'Telegram API hash: ')
    os.write(fd, b'\x03')
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        timeout = max(0, deadline - time.monotonic())
        ready, _, _ = select.select([fd], [], [], timeout)
        if not ready: break
        try: part = os.read(fd, 65536)
        except OSError: break
        if not part: break
        data += part
    signal.alarm(3)
    try:
        _, status = os.waitpid(pid, 0)
        reaped = True
    finally: signal.alarm(0)
    assert os.waitstatus_to_exitcode(status) == 1, data
    assert b'Cancelled' in data, data
finally:
    if not reaped:
        try: os.kill(pid, signal.SIGKILL)
        except ProcessLookupError: pass
        os.waitpid(pid, 0)
    os.close(fd)
`;
    const result = spawnSync(
      'python3',
      ['-c', driver, process.execPath, child, directory],
      {
        cwd: new URL('../', import.meta.url),
        encoding: 'utf8',
        timeout: 15000,
      },
    );
    if (result.error?.code === 'ENOENT') {
      t.skip('Optional PTY integration driver unavailable');
      return;
    }
    assert.equal(result.status, 0, result.stderr + result.stdout);
  },
);
test(
  'Credential manager selection is explicit and the old app' +
    ' passphrase option is rejected',
  () => {
    const login = parseCommand(['auth', 'login']);
    assert.equal(login.command, 'auth login');
    assert.equal(login.values.store, undefined);
    assert.equal(
      parseCommand(['auth', 'login', '--store', 'gopass']).values.store,
      'gopass',
    );
    assert.equal(parseCommand(['auth', 'login', '--dc', '3']).values.dc, '3');
    assert.equal(parseCommand(['auth', 'logout']).command, 'auth logout');
    assert.equal(parseCommand(['logout']).command, 'auth logout');
    assert.equal(parseCommand(['auth', 'check']).command, 'auth check');
    assert.equal(parseCommand(['check']).command, 'auth check');
    assert.throws(() => parseCommand(['auth', 'check', 'extra']), /Incorrect/);
    assert.throws(() => parseCommand(['auth', 'check', '--store', 'gopass']));
    assert.throws(() => parseCommand(['auth', 'logout', '--store', 'gopass']));
    assert.throws(() => parseCommand(['auth', 'unknown']), /auth --help/);
    assert.throws(
      () => parseCommand(['auth', '--store', 'gopass']),
      /auth login/,
    );
    assert.throws(() =>
      parseCommand(['auth', 'login', '--store', 'plaintext']),
    );
    assert.throws(() =>
      parseCommand(['auth', 'login', '--passphrase-fd', '3']),
    );
    assert.throws(() => parseCommand(['auth', 'login', 'extra']), /Incorrect/);
    assert.throws(() => parseCommand(['toString']), /Unknown command/);
  },
);
