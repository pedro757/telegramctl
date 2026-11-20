import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { readFile, writeFile, readdir, stat } from 'node:fs/promises';
import { join } from 'node:path';
import {
  credentialStore,
  runCredentialCommand,
  defaultStateDirectory,
  credentialExecutable,
} from '../src/credentials.ts';
import { HELPER_MISSING } from '../src/native.ts';
import { atomicPrivateWrite } from '../src/files.ts';
import { isSecurityError } from '../src/common.ts';
import { scratch, session, fakeCredentials, windows } from './support.ts';

test(
  'Default local state uses the telegram directory without' + ' accessing it',
  () => {
    assert.equal(
      defaultStateDirectory('linux', '/home/alice'),
      '/home/alice/.local/state/telegram',
    );
    assert.equal(
      defaultStateDirectory('darwin', '/Users/alice'),
      '/Users/alice/Library/Application Support/TelegramCLI',
    );
    assert.equal(
      defaultStateDirectory('win32', 'D:\\Users\\Alice', 'C:\\Local State'),
      'C:\\Local State\\TelegramCLI',
    );
    assert.equal(
      defaultStateDirectory('win32', 'D:\\Users\\Alice', 'relative'),
      'D:\\Users\\Alice\\AppData\\Local\\TelegramCLI',
    );
  },
);

for (const backend of ['keyring', 'gopass'])
  test(`${backend} writes only a nonsecret local reference`, async (t) => {
    const directory = await scratch(t),
      fake = fakeCredentials(directory, { backend }),
      original = session();
    await fake.store.create(original);
    const loaded = await fake.store.load();
    assert.equal(loaded.credentialStore, backend);
    assert.deepEqual(loaded.authKey, original.authKey);
    const file = join(directory, 'session.json'),
      text = await readFile(file, 'utf8'),
      ref = JSON.parse(text);
    assert.deepEqual(Object.keys(ref).sort(), [
      'id',
      'profile',
      'store',
      'version',
    ]);
    assert.equal(ref.store, backend);
    if (!windows) assert.equal((await stat(file)).mode & 0o777, 0o600);
    assert.ok(!text.includes(original.apiHash));
    assert.ok(!text.includes(original.authKey.toString('base64')));
    assert.deepEqual(await readdir(directory), ['session.json']);
    for (const call of fake.calls) {
      assert.ok(!call.args.join(' ').includes(original.apiHash));
      assert.ok(
        !call.args.join(' ').includes(original.authKey.toString('base64')),
      );
    }
    if (backend === 'gopass') {
      assert.ok(
        fake.calls.every(
          (call) =>
            call.args.includes('--nosync') &&
            call.args.includes('--nofuzzysearch'),
        ),
      );
      assert.ok(
        fake.calls
          .filter((call) => call.args.includes('show'))
          .every((call) => call.args.includes('--alsoclip=false')),
      );
    }
    const before = await readFile(file);
    await assert.rejects(fake.store.create(session()), /already configured/);
    assert.deepEqual(await readFile(file), before);
    assert.equal(fake.records.size, 1);
    await fake.store.remove({
      expectedFingerprint: loaded.credentialFingerprint,
    });
    if (backend === 'gopass')
      assert.deepEqual(fake.calls.at(-1).args.slice(3, -1), [
        'list',
        '--flat',
        '--limit',
        '1',
      ]);
    assert.equal(fake.records.size, 0);
    assert.deepEqual(await readdir(directory), []);
    loaded.authKey.fill(0);
  });
test(
  'An existing custom-vault file is never read, changed,' +
    ' deleted or used as fallback',
  async (t) => {
    const directory = await scratch(t),
      fake = fakeCredentials(directory),
      old = join(directory, 'session.enc.json');
    await writeFile(old, 'OLD USER DATA', { mode: 0o600 });
    await assert.rejects(
      fake.store.load(),
      /old session.enc.json files are not loaded or changed/,
    );
    await fake.store.create(session());
    await fake.store.remove();
    assert.equal(await readFile(old, 'utf8'), 'OLD USER DATA');
    assert.deepEqual(await readdir(directory), ['session.enc.json']);
  },
);
test(
  'References are bound to the state directory, and loading' +
    ' uses the recorded backend',
  async (t) => {
    const directory = await scratch(t),
      other = await scratch(t),
      fake = fakeCredentials(directory);
    await fake.store.create(session());
    await atomicPrivateWrite(
      other,
      'session.json',
      await readFile(join(directory, 'session.json')),
    );
    await assert.rejects(
      credentialStore(other, { run: fake.run }).load(),
      /profile identity/,
    );
    const loaded = await credentialStore(directory, {
      backend: 'gopass',
      run: fake.run,
    }).load();
    assert.equal(loaded.credentialStore, 'keyring');
    assert.ok(fake.calls.every((call) => call.store === 'keyring'));
    loaded.authKey.fill(0);
  },
);
test('Malformed references fail before invoking either helper', async (t) => {
  const directory = await scratch(t),
    fake = fakeCredentials(directory);
  await fake.store.create(session());
  const filename = join(directory, 'session.json'),
    original = JSON.parse(await readFile(filename, 'utf8')),
    calls = fake.calls.length;
  for (const ref of [
    { ...original, store: ['keyring'] },
    { ...original, id: [original.id] },
    { ...original, unexpected: true },
  ]) {
    await writeFile(filename, JSON.stringify(ref));
    await assert.rejects(fake.store.load(), /Invalid credential reference/);
    assert.equal(fake.calls.length, calls);
  }
  assert.throws(
    () => credentialStore(directory, { backend: ['gopass'] }),
    isSecurityError,
  );
  await assert.rejects(runCredentialCommand('toString', []), isSecurityError);
});
test(
  'gopass deletion never treats a decryption failure as proof' + ' of absence',
  async (t) => {
    const directory = await scratch(t),
      fake = fakeCredentials(directory, { backend: 'gopass' });
    await fake.store.create(session());
    fake.failure = (backend, args) =>
      args.includes('list')
        ? { code: 11, stdout: Buffer.alloc(0), stderrBytes: 20 }
        : undefined;
    await assert.rejects(fake.store.remove(), /deletion verification failed/);
    assert.deepEqual(await readdir(directory), ['session.json']);
  },
);
test(
  'Manager read/save/deletion failures do not fall back, leak' +
    ' credentials or remove the reference',
  async (t) => {
    const directory = await scratch(t),
      fake = fakeCredentials(directory, { backend: 'gopass' });
    await fake.store.create(session());
    fake.failure = (store, args) =>
      args.includes('show')
        ? {
            code: 11,
            stdout: Buffer.from('FAKE_SENSITIVE_ERROR'),
            stderrBytes: 20,
          }
        : undefined;
    await assert.rejects(
      fake.store.load(),
      (error) =>
        isSecurityError(error) &&
        !error.message.includes('FAKE_SENSITIVE_ERROR'),
    );
    await assert.rejects(fake.store.remove());
    assert.equal(fake.records.size, 1);
    assert.deepEqual(await readdir(directory), ['session.json']);
    fake.failure = (store, args) =>
      args.includes('rm')
        ? { code: 1, stdout: Buffer.alloc(0), stderrBytes: 10 }
        : undefined;
    await assert.rejects(fake.store.remove(), /deletion was not confirmed/);
    assert.equal(fake.records.size, 1);
    const other = await scratch(t),
      failed = fakeCredentials(other);
    failed.failure = () => ({
      code: 1,
      stdout: Buffer.from('FAKE_PRIVATE_OUTPUT'),
      stderrBytes: 10,
    });
    await assert.rejects(failed.store.create(session()), /Could not save/);
    assert.deepEqual(await readdir(other), []);
    assert.equal(failed.records.size, 0);
  },
);
test(
  'A concurrent reference creation rolls back only the new' +
    ' external entry and preserves user data',
  async (t) => {
    const directory = await scratch(t),
      fake = fakeCredentials(directory);
    const store = credentialStore(directory, {
      run: async (backend, args, input) => {
        const result = await fake.run(backend, args, input);
        if (['store', 'credential-put'].includes(args[0]))
          await atomicPrivateWrite(
            directory,
            'session.json',
            'OTHER USER DATA',
          );
        return result;
      },
    });
    await assert.rejects(store.create(session()), /Refusing to replace/);
    assert.equal(fake.records.size, 0);
    assert.equal(
      await readFile(join(directory, 'session.json'), 'utf8'),
      'OTHER USER DATA',
    );
  },
);
test(
  'Malformed/oversized store responses are rejected and' +
    ' deletion must be verified',
  async (t) => {
    const directory = await scratch(t),
      fake = fakeCredentials(directory);
    await fake.store.create(session());
    const key = [...fake.records.keys()][0],
      original = Buffer.from(fake.records.get(key));
    for (const value of [
      Buffer.from('{invalid'),
      Buffer.alloc(20 * 1024, 65),
    ]) {
      fake.records.set(key, value);
      await assert.rejects(fake.store.load(), isSecurityError);
    }
    fake.records.set(key, original);
    fake.failure = (backend, args) =>
      ['clear', 'credential-remove'].includes(args[0])
        ? { code: 0, stdout: Buffer.alloc(0), stderrBytes: 0 }
        : undefined;
    await assert.rejects(fake.store.remove(), /deletion verification failed/);
    assert.equal(fake.records.size, 1);
    assert.deepEqual(await readdir(directory), ['session.json']);
  },
);

function fakeProcess(onInput) {
  const child = new EventEmitter();
  child.stdin = new PassThrough();
  child.stdout = new PassThrough();
  child.stderr = new PassThrough();
  child.kill = () => {
    child.killed = true;
  };
  const input = [];
  child.stdin.on('data', (chunk) => input.push(Buffer.from(chunk)));
  child.stdin.on('finish', () => onInput?.(Buffer.concat(input), child));
  return child;
}
test(
  'The subprocess boundary uses fixed helpers, pipes, no shell,' +
    ' and stdin-only payloads',
  async () => {
    const secret = Buffer.from('FAKE_PRIVATE_STDIN');
    let invoked;
    const result = await runCredentialCommand(
      'keyring',
      ['store', '--label=Test', 'profile', 'public-id'],
      secret,
      {
        platform: 'linux',
        spawnProcess(executable, args, options) {
          invoked = { executable, args, options };
          return fakeProcess((input, child) => {
            assert.deepEqual(input, secret);
            child.stderr.write('discarded diagnostic');
            child.emit('close', 0);
          });
        },
      },
    );
    assert.equal(invoked.executable, '/usr/bin/secret-tool');
    assert.equal(invoked.options.shell, false);
    assert.deepEqual(invoked.options.stdio, ['pipe', 'pipe', 'pipe']);
    assert.ok(!JSON.stringify(invoked).includes(secret.toString()));
    assert.equal(result.code, 0);
    assert.equal(result.stderrBytes, 20);
    assert.equal(result.stdout.length, 0);
    await assert.rejects(
      runCredentialCommand('plaintext', [], secret),
      isSecurityError,
    );
  },
);
test(
  'Helper timeout, excessive output and process errors are' +
    ' bounded and sanitized',
  async () => {
    for (const mode of [
      'timeout',
      'stdout',
      'stderr',
      'error',
      'stdin-error',
      'stdout-error',
      'stderr-error',
      'signal',
    ]) {
      let child;
      await assert.rejects(
        runCredentialCommand('gopass', ['show', 'public-id'], undefined, {
          platform: 'linux',
          timeoutMs: 10,
          spawnProcess() {
            child = fakeProcess((input, process) => {
              if (mode === 'stdout')
                process.stdout.write(Buffer.alloc(32769, 65));
              if (mode === 'stderr')
                process.stderr.write(Buffer.alloc(32769, 65));
              if (mode === 'error')
                process.emit('error', new Error('FAKE_PRIVATE_PROCESS_ERROR'));
              if (mode.endsWith('-error'))
                process[mode.slice(0, -6)].emit(
                  'error',
                  new Error('FAKE_PRIVATE_STREAM_ERROR'),
                );
              if (mode === 'signal') process.emit('close', null);
            });
            return child;
          },
        }),
        (error) =>
          isSecurityError(error) && !error.message.includes('FAKE_PRIVATE'),
      );
      assert.equal(child.killed, true);
    }
    await assert.rejects(
      runCredentialCommand('keyring', [], undefined, {
        spawnProcess() {
          throw new Error('FAKE_PRIVATE_SPAWN_ERROR');
        },
      }),
      (error) =>
        isSecurityError(error) && !error.message.includes('FAKE_PRIVATE'),
    );
  },
);

test('gopass paths must name an absolute executable, not a command', () => {
  for (const [platform, path] of [
    ['linux', '/custom directory/gopass'],
    ['darwin', '/opt/homebrew/bin/gopass'],
    ['win32', 'C:\\Program Files\\gopass\\gopass.exe'],
  ] as const)
    assert.equal(credentialExecutable('gopass', platform, path), path);
  for (const path of ['gopass', '.\\gopass.exe', 'C:gopass.exe', 'C:\\g.cmd'])
    assert.throws(
      () => credentialExecutable('gopass', 'win32', path),
      isSecurityError,
    );
  assert.throws(
    () => credentialExecutable('gopass', 'darwin', 'gopass'),
    isSecurityError,
  );
});

for (const platform of ['darwin', 'win32'] as const) {
  test(`${platform} keyring uses exact native entry and stdin`, async (t) => {
    const directory = await scratch(t),
      fake = fakeCredentials(directory, { platform });
    await fake.store.create(session());
    const loaded = await fake.store.load();
    await fake.store.remove({
      expectedFingerprint: loaded.credentialFingerprint,
    });
    const target = fake.calls[0].args[1];
    assert.match(target, /^telegram\/profiles\/[0-9a-f]{64}\/[0-9a-f]{32}$/);
    assert.deepEqual(
      fake.calls.map((call) => call.args[0]),
      [
        'credential-put',
        'credential-get',
        'credential-get',
        'credential-get',
        'credential-remove',
        'credential-get',
      ],
    );
    assert.ok(
      fake.calls.every(
        (call) => call.args.length === 2 && call.args[1] === target,
      ),
    );
    assert.ok(fake.calls[0].input.includes(session().apiHash));
    assert.ok(fake.calls.slice(1).every((call) => call.input === undefined));
    assert.equal(fake.records.size, 0);
    assert.deepEqual(await readdir(directory), []);
  });

  test(`${platform} keyring only accepts definite absence`, async (t) => {
    const fake = fakeCredentials(await scratch(t), { platform });
    await fake.store.create(session());
    fake.failure = (_backend, args) => {
      if (args[0] !== 'credential-get' || fake.records.size) return;
      return { code: HELPER_MISSING, stdout: Buffer.alloc(0), stderrBytes: 1 };
    };
    await assert.rejects(fake.store.remove(), /Could not read/);
  });

  test(`${platform} gopass uses the same scoped protocol`, async (t) => {
    const fake = fakeCredentials(await scratch(t), {
      backend: 'gopass',
      platform,
    });
    await fake.store.create(session());
    await fake.store.remove();
    assert.deepEqual(
      fake.calls.map((call) => call.args[3]),
      ['insert', 'show', 'show', 'rm', 'list'],
    );
  });
}
