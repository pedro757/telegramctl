import test from 'node:test';
import assert from 'node:assert/strict';
import {
  mkdir,
  readFile,
  writeFile,
  chmod,
  stat,
  symlink,
  link,
  readdir,
  truncate,
} from 'node:fs/promises';
import { join } from 'node:path';
import {
  encodeSession,
  decodeSession,
  validateSession,
  parseLegacy,
  importStringSession,
  loadLegacy,
  privateDirectory,
  privateRead,
  readPrivateFile,
  atomicPrivateWrite,
  removePrivate,
  privateTemporary,
  lockDirectory,
  initializePreferences,
  preferences,
  auditWriter,
} from '../src/files.ts';
import { isSecurityError } from '../src/common.ts';
import {
  directoryLink,
  publicWindowsRead,
  scratch,
  session,
  windows,
} from './support.ts';

function legacyString(address = '149.154.167.51', dc = 2) {
  const header = Buffer.alloc(3);
  header[0] = dc;
  header.writeInt16BE(Buffer.byteLength(address), 1);
  const port = Buffer.alloc(2);
  port.writeUInt16BE(443);
  return (
    '1' +
    Buffer.concat([
      header,
      Buffer.from(address),
      port,
      Buffer.alloc(256, 7),
    ]).toString('base64')
  );
}
test(
  'Session serialization validates credentials without' +
    ' inventing an encryption/vault format',
  () => {
    const original = session(),
      encoded = encodeSession(original),
      opened = decodeSession(encoded);
    assert.equal(opened.apiHash, original.apiHash);
    assert.deepEqual(opened.authKey, original.authKey);
    assert.equal(opened.salt, 123n);
    assert.throws(() => decodeSession(Buffer.from('{broken')), isSecurityError);
    assert.throws(
      () => validateSession({ ...original, dcId: 99 }),
      isSecurityError,
    );
    assert.throws(
      () => validateSession({ ...original, createdAt: 'not a time' }),
      isSecurityError,
    );
    assert.throws(
      () => validateSession({ ...original, authKey: Buffer.alloc(256) }),
      isSecurityError,
    );
    encoded.fill(0);
    opened.authKey.fill(0);
  },
);
test(
  'Storage rejects symlink paths, hard links, weak file modes' +
    ' and unsafe existing directories',
  async (t) => {
    const root = await scratch(t),
      directory = await privateDirectory(join(root, 'private'));
    const weak = join(root, 'weak');
    await privateDirectory(weak);
    if (windows) publicWindowsRead(weak, true);
    else await chmod(weak, 0o755);
    await assert.rejects(privateDirectory(weak), isSecurityError);
    await symlink(directory, join(root, 'alias'), directoryLink);
    await assert.rejects(
      privateDirectory(join(root, 'alias')),
      isSecurityError,
    );
    await atomicPrivateWrite(directory, 'data.json', 'original');
    const data = join(directory, 'data.json');
    if (windows) publicWindowsRead(data, true);
    else await chmod(data, 0o644);
    await assert.rejects(privateRead(directory, 'data.json'), isSecurityError);
    await assert.rejects(
      atomicPrivateWrite(directory, 'data.json', 'changed'),
      isSecurityError,
    );
    assert.equal(
      await readFile(join(directory, 'data.json'), 'utf8'),
      'original',
    );
    if (windows) publicWindowsRead(data, false);
    else await chmod(data, 0o600);
    await link(join(directory, 'data.json'), join(directory, 'hard.json'));
    await assert.rejects(privateRead(directory, 'hard.json'), isSecurityError);
    const outside = join(root, 'outside'),
      original = windows ? join(outside, 'original') : outside;
    if (windows) await privateDirectory(outside);
    await writeFile(original, 'untouched', { mode: 0o600 });
    await symlink(
      outside,
      join(directory, 'redirect.json'),
      windows ? 'junction' : 'file',
    );
    await assert.rejects(
      atomicPrivateWrite(directory, 'redirect.json', 'overwritten'),
    );
    assert.equal(await readFile(original, 'utf8'), 'untouched');
    await assert.rejects(
      atomicPrivateWrite(directory, '../escape.json', 'bad'),
      isSecurityError,
    );
  },
);
test(
  'Exclusive directory locks reject concurrent operations and' +
    ' clean up explicitly',
  async (t) => {
    const directory = await scratch(t),
      release = await lockDirectory(directory);
    await assert.rejects(lockDirectory(directory), /Another operation/);
    await release();
    assert.ok(!(await readdir(directory)).includes('session.lock'));
  },
);
test(
  'Legacy read validates and opens the same normalized path' +
    ' when symlinks precede dot-dot',
  async (t) => {
    const root = await scratch(t),
      checked = await privateDirectory(join(root, 'checked')),
      actual = await privateDirectory(join(root, 'actual'));
    await mkdir(join(actual, 'nested'), { mode: 0o700 });
    await symlink(
      join(actual, 'nested'),
      join(checked, 'alias'),
      directoryLink,
    );
    const config = (id) =>
      JSON.stringify({
        apiId: id,
        apiHash: session().apiHash,
        sessionString: legacyString(),
      });
    await writeFile(join(checked, 'legacy.json5'), config(12345), {
      mode: 0o600,
    });
    await writeFile(join(actual, 'legacy.json5'), config(54321), {
      mode: 0o600,
    });
    const filename = `${checked}/alias/../legacy.json5`;
    assert.equal((await readPrivateFile(filename)).toString(), config(12345));
    assert.equal((await loadLegacy(filename)).apiId, 12345);
    await assert.rejects(
      readPrivateFile(`${checked}/alias/legacy.json5`),
      isSecurityError,
    );
    if (windows) publicWindowsRead(actual, true);
    else await chmod(actual, 0o777);
    assert.equal((await readPrivateFile(filename)).toString(), config(12345));
  },
);
test(
  'Mutations, directory sync, locks and temporary commits use' +
    ' the same validated lexical directory',
  async (t) => {
    const root = await scratch(t),
      checked = await privateDirectory(join(root, 'checked')),
      actual = await privateDirectory(join(root, 'actual'));
    await mkdir(join(actual, 'nested'), { mode: 0o700 });
    await symlink(
      join(actual, 'nested'),
      join(checked, 'alias'),
      directoryLink,
    );
    const raw = `${checked}/alias/../state`,
      absolute = join(checked, 'state');
    await atomicPrivateWrite(raw, 'data.json', 'first', { replace: false });
    await atomicPrivateWrite(raw, 'data.json', 'replacement');
    assert.equal(
      (await privateRead(raw, 'data.json')).toString(),
      'replacement',
    );
    for (const replace of [false, true]) {
      const temporary = await privateTemporary(raw);
      try {
        await temporary.handle.writeFile(String(replace));
        await temporary.commit('archive.jsonl', { replace });
      } finally {
        await temporary.dispose();
      }
      assert.equal(
        await readFile(join(absolute, 'archive.jsonl'), 'utf8'),
        String(replace),
      );
    }
    const release = await lockDirectory(raw);
    await release();
    await removePrivate(raw, 'data.json');
    await removePrivate(raw, 'archive.jsonl');
    assert.deepEqual(await readdir(absolute), []);
    await assert.rejects(stat(join(actual, 'state')), { code: 'ENOENT' });
  },
);
test(
  'Legacy migration parses a safe flat JSON5 subset without' +
    ' evaluating expressions',
  () => {
    const parsed = parseLegacy(
      "{ // comment\n apiId: +123, apiHash: 'abc'," +
        ' sessionString: "https://host/*not-comment*/",' +
        " defaultFormat:'json', writeEnabled:'true', }",
    );
    assert.equal(parsed.apiId, 123);
    assert.equal(parsed.defaultFormat, 'json');
    assert.equal(parsed.sessionString, 'https://host/*not-comment*/');
    assert.equal(parseLegacy('{"apiId":123,"apiHash":"value"}').apiId, 123);
    for (const value of [
      '{apiId:1,apiId:2}',
      '{__proto__:null}',
      '{constructor:null}',
      '{x:{nested:true}}',
      '{x:[1]}',
      '{x:Infinity}',
      '{x:(globalThis.injected=true)}',
      '{x:"bad\\q"}',
      '{} trailing',
      '{ /* never ends',
    ])
      assert.throws(() => parseLegacy(value), isSecurityError, value);
    assert.equal(globalThis.injected, undefined);
  },
);
test(
  'Legacy string sessions are imported as keys/DC IDs, never as' +
    ' arbitrary endpoints',
  () => {
    const imported = importStringSession(legacyString('attacker.example'));
    assert.equal(imported.dcId, 2);
    assert.equal(imported.authKey.length, 256);
    assert.equal(imported.serverAddress, undefined);
    assert.equal(imported.port, undefined);
    assert.throws(
      () => importStringSession('2' + legacyString().slice(1)),
      isSecurityError,
    );
    assert.throws(
      () => importStringSession(legacyString().slice(0, -4)),
      isSecurityError,
    );
  },
);
test(
  'Explicit legacy import never imports a write flag or' +
    ' persists plaintext credentials into preferences',
  async (t) => {
    const root = await scratch(t),
      filename = join(root, 'old.json5');
    await writeFile(
      filename,
      "{apiId:12345,apiHash:'0123456789abcdef0123456789abcdef'," +
        `sessionString:'${legacyString()}',writeEnabled:'true',` +
        "defaultFormat:'json',}",
      { mode: 0o600 },
    );
    const imported = await loadLegacy(filename);
    assert.equal(imported.writeEnabled, undefined);
    assert.equal(imported.legacyDefaultFormat, 'json');
    const directory = join(root, 'new');
    await initializePreferences(directory, imported.legacyDefaultFormat);
    assert.deepEqual(await preferences(directory), {
      version: 1,
      defaultFormat: 'json',
    });
    const text = await readFile(join(directory, 'config.json'), 'utf8');
    assert.ok(!text.includes('apiHash'));
    assert.ok(!text.includes('sessionString'));
    assert.ok(!text.includes('writeEnabled'));
    await writeFile(
      join(directory, 'config.json'),
      '{"version":1,"defaultFormat":"json","writeEnabled":true}',
    );
    await assert.rejects(preferences(directory), /Preferences accept only/);
    assert.ok((await readFile(filename, 'utf8')).includes('sessionString'));
  },
);
test(
  'Audit stores only private bounded metadata, never message' +
    ' text or names',
  async (t) => {
    const directory = await scratch(t),
      audit = auditWriter(directory);
    await audit({
      command: 'send',
      peers: ['user:1'],
      digest: 'a'.repeat(64),
      status: 'requested',
      message: 'FAKE_PRIVATE_BODY',
      phone: 'FAKE_PHONE',
      name: 'FAKE_NAME',
    });
    const file = join(directory, 'audit.jsonl'),
      text = await readFile(file, 'utf8');
    assert.ok(!text.includes('FAKE_'));
    if (!windows) assert.equal((await stat(file)).mode & 0o777, 0o600);
    assert.equal(JSON.parse(text).status, 'requested');
    await assert.rejects(
      audit({
        command: 'send',
        peers: ['../../bad'],
        digest: 'a'.repeat(64),
        status: 'approved',
      }),
      isSecurityError,
    );
    await truncate(file, 10 * 1024 * 1024);
    await assert.rejects(
      audit({
        command: 'send',
        peers: ['user:1'],
        digest: 'a'.repeat(64),
        status: 'approved',
      }),
      /size budget exhausted/,
    );
    assert.equal((await stat(file)).size, 10 * 1024 * 1024);
  },
);
