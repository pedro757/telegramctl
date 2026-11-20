import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { HELPER_MISSING, runNative } from '../src/native.ts';
import { nativeFilename } from '../src/native-filename.ts';

test('Native helper uses the matching Windows architecture', () => {
  assert.equal(nativeFilename('win32', 'x64'), 'telegram-os-x64.exe');
  assert.equal(nativeFilename('win32', 'arm64'), 'telegram-os-arm64.exe');
  assert.equal(nativeFilename('darwin', 'arm64'), 'telegram-os');
  assert.throws(
    () => nativeFilename('win32', 'ia32'),
    /supports x64 and ARM64/,
  );
});

const platformSupported = ['darwin', 'win32'].includes(process.platform);
const enabled = platformSupported && process.env.TELEGRAM_TEST_KEYRING === '1';

test(
  'Native OS keyring round trip under the current desktop account',
  { skip: !enabled && 'Requires an unlocked macOS or Windows desktop account' },
  async () => {
    const target =
      `telegram/profiles/${randomBytes(32).toString('hex')}/` +
      randomBytes(16).toString('hex');
    const synthetic = Buffer.from('{"test":"synthetic fixture, not a login"}');
    const invoke = (op: string, input?: Buffer) =>
      runNative([`credential-${op}`, target], input);
    try {
      assert.equal((await invoke('get')).code, HELPER_MISSING);
      assert.equal((await invoke('put', synthetic)).code, 0);
      const result = await invoke('get');
      assert.equal(result.code, 0);
      assert.deepEqual(result.stdout, synthetic);
      assert.equal((await invoke('remove')).code, 0);
      assert.equal((await invoke('get')).code, HELPER_MISSING);
    } finally {
      const { code } = await invoke('remove');
      assert.ok(code === 0 || code === HELPER_MISSING, 'Test cleanup failed');
    }
  },
);
