import { mkdtemp, rm, access, realpath } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import type { TestContext } from 'node:test';
import { encode } from '../src/tl.ts';
import { credentialStore, type CredentialBackend } from '../src/credentials.ts';
import { HELPER_MISSING } from '../src/native.ts';
import { privateDirectory, type Session } from '../src/files.ts';
import type { RpcOptions } from '../src/rpc.ts';

export const windows = process.platform === 'win32';
export const directoryLink = windows ? 'junction' : 'dir';
export function publicWindowsRead(path: string, grant: boolean) {
  const result = spawnSync(
    'icacls.exe',
    [path, ...(grant ? ['/grant', '*S-1-1-0:(R)'] : ['/remove:g', '*S-1-1-0'])],
    { encoding: 'utf8' },
  );
  if (result.error || result.status !== 0)
    throw new Error(`Fixture ACL change failed: ${result.stderr}`, {
      cause: result.error,
    });
}
export async function scratch(t: TestContext) {
  let parent = join(tmpdir(), 'opencode');
  try {
    await access(parent);
  } catch {
    parent = tmpdir();
  }
  // macOS commonly reports a temp path through the /var symlink.
  const prefix = join(await realpath(parent), 'telegram-cli-test-');
  const directory = windows
    ? await privateDirectory(prefix + randomBytes(12).toString('hex'))
    : await mkdtemp(prefix);
  t.after(() => rm(directory, { recursive: true, force: true }));
  return directory;
}
type FixtureId = number | bigint;
export const user = (id: FixtureId, extra = {}) => ({
  _: 'User',
  id: BigInt(id),
  accessHash: BigInt(id) + 100n,
  firstName: `User ${id}`,
  ...extra,
});
export const channel = (id: FixtureId, extra = {}) => ({
  _: 'Channel',
  id: BigInt(id),
  accessHash: BigInt(id) + 100n,
  title: `Group ${id}`,
  megagroup: true,
  ...extra,
});
export const chat = (id: FixtureId, extra = {}) => ({
  _: 'Chat',
  id: BigInt(id),
  title: `Chat ${id}`,
  ...extra,
});
// Tests share this recorder across many different TL methods and fixtures.
type FixtureArgs = Record<string, any>;
type RpcCall = { name: string; args: FixtureArgs; options?: RpcOptions };
type FakeRpcHandler = (
  name: string,
  args: FixtureArgs,
  options: RpcOptions | undefined,
  calls: RpcCall[],
) => unknown;
export function fakeRpc(handler: FakeRpcHandler) {
  const calls: RpcCall[] = [];
  return {
    calls,
    async invoke(name: string, args: FixtureArgs = {}, options?: RpcOptions) {
      encode({ ...args, _: name });
      calls.push({ name, args, options });
      if (
        name === 'users.GetUsers' &&
        args.id?.length === 1 &&
        args.id[0]._ === 'InputUserSelf'
      )
        return [user(1, { self: true })];
      return handler(name, args, options, calls);
    },
  };
}
export const session = (): Session => ({
  version: 1,
  apiId: 12345,
  apiHash: '0123456789abcdef0123456789abcdef',
  dcId: 2,
  authKey: Buffer.alloc(256, 7),
  salt: 123n,
  timeOffset: 0,
  createdAt: '2026-11-05T12:00:00Z',
});
export function fakeCredentials(
  directory: string,
  {
    backend = 'keyring',
    platform = process.platform,
  }: { backend?: CredentialBackend; platform?: NodeJS.Platform } = {},
) {
  const fake = { records: new Map(), calls: [], failure: undefined };
  fake.run = async (store, args, input) => {
    fake.calls.push({
      store,
      args,
      input: input ? Buffer.from(input) : undefined,
    });
    const injected = fake.failure?.(store, args, input);
    if (injected) return injected;
    const native = store === 'keyring' && platform !== 'linux';
    const operation = store === 'keyring' ? args[0] : args[3];
    const key =
      store +
      ':' +
      (store === 'keyring' && !native ? args.slice(-6).join(':') : args.at(-1));
    if (['store', 'insert', 'credential-put'].includes(operation)) {
      fake.records.set(key, Buffer.from(input.subarray(0, input.length - 1)));
      return { code: 0, stdout: Buffer.alloc(0), stderrBytes: 0 };
    }
    if (['clear', 'rm', 'credential-remove'].includes(operation)) {
      fake.records.get(key)?.fill(0);
      fake.records.delete(key);
      return { code: 0, stdout: Buffer.alloc(0), stderrBytes: 0 };
    }
    if (operation === 'list')
      return {
        code: fake.records.has(key) ? 0 : 10,
        stdout: fake.records.has(key)
          ? Buffer.from(args.at(-1) + '\n')
          : Buffer.alloc(0),
        stderrBytes: fake.records.has(key) ? 0 : 20,
      };
    if (!fake.records.has(key))
      return {
        code: store === 'keyring' ? (native ? HELPER_MISSING : 1) : 11,
        stdout: Buffer.alloc(0),
        stderrBytes: store === 'keyring' ? 0 : 20,
      };
    return {
      code: 0,
      stdout: Buffer.concat([fake.records.get(key), Buffer.from('\n')]),
      stderrBytes: 0,
    };
  };
  fake.store = credentialStore(directory, { backend, platform, run: fake.run });
  return fake;
}
