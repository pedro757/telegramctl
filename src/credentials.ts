import { existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { posix, win32 } from 'node:path';
import { randomBytes, sha256, equal } from './crypto.ts';
import {
  encodeSession,
  decodeSession,
  privateDirectory,
  privateRead,
  existsPrivate,
  atomicPrivateWrite,
  removePrivate,
  lockDirectory,
  type Session,
} from './files.ts';
import { securityError } from './common.ts';
import {
  assertExecutable,
  assertNative,
  HELPER_MISSING,
  nativeExecutable,
  runHelper,
  type HelperResult,
} from './native.ts';

const MAX_SECRET = 16 * 1024;

export type CredentialBackend = 'keyring' | 'gopass';
const isBackend = (store: unknown): store is CredentialBackend =>
  store === 'keyring' || store === 'gopass';
type Reference = {
  version: number;
  store: CredentialBackend;
  profile: string;
  id: string;
};
type Operation = 'get' | 'put' | 'exists' | 'remove';
type RunHelper = (
  backend: CredentialBackend,
  args: string[],
  input?: Buffer,
) => Promise<HelperResult>;
const drivePath = /^[a-z]:[\\/]/i;
export function defaultStateDirectory(
  platform = process.platform,
  home = homedir(),
  localAppData = process.env.LOCALAPPDATA,
) {
  if (platform === 'win32')
    return win32.join(
      localAppData && drivePath.test(localAppData)
        ? localAppData
        : win32.join(home, 'AppData', 'Local'),
      'TelegramCLI',
    );
  if (platform === 'darwin')
    return posix.join(home, 'Library', 'Application Support', 'TelegramCLI');
  return posix.join(home, '.local', 'state', 'telegram');
}

export function credentialExecutable(
  backend: CredentialBackend,
  platform = process.platform,
  gopassPath = process.env.TELEGRAMCTL_GOPASS_PATH ??
    process.env.TELEGRAM_GOPASS_PATH,
) {
  if (!['linux', 'darwin', 'win32'].includes(platform))
    throw securityError('Credential storage supports Linux, macOS and Windows');
  if (backend === 'keyring')
    return platform === 'linux'
      ? '/usr/bin/secret-tool'
      : nativeExecutable(platform);
  if (!isBackend(backend))
    throw securityError('Choose credential storage keyring or gopass');
  if (gopassPath !== undefined) {
    if (
      gopassPath.includes('\0') ||
      (platform === 'win32'
        ? !drivePath.test(gopassPath) || !/\.exe$/i.test(gopassPath)
        : !posix.isAbsolute(gopassPath))
    )
      throw securityError(
        'Set TELEGRAMCTL_GOPASS_PATH to a trusted absolute gopass executable' +
          ' (gopass.exe on Windows)',
      );
    return gopassPath;
  }
  if (platform === 'win32')
    throw securityError(
      'Set TELEGRAMCTL_GOPASS_PATH to the absolute path of a trusted' +
        ' gopass.exe (gopass >=1.17). No file fallback is available.',
    );
  if (platform === 'linux') return '/usr/bin/gopass';
  const paths = [
    '/opt/homebrew/bin/gopass',
    '/usr/local/bin/gopass',
    '/opt/local/bin/gopass',
  ];
  return paths.find((path) => existsSync(path)) ?? paths[0];
}

export async function runCredentialCommand(
  backend: CredentialBackend,
  args: string[],
  input?: Buffer,
  {
    spawnProcess,
    timeoutMs,
    platform = process.platform,
  }: {
    spawnProcess?: Parameters<typeof runHelper>[3]['spawnProcess'];
    timeoutMs?: number;
    platform?: NodeJS.Platform;
  } = {},
): Promise<HelperResult> {
  return runAt(credentialExecutable(backend, platform), backend, args, input, {
    spawnProcess,
    timeoutMs,
  });
}

function runAt(
  executable: string,
  backend: CredentialBackend,
  args: string[],
  input: Buffer | undefined,
  options: Omit<Parameters<typeof runHelper>[3], 'failure'> = {},
) {
  return runHelper(executable, args, input, {
    ...options,
    failure: () =>
      securityError(
        `The ${backend} credential helper failed or timed out;` +
          ' unlock/configure it and try again. No file fallback was used.',
      ),
  });
}

function command(
  ref: Reference,
  operation: Operation,
  platform: NodeJS.Platform,
) {
  const name = `telegram/profiles/${ref.profile}/${ref.id}`;
  if (ref.store === 'keyring') {
    if (platform !== 'linux') return [`credential-${operation}`, name];
    const attrs = [
      'application',
      'telegram',
      'profile',
      ref.profile,
      'credential',
      ref.id,
    ];
    return operation === 'put'
      ? ['store', '--label=Telegram CLI session', ...attrs]
      : [operation === 'get' ? 'lookup' : 'clear', ...attrs];
  }
  const options = ['--nosync', '--noparsing', '--nofuzzysearch'];
  if (operation === 'put')
    return [...options, 'insert', '--force', '--multiline', name];
  if (operation === 'get')
    return [...options, 'show', '--password', '--alsoclip=false', name];
  if (operation === 'exists')
    return [...options, 'list', '--flat', '--limit', '1', name];
  return [...options, 'rm', '--force', name];
}
function missing(
  ref: Reference,
  result: HelperResult,
  platform: NodeJS.Platform,
) {
  return (
    ref.store === 'keyring' &&
    result.code === (platform === 'linux' ? 1 : HELPER_MISSING) &&
    !result.stdout.length &&
    !result.stderrBytes
  );
}

export function credentialStore(
  directory: string,
  {
    backend = 'keyring',
    run = runCredentialCommand,
    platform = process.platform,
  }: {
    backend?: CredentialBackend;
    run?: RunHelper;
    platform?: NodeJS.Platform;
  } = {},
) {
  if (!isBackend(backend))
    throw securityError('Choose credential storage keyring or gopass');
  const location = async () => {
    const absolute = await privateDirectory(directory);
    return { absolute, profile: sha256(Buffer.from(absolute)).toString('hex') };
  };
  const reference = async (): Promise<Reference> => {
    const { absolute, profile } = await location();
    let ref: Reference;
    try {
      ref = JSON.parse(
        (await privateRead(absolute, 'session.json', 4096)).toString('utf8'),
      );
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT')
        throw securityError(
          'No keyring/gopass session is configured. Run telegramctl auth' +
            ' login; old session.enc.json files are not loaded or changed.',
        );
      throw securityError('Invalid or insecure credential reference');
    }
    if (
      !ref ||
      ref.version !== 1 ||
      !isBackend(ref.store) ||
      ref.profile !== profile ||
      typeof ref.id !== 'string' ||
      !/^[a-f0-9]{32}$/.test(ref.id) ||
      Object.keys(ref).some(
        (key) => !['version', 'store', 'profile', 'id'].includes(key),
      )
    )
      throw securityError('Invalid credential reference or profile identity');
    return ref;
  };
  const helperFor = async (store: CredentialBackend) => {
    const executable = credentialExecutable(store, platform);
    if (store === 'keyring' && platform !== 'linux')
      await assertNative(platform);
    else {
      const helper =
        store === 'keyring'
          ? 'secret-tool (libsecret) and an OS Secret Service keyring'
          : 'gopass >=1.17 (set TELEGRAMCTL_GOPASS_PATH if needed)';
      await assertExecutable(
        executable,
        `Install/configure ${helper} first. No file fallback is available.`,
      );
    }
    return executable;
  };
  const call = async (ref: Reference, operation: Operation, input?: Buffer) => {
    const args = command(ref, operation, platform);
    if (run !== runCredentialCommand) return run(ref.store, args, input);
    const executable = await helperFor(ref.store);
    return runAt(executable, ref.store, args, input);
  };
  const get = async (ref: Reference, { allowMissing = false } = {}) => {
    const result = await call(ref, 'get');
    if (allowMissing && missing(ref, result, platform)) {
      result.stdout.fill(0);
      return undefined;
    }
    if (
      result.code !== 0 ||
      !result.stdout.length ||
      result.stdout.length > MAX_SECRET
    ) {
      result.stdout.fill(0);
      throw securityError(
        `Could not read the ${ref.store} session; unlock/configure the` +
          ' credential manager. No fallback was used.',
      );
    }
    // Normalize one optional final line terminator around compact JSON.
    const length =
      result.stdout.at(-1) === 10
        ? result.stdout.length - (result.stdout.at(-2) === 13 ? 2 : 1)
        : result.stdout.length;
    const bytes = Buffer.from(result.stdout.subarray(0, length));
    result.stdout.fill(0);
    return bytes;
  };
  const digest = (ref: Reference, bytes: Buffer) =>
    sha256(Buffer.from(JSON.stringify(ref)), bytes).toString('hex');
  const clear = async (ref: Reference) => {
    const result = await call(ref, 'remove');
    result.stdout.fill(0);
    if (result.code !== 0)
      throw securityError(
        `The ${ref.store} credential deletion was not confirmed`,
      );
    if (ref.store === 'gopass') {
      // gopass show wraps missing-entry errors as decryption errors. Only the
      // entry-scoped list command reliably returns documented NotFound (10).
      const check = await call(ref, 'exists'),
        absent = check.code === 10 && !check.stdout.length;
      check.stdout.fill(0);
      if (!absent)
        throw securityError('Credential deletion verification failed');
      return;
    }
    const remaining = await get(ref, { allowMissing: true });
    if (remaining) {
      remaining.fill(0);
      throw securityError('Credential deletion verification failed');
    }
  };
  async function assertNew() {
    const { absolute } = await location();
    if (await existsPrivate(absolute, 'session.json'))
      throw securityError(
        'A session is already configured. Use auth check or auth logout,' +
          ' or explicitly forget-local first.',
      );
    if (run === runCredentialCommand) await helperFor(backend);
  }
  return {
    backend,
    assertNew,
    async create(session: Session) {
      const { absolute, profile } = await location(),
        release = await lockDirectory(absolute);
      let bytes: Buffer | undefined,
        ref: Reference | undefined,
        written = false;
      try {
        await assertNew();
        ref = {
          version: 1,
          store: backend,
          profile,
          id: randomBytes(16).toString('hex'),
        };
        bytes = encodeSession(session);
        const input = Buffer.concat([bytes, Buffer.from('\n')]);
        let result;
        try {
          result = await call(ref, 'put', input);
        } finally {
          input.fill(0);
        }
        result.stdout.fill(0);
        if (result.code !== 0)
          throw securityError(
            `Could not save the ${backend} session;` +
              ' no local credential file was created',
          );
        written = true;
        const check = (await get(ref))!;
        try {
          if (!equal(check, bytes))
            throw securityError('Credential read-back verification failed');
        } finally {
          check.fill(0);
        }
        await atomicPrivateWrite(
          absolute,
          'session.json',
          JSON.stringify(ref) + '\n',
          { replace: false },
        );
      } catch (error) {
        if (written && ref && bytes) {
          // Each create uses a new random entry; never erase somebody else's
          // changed record while attempting rollback after a local failure.
          try {
            const current = (await get(ref))!;
            try {
              if (equal(current, bytes)) await clear(ref);
            } finally {
              current.fill(0);
            }
          } catch {
            /* The caller revokes the newly authorized Telegram key. */
          }
        }
        throw error;
      } finally {
        bytes?.fill(0);
        await release();
      }
    },
    async load() {
      const ref = await reference(),
        bytes = (await get(ref))!;
      try {
        return {
          ...decodeSession(bytes),
          credentialStore: ref.store,
          credentialFingerprint: digest(ref, bytes),
        };
      } finally {
        bytes.fill(0);
      }
    },
    async fingerprint() {
      const ref = await reference(),
        bytes = (await get(ref))!;
      try {
        return digest(ref, bytes);
      } finally {
        bytes.fill(0);
      }
    },
    async remove({
      expectedFingerprint,
    }: { expectedFingerprint?: string } = {}) {
      const { absolute } = await location(),
        release = await lockDirectory(absolute);
      try {
        const ref = await reference(),
          bytes = (await get(ref))!;
        try {
          if (expectedFingerprint && digest(ref, bytes) !== expectedFingerprint)
            throw securityError(
              'The stored session changed during the operation; refusing' +
                ' to delete a different credential',
            );
        } finally {
          bytes.fill(0);
        }
        await clear(ref);
        await removePrivate(absolute, 'session.json');
      } finally {
        await release();
      }
    },
  };
}
