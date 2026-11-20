import { createHash, randomBytes } from 'node:crypto';
import { constants, type Stats } from 'node:fs';
import {
  open,
  type FileHandle,
  lstat,
  mkdir,
  rename,
  unlink,
  realpath,
  link,
} from 'node:fs/promises';
import { basename, dirname, join, parse, resolve } from 'node:path';
import {
  isAmbiguousMutationError,
  isSecurityError,
  protocolError,
  securityError,
  timestamp,
} from './common.ts';
import { randomLong } from './crypto.ts';
import type { RpcClient } from './rpc.ts';
import { DC_ADDRESSES } from './wire.ts';
import { HELPER_EXISTS, HELPER_MISSING, runNative } from './native.ts';

// Private paths, locks, preferences, and audit logs.
const windows = process.platform === 'win32';
const noFollow = constants.O_NOFOLLOW ?? 0;
const uid = () => {
  if (typeof process.getuid !== 'function' || !constants.O_NOFOLLOW)
    throw securityError(
      'Secure file storage currently requires a POSIX system',
    );
  return process.getuid();
};
async function windowsPath(operation: string, absolute: string) {
  // oxlint-disable-next-line no-control-regex -- Reject Win32 control bytes.
  const invalid = /[:*?"<>|\u0000-\u001f]|[. ]$/;
  const device = /^(?:con|prn|aux|nul|conin\$|conout\$|clock\$)(?:[ .]|$)/i;
  const port = /^(?:com|lpt)[0-9¹²³](?:[ .]|$)/i;
  if (
    !/^[a-z]:\\/i.test(absolute) ||
    absolute
      .slice(3)
      .split('\\')
      .some(
        (part) => invalid.test(part) || device.test(part) || port.test(part),
      )
  )
    throw securityError('Use a local Windows path without device names');
  const result = await runNative([`path-${operation}`, absolute]);
  result.stdout.fill(0);
  if (result.code === HELPER_MISSING || result.code === HELPER_EXISTS)
    throw Object.assign(new Error('Local path does not exist or is in use'), {
      code: result.code === HELPER_MISSING ? 'ENOENT' : 'EEXIST',
    });
  if (result.code !== 0)
    throw securityError(
      'Unsafe Windows path: use a local ACL-capable drive, no reparse' +
        ' points, and private files/directories owned by your account',
    );
}
export async function noSymlinkPath(directory: string) {
  const absolute = resolve(directory);
  if (windows) {
    await windowsPath('parents', absolute);
    return absolute;
  }
  const root = parse(absolute).root;
  let current = root;
  for (const part of absolute.slice(root.length).split('/').filter(Boolean)) {
    current = join(current, part);
    let stat;
    try {
      stat = await lstat(current);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') break;
      throw error;
    }
    if (stat.isSymbolicLink() || !stat.isDirectory())
      throw securityError('Storage path contains a symlink or non-directory');
    if (stat.mode & 0o022 && !(stat.mode & 0o1000))
      throw securityError(
        'Storage parent is writable by another group or other users',
      );
  }
  return absolute;
}
export async function privateDirectory(
  directory: string,
  { create = true } = {},
) {
  if (windows) {
    const absolute = resolve(directory);
    await windowsPath(create ? 'mkdir' : 'directory', absolute);
    const canonical = await realpath(absolute);
    if (canonical.toLowerCase() !== absolute.toLowerCase())
      throw securityError('Storage path must use its canonical Windows name');
    return canonical;
  }
  const absolute = await noSymlinkPath(directory);
  if (create) await mkdir(absolute, { recursive: true, mode: 0o700 });
  const stat = await lstat(absolute);
  if (
    !stat.isDirectory() ||
    stat.isSymbolicLink() ||
    stat.uid !== uid() ||
    stat.mode & 0o077
  )
    throw securityError(
      'Storage directory must be owned by you with mode 0700 (or stricter)',
    );
  if ((await realpath(absolute)) !== absolute)
    throw securityError('Storage directory changed while checking it');
  return absolute;
}
export async function downloadDirectory(directory: string) {
  const absolute = resolve(directory);
  try {
    if (windows) {
      await windowsPath('download-dir', absolute);
    } else {
      await noSymlinkPath(absolute);
      const stat = await lstat(absolute);
      if (!stat.isDirectory() || stat.uid !== uid() || stat.mode & 0o022)
        throw securityError(
          'Download directory must be owned by you and not writable by others',
        );
    }
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT')
      return privateDirectory(absolute);
    throw error;
  }
  const canonical = await realpath(absolute);
  if (
    windows
      ? canonical.toLowerCase() !== absolute.toLowerCase()
      : canonical !== absolute
  )
    throw securityError('Download directory changed while checking it');
  return canonical;
}
function assertPrivateFile(stat: Stats, maxBytes = 1024 * 1024) {
  if (
    !stat.isFile() ||
    stat.nlink !== 1 ||
    (!windows && (stat.uid !== uid() || !!(stat.mode & 0o077))) ||
    stat.size > maxBytes
  )
    throw securityError(
      'Expected an owner-only regular file without hard links and' +
        ' within the size limit',
    );
}
export function safeFilename(name: string) {
  if (!/^[a-z0-9][a-z0-9.-]{0,127}$/.test(name) || name.includes('..'))
    throw securityError('Unsafe storage filename');
  return name;
}
export async function readPrivateFile(
  filename: string,
  maxBytes = 1024 * 1024,
) {
  const handle = await openPrivateFile(filename, maxBytes);
  try {
    return await handle.readFile();
  } finally {
    await handle.close();
  }
}
export async function openPrivateFile(
  filename: string,
  maxBytes: number,
  flags = constants.O_RDONLY,
) {
  const absolute = resolve(filename);
  if (windows) await windowsPath('file', absolute);
  else await noSymlinkPath(dirname(absolute));
  const entry = windows ? await lstat(absolute, { bigint: true }) : undefined;
  const handle = await open(absolute, flags | noFollow);
  try {
    assertPrivateFile(await handle.stat(), maxBytes);
    if (entry) {
      const opened = await handle.stat({ bigint: true });
      if (
        !entry.isFile() ||
        entry.dev !== opened.dev ||
        entry.ino !== opened.ino
      )
        throw securityError('Private file changed while opening');
    }
    return handle;
  } catch (error) {
    await handle.close();
    throw error;
  }
}
export async function privateRead(
  directory: string,
  name: string,
  maxBytes?: number,
) {
  directory = await privateDirectory(directory, { create: false });
  return readPrivateFile(join(directory, safeFilename(name)), maxBytes);
}
export async function existsPrivate(directory: string, name: string) {
  try {
    const handle = await openPrivateFile(
      join(directory, safeFilename(name)),
      Infinity,
    );
    await handle.close();
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return false;
    throw error;
  }
}
async function syncDirectory(directory: string) {
  // Node cannot fsync a directory handle on Windows. Files are still synced
  // before publication; do not claim directory-entry crash durability there.
  if (windows) return;
  const handle = await open(
    directory,
    constants.O_RDONLY | constants.O_DIRECTORY | noFollow,
  );
  try {
    await handle.sync();
  } catch (error) {
    if (
      process.platform !== 'darwin' ||
      !['EINVAL', 'ENOTSUP'].includes((error as NodeJS.ErrnoException).code!)
    )
      throw error;
  } finally {
    await handle.close();
  }
}
async function openNewPrivate(
  filename: string,
  flags: number,
  download = false,
) {
  if (windows) {
    await windowsPath(download ? 'create-download' : 'create-file', filename);
    try {
      return await openPrivateFile(filename, Infinity, flags);
    } catch (error) {
      await unlink(filename);
      throw error;
    }
  }
  return open(
    filename,
    flags | constants.O_CREAT | constants.O_EXCL | noFollow,
    0o600,
  );
}
export async function atomicPrivateWrite(
  directory: string,
  name: string,
  data: string | Buffer,
  { replace = true } = {},
) {
  directory = await privateDirectory(directory);
  safeFilename(name);
  const target = join(directory, name);
  if (await existsPrivate(directory, name)) {
    if (!replace)
      throw securityError('Refusing to replace an existing private file');
  }
  const temporary = join(
    directory,
    `tmp-${randomBytes(16).toString('hex')}.tmp`,
  );
  const handle = await openNewPrivate(temporary, constants.O_WRONLY);
  let closed = false;
  try {
    await handle.writeFile(data);
    await handle.sync();
    await handle.close();
    closed = true;
    if (replace) await rename(temporary, target);
    else {
      await link(temporary, target);
      await unlink(temporary);
    }
    await syncDirectory(directory);
  } finally {
    if (!closed) await handle.close();
    await unlink(temporary).catch((error) => {
      if (error.code !== 'ENOENT') throw error;
    });
  }
}
export async function removePrivate(directory: string, name: string) {
  directory = await privateDirectory(directory, { create: false });
  if (!(await existsPrivate(directory, name))) return;
  await unlink(join(directory, safeFilename(name)));
  await syncDirectory(directory);
  if (await existsPrivate(directory, name))
    throw securityError('Private file deletion did not complete');
}
export async function lockDirectory(directory: string, name = 'session.lock') {
  directory = await privateDirectory(directory);
  const filename = join(directory, safeFilename(name));
  let handle;
  try {
    handle = await openNewPrivate(filename, constants.O_WRONLY);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'EEXIST')
      throw securityError(
        'Another operation holds the lock. If a process crashed,' +
          ' verify it has stopped before removing its lock file' +
          ' manually.',
      );
    throw error;
  }
  await handle.writeFile(`${process.pid}\n`);
  await handle.sync();
  const original = await handle.stat();
  return async () => {
    await handle.close();
    const current = await lstat(filename);
    if (
      current.ino !== original.ino ||
      current.dev !== original.dev ||
      current.isSymbolicLink()
    )
      throw securityError('Lock file identity changed');
    await unlink(filename);
  };
}
export async function privateTemporary(directory: string) {
  return temporary(await privateDirectory(directory));
}

export async function downloadTemporary(directory: string) {
  const output = await temporary(await downloadDirectory(directory), true);
  return {
    directory: output.directory,
    handle: output.handle,
    commit: (filename: string) => output.commit(filename, { replace: false }),
    dispose: () => output.dispose(),
  };
}

async function temporary(directory: string, download = false) {
  const name = `tmp-${randomBytes(16).toString('hex')}.tmp`;
  const filename = join(directory, name);
  const handle = await openNewPrivate(filename, constants.O_RDWR, download);
  let closed = false,
    committed = false;
  return {
    directory,
    handle,
    async commit(target: string, { replace = true } = {}) {
      safeFilename(target);
      const destination = join(directory, target);
      if (replace) await existsPrivate(directory, target);
      else {
        // Windows may return access denied rather than EEXIST for a junction.
        // lstat never follows it; the hard link still enforces no replacement.
        const existing = await lstat(destination).catch((error) => {
          if (error.code !== 'ENOENT') throw error;
        });
        if (existing)
          throw securityError('Refusing to replace an existing file');
      }
      await handle.sync();
      await handle.close();
      closed = true;
      if (replace) await rename(filename, destination);
      else {
        try {
          await link(filename, destination);
        } catch (error) {
          if ((error as NodeJS.ErrnoException).code === 'EEXIST')
            throw securityError('Refusing to replace an existing file');
          throw error;
        }
        await unlink(filename);
      }
      committed = true;
      await syncDirectory(directory);
    },
    async dispose() {
      if (!closed) {
        await handle.close();
        closed = true;
      }
      if (!committed)
        await unlink(filename).catch((error) => {
          if (error.code !== 'ENOENT') throw error;
        });
    },
  };
}

export async function preferences(directory: string) {
  let value;
  try {
    value = JSON.parse(
      (await privateRead(directory, 'config.json', 4096)).toString('utf8'),
    );
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT')
      return { version: 1, defaultFormat: 'plain' };
    throw securityError('Invalid or insecure preferences file');
  }
  if (
    !value ||
    value.version !== 1 ||
    !['plain', 'json', 'markdown'].includes(value.defaultFormat) ||
    Object.keys(value).some(
      (key) => !['version', 'defaultFormat'].includes(key),
    )
  )
    throw securityError(
      'Preferences accept only version and defaultFormat;' +
        ' credentials/permissions do not belong in config.json',
    );
  return { version: 1, defaultFormat: value.defaultFormat };
}
export async function initializePreferences(
  directory: string,
  defaultFormat: unknown = 'plain',
) {
  await privateDirectory(directory);
  if (await existsPrivate(directory, 'config.json'))
    return preferences(directory);
  const value = {
    version: 1,
    defaultFormat: (['plain', 'json', 'markdown'] as unknown[]).includes(
      defaultFormat,
    )
      ? defaultFormat
      : 'plain',
  };
  await atomicPrivateWrite(
    directory,
    'config.json',
    JSON.stringify(value, null, 2) + '\n',
    { replace: false },
  );
  return value;
}

export type AuditStatus =
  | 'requested'
  | 'approved'
  | 'succeeded'
  | 'failed'
  | 'unknown';
export type AuditRecord = {
  command: string;
  account?: string;
  peers: string[];
  digest: string;
  status: AuditStatus;
  error?: string;
};

export function auditWriter(directory: string) {
  return async (entry: AuditRecord) => {
    if (
      !/^[a-z-]+$/.test(entry.command) ||
      !Array.isArray(entry.peers) ||
      entry.peers.some((id) => !/^(user|chat|channel):[1-9][0-9]*$/.test(id)) ||
      !/^[a-f0-9]{64}$/.test(entry.digest) ||
      !['requested', 'approved', 'succeeded', 'failed', 'unknown'].includes(
        entry.status,
      )
    )
      throw securityError('Invalid audit metadata');
    const absolute = await privateDirectory(directory);
    const release = await lockDirectory(directory, 'audit.lock');
    try {
      const filename = join(absolute, 'audit.jsonl'),
        flags = constants.O_WRONLY | constants.O_APPEND,
        limit = 10 * 1024 * 1024;
      let handle: FileHandle;
      try {
        handle = await openNewPrivate(filename, flags);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error;
        handle = await openPrivateFile(filename, limit, flags);
      }
      try {
        const stat = await handle.stat();
        assertPrivateFile(stat, limit);
        // Deliberately exclude message bodies, display names, phone numbers,
        // credentials, API request arguments, and free-form error strings.
        if (
          entry.account !== undefined &&
          !/^user:[1-9][0-9]*$/.test(entry.account)
        )
          throw securityError('Invalid audit account');
        const record = {
          timestamp: timestamp(),
          command: entry.command,
          ...(entry.account ? { account: entry.account } : {}),
          peers: entry.peers,
          digest: entry.digest,
          status: entry.status,
          ...(entry.error && /^[A-Za-z]{1,50}$/.test(entry.error)
            ? { error: entry.error }
            : {}),
        };
        const line = JSON.stringify(record) + '\n';
        if (stat.size + Buffer.byteLength(line) > limit)
          throw securityError(
            'Audit size budget exhausted; privately archive the log' +
              ' before new mutations',
          );
        await handle.writeFile(line);
        await handle.sync();
      } finally {
        await handle.close();
      }
    } finally {
      await release();
    }
  };
}

// Session encoding and explicitly requested legacy imports.
export function base64(
  value: unknown,
  expectedLength: number,
  maxLength = expectedLength,
) {
  if (
    typeof value !== 'string' ||
    value.length > Math.ceil(maxLength / 3) * 4 ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(
      value,
    )
  )
    throw securityError('Invalid credential encoding');
  const bytes = Buffer.from(value, 'base64');
  if (
    bytes.toString('base64') !== value ||
    bytes.length < expectedLength ||
    bytes.length > maxLength
  )
    throw securityError('Invalid credential size');
  return bytes;
}
export type Session = {
  version: 1;
  apiId: number;
  apiHash: string;
  dcId: number;
  authKey: Buffer;
  salt: bigint;
  timeOffset: number;
  createdAt: string;
};
type StoredSession = Omit<Session, 'authKey' | 'salt'> & {
  authKey: string;
  salt: string;
};

export function validateSession(input: unknown): Session {
  const value = input as Session | StoredSession;
  if (
    !value ||
    value.version !== 1 ||
    !Number.isInteger(value.apiId) ||
    value.apiId < 1 ||
    value.apiId > 2_147_483_647 ||
    typeof value.apiHash !== 'string' ||
    !/^[a-f0-9]{32}$/i.test(value.apiHash) ||
    !Number.isInteger(value.dcId) ||
    !Object.hasOwn(DC_ADDRESSES, value.dcId)
  )
    throw securityError('Invalid stored session fields');
  const authKey = Buffer.isBuffer(value.authKey)
    ? Buffer.from(value.authKey)
    : base64(value.authKey, 256);
  try {
    if (authKey.length !== 256 || authKey.every((byte) => byte === 0))
      throw securityError('Invalid authentication key');
    if (!/^-?\d{1,20}$/.test(String(value.salt ?? '0')))
      throw securityError('Invalid server salt');
    const salt = BigInt(value.salt ?? '0');
    if (
      salt < -(1n << 63n) ||
      salt >= 1n << 63n ||
      !Number.isFinite(value.timeOffset ?? 0) ||
      Math.abs(value.timeOffset ?? 0) > 86400
    )
      throw securityError('Invalid session timing/salt');
    const createdAt = value.createdAt ?? timestamp();
    try {
      if (typeof createdAt !== 'string') throw new Error();
      Temporal.Instant.from(createdAt);
    } catch {
      throw securityError('Invalid session timestamp');
    }
    return {
      version: 1,
      apiId: value.apiId,
      apiHash: value.apiHash,
      dcId: value.dcId,
      authKey,
      salt,
      timeOffset: value.timeOffset ?? 0,
      createdAt,
    };
  } catch (error) {
    authKey.fill(0);
    throw error;
  }
}
export function encodeSession(session: Session) {
  const value = validateSession(session);
  try {
    return Buffer.from(
      JSON.stringify({
        ...value,
        authKey: value.authKey.toString('base64'),
        salt: value.salt.toString(),
      }),
    );
  } finally {
    value.authKey.fill(0);
  }
}
export function decodeSession(bytes: Buffer) {
  try {
    return validateSession(
      JSON.parse(new TextDecoder('utf8', { fatal: true }).decode(bytes)),
    );
  } catch {
    throw securityError(
      'The credential store returned an invalid Telegram session',
    );
  }
}

const legacyToken = new RegExp(
  String.raw`^(true|false|null|[+-]?(?:0[xX][a-fA-F0-9]+|` +
    String.raw`(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?))`,
);

// Non-evaluating JSON5 subset for the old CLI's flat config. Supports comments,
// quoted or unquoted keys, strings, finite numbers, booleans, null, and
// trailing commas. Rejects expressions, duplicate/prototype keys, and nesting.
type LegacyValue = string | number | boolean | null;
export function parseLegacy(text: string): Record<string, LegacyValue> {
  if (typeof text !== 'string' || text.length > 65_536)
    throw securityError('Legacy config exceeds limit');
  let index = 0;
  function fail(): never {
    throw securityError(
      'Unsupported or invalid legacy JSON5 config; no code was evaluated',
    );
  }
  function space() {
    while (index < text.length) {
      if (/\s/.test(text[index])) {
        index++;
        continue;
      }
      if (text.startsWith('//', index)) {
        const end = text.indexOf('\n', index + 2);
        index = end < 0 ? text.length : end;
        continue;
      }
      if (text.startsWith('/*', index)) {
        const end = text.indexOf('*/', index + 2);
        if (end < 0) fail();
        index = end + 2;
        continue;
      }
      break;
    }
  }
  function quoted() {
    const quote = text[index++];
    let result = '';
    while (index < text.length) {
      let character = text[index++];
      if (character === quote) return result;
      if (character.charCodeAt(0) < 32) fail();
      if (character === '\\') {
        character = text[index++];
        const escapes: Record<string, string> = {
          '"': '"',
          "'": "'",
          '\\': '\\',
          '/': '/',
          b: '\b',
          f: '\f',
          n: '\n',
          r: '\r',
          t: '\t',
          v: '\v',
        };
        if (Object.hasOwn(escapes, character)) result += escapes[character];
        else if (character === 'u' || character === 'x') {
          const length = character === 'u' ? 4 : 2,
            hex = text.slice(index, index + length);
          if (!new RegExp(`^[a-f0-9]{${length}}$`, 'i').test(hex)) fail();
          result += String.fromCharCode(parseInt(hex, 16));
          index += length;
        } else fail();
      } else result += character;
    }
    fail();
  }
  space();
  if (text[index++] !== '{') fail();
  const result: Record<string, LegacyValue> = Object.create(null);
  while (true) {
    space();
    if (text[index] === '}') {
      index++;
      break;
    }
    const isQuoted = text[index] === '"' || text[index] === "'";
    const key = isQuoted
      ? quoted()
      : /^[a-zA-Z_$][\w$]*/.exec(text.slice(index))?.[0];
    if (!key) fail();
    if (!isQuoted) index += key.length;
    if (
      ['__proto__', 'constructor', 'prototype'].includes(key) ||
      Object.hasOwn(result, key) ||
      Object.keys(result).length >= 32
    )
      fail();
    space();
    if (text[index++] !== ':') fail();
    space();
    let value;
    if (text[index] === '"' || text[index] === "'") value = quoted();
    else {
      const token = legacyToken.exec(text.slice(index));
      if (!token) fail();
      index += token[0].length;
      value =
        token[0] === 'true'
          ? true
          : token[0] === 'false'
            ? false
            : token[0] === 'null'
              ? null
              : Number(token[0]);
      if (typeof value === 'number' && !Number.isFinite(value)) fail();
    }
    result[key] = value;
    space();
    if (text[index] === '}') {
      index++;
      break;
    }
    if (text[index++] !== ',') fail();
  }
  space();
  if (index !== text.length) fail();
  return result;
}
export function importStringSession(sessionString: unknown) {
  if (typeof sessionString !== 'string' || sessionString[0] !== '1')
    throw securityError('Unsupported legacy session version');
  const data = base64(sessionString.slice(1), 263, 512);
  let offset = 1;
  const dcId = data[0];
  if (data.length === 263) offset += 4; // Telethon's fixed IPv4 representation.
  else {
    const length = data.readInt16BE(1);
    offset = 3;
    if (length < 1 || length > 100 || data.length !== 1 + 2 + length + 2 + 256)
      throw securityError('Invalid legacy server address length');
    offset += length;
  }
  const port = data.readUInt16BE(offset);
  offset += 2;
  if (![80, 443, 5222].includes(port) || data.length - offset !== 256)
    throw securityError('Invalid legacy session layout');
  // Never use the embedded address/port. DC IDs are mapped to pinned endpoints.
  return {
    dcId,
    authKey: Buffer.from(data.subarray(offset)),
    salt: 0n,
    timeOffset: 0,
  };
}
export async function loadLegacy(filename: string) {
  const bytes = await readPrivateFile(filename, 65_536);
  let session;
  try {
    const config = parseLegacy(bytes.toString('utf8'));
    session = importStringSession(config.sessionString);
    return {
      ...validateSession({
        version: 1,
        apiId: config.apiId,
        apiHash: config.apiHash,
        ...session,
        createdAt: timestamp(),
      }),
      legacyDefaultFormat: config.defaultFormat,
    };
  } finally {
    bytes.fill(0);
    session?.authKey.fill(0);
  }
}

// Local attachments and bounded upload parts.
const PART_SIZE = 512 * 1024,
  BIG_FILE_THRESHOLD = 10 * 1024 * 1024;
export const MAX_UPLOAD_MIB = 100;
const MAX_SIZE = BigInt(MAX_UPLOAD_MIB * 1024 * 1024);

export async function openAttachment(filename: string) {
  if (
    typeof filename !== 'string' ||
    !filename ||
    filename.includes('\0') ||
    !filename.isWellFormed()
  )
    throw securityError('Supply one local attachment path');
  const absolute = resolve(filename),
    name = basename(absolute);
  if (
    !name ||
    /[\\\p{Cc}\p{Bidi_Control}\u2028\u2029]/u.test(name) ||
    Buffer.byteLength(name) > 255
  )
    throw securityError('Invalid attachment filename');
  let handle, original;
  try {
    if (windows) await windowsPath('attachment', absolute);
    else await noSymlinkPath(dirname(absolute));
    const path = absolute;
    const entry = await lstat(path, { bigint: true });
    if (!entry.isFile())
      throw securityError(
        'Attachment must be a regular file, not a symlink or special file',
      );
    // Recheck the opened descriptor. NONBLOCK avoids hanging on a FIFO
    // substituted between lstat and open; NOFOLLOW protects the final element.
    handle = await open(
      path,
      constants.O_RDONLY | noFollow | (constants.O_NONBLOCK ?? 0),
    );
    original = await handle.stat({ bigint: true });
    if (
      !original.isFile() ||
      original.dev !== entry.dev ||
      original.ino !== entry.ino
    )
      throw securityError('Attachment changed while opening');
    if (original.size < 1n || original.size > MAX_SIZE)
      throw securityError(
        `Attachment must be nonempty and at most ${MAX_UPLOAD_MIB} MiB`,
      );
  } catch (error) {
    await handle?.close();
    if (isSecurityError(error)) throw error;
    throw securityError('Could not open the attachment');
  }

  const size = Number(original.size);
  const verifyUnchanged = async () => {
    const current = await handle.stat({ bigint: true }).catch(() => {
      throw securityError('Could not check the attachment');
    });
    if (
      current.size !== original.size ||
      current.mtimeNs !== original.mtimeNs ||
      current.ctimeNs !== original.ctimeNs
    )
      throw securityError(
        'Attachment changed during the operation; no message was submitted',
      );
  };
  return {
    name,
    size,
    close: () => handle.close(),
    async upload(rpc: RpcClient) {
      await verifyUnchanged();
      const id = randomLong() || 1n,
        parts = Math.ceil(size / PART_SIZE),
        big = size > BIG_FILE_THRESHOLD;
      // MD5 is the wire checksum for small files, not authentication.
      const checksum = big ? undefined : createHash('md5');
      const buffer = Buffer.alloc(Math.min(size, PART_SIZE));
      try {
        for (let filePart = 0; filePart < parts; filePart++) {
          const position = filePart * PART_SIZE,
            length = Math.min(PART_SIZE, size - position);
          for (let offset = 0; offset < length;) {
            const { bytesRead } = await handle
              .read(buffer, offset, length - offset, position + offset)
              .catch(() => {
                throw securityError('Could not read the attachment');
              });
            if (!bytesRead)
              throw securityError(
                'Attachment was truncated; no message was submitted',
              );
            offset += bytesRead;
          }
          const bytes = buffer.subarray(0, length);
          checksum?.update(bytes);
          const accepted = await rpc.invoke(
            big ? 'upload.SaveBigFilePart' : 'upload.SaveFilePart',
            {
              fileId: id,
              filePart,
              bytes,
              ...(big ? { fileTotalParts: parts } : {}),
            },
            { mutation: true },
          );
          if (accepted !== true)
            throw protocolError(
              'Telegram did not accept an attachment part; no message was' +
                ' submitted',
            );
        }
        await verifyUnchanged();
      } catch (error) {
        // Only the later SendMedia request can publish a chat message.
        if (isAmbiguousMutationError(error))
          throw protocolError(
            'Attachment upload was interrupted; no message was submitted',
          );
        throw error;
      } finally {
        buffer.fill(0);
      }
      return big
        ? { _: 'InputFileBig', id, parts, name }
        : {
            _: 'InputFile',
            id,
            parts,
            name,
            md5Checksum: checksum!.digest('hex'),
          };
    },
  };
}
