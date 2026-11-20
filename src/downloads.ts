import { constants } from 'node:fs';
import { open } from 'node:fs/promises';
import { homedir } from 'node:os';
import { isAbsolute, join, posix, win32 } from 'node:path';
import { runNative } from './native.ts';
import { securityError } from './common.ts';

const MAX_CONFIG = 16 * 1024;

// XDG's file is shell-like configuration, not a script. Only accept a quoted
// absolute path or one rooted in $HOME; never expand commands or other vars.
export function xdgDownloads(config: string, home: string) {
  const key = /^[ \t]*XDG_DOWNLOAD_DIR[ \t]*=[ \t]*/;
  const setting = config.split(/\r?\n/).find((line) => key.test(line));
  const value = setting
    ?.replace(key, '')
    .match(/^"((?:\\.|[^"\\])*)"[ \t]*(?:#.*)?$/);
  if (!value) return undefined;
  let text = value[1],
    prefix = '';
  if (text.startsWith('$HOME/') || text.startsWith('${HOME}/')) {
    prefix = home;
    text = text.slice(text.indexOf('/'));
  }
  let path = prefix;
  for (let i = 0; i < text.length; i++) {
    const char = text[i];
    if (char === '\\' && ['\\', '"', '$', '`'].includes(text[i + 1])) {
      path += text[++i];
    } else {
      if (char === '$' || char === '`' || char === '\0') return undefined;
      path += char;
    }
  }
  if (!posix.isAbsolute(path)) return undefined;
  const directory = posix.resolve(path);
  // XDG writes "$HOME/" when the user disables a special directory.
  if (directory === posix.resolve(home)) return undefined;
  return directory;
}

async function linuxDownloads(home: string, configHome?: string) {
  const directory =
    configHome && isAbsolute(configHome) ? configHome : join(home, '.config');
  try {
    const handle = await open(
      join(directory, 'user-dirs.dirs'),
      constants.O_RDONLY | (constants.O_NONBLOCK ?? 0),
    );
    try {
      if (!(await handle.stat()).isFile()) return undefined;
      const buffer = Buffer.alloc(MAX_CONFIG + 1);
      let length = 0;
      while (length < buffer.length) {
        const { bytesRead } = await handle.read(buffer, length);
        if (!bytesRead) break;
        length += bytesRead;
      }
      if (length <= MAX_CONFIG) {
        const decoder = new TextDecoder('utf-8', { fatal: true });
        return xdgDownloads(decoder.decode(buffer.subarray(0, length)), home);
      }
    } finally {
      await handle.close();
    }
  } catch {
    // Missing or unreadable user configuration: use the platform default.
  }
}

export async function defaultDownloadsDirectory({
  platform = process.platform,
  home = homedir(),
  configHome = process.env.XDG_CONFIG_HOME,
} = {}) {
  if (platform === 'win32') {
    const result = await runNative(['known-downloads']);
    const directory = result.stdout.toString('utf8');
    if (result.code !== 0 || !win32.isAbsolute(directory))
      throw securityError(
        'Could not locate Windows Downloads; pass -o/--output <directory>',
      );
    return directory;
  }
  if (platform === 'linux') {
    const directory = await linuxDownloads(home, configHome);
    if (directory) return directory;
  }
  return join(home, 'Downloads');
}
