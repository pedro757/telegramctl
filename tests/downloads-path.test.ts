import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, writeFile } from 'node:fs/promises';
import { join, win32 } from 'node:path';
import { defaultDownloadsDirectory, xdgDownloads } from '../src/downloads.ts';
import { scratch, windows } from './support.ts';

test('XDG Downloads handles localization without shell expansion', () => {
  const home = '/home/alice';
  assert.equal(
    xdgDownloads('XDG_DOWNLOAD_DIR="$HOME/Téléchargements"\n', home),
    '/home/alice/Téléchargements',
  );
  assert.equal(
    xdgDownloads('XDG_DOWNLOAD_DIR="${HOME}/Shared Downloads" # note', home),
    '/home/alice/Shared Downloads',
  );
  assert.equal(
    xdgDownloads('XDG_DOWNLOAD_DIR="/data/Downloads"\r\n', home),
    '/data/Downloads',
  );
  for (const path of [
    '$HOME/',
    'relative',
    '$OTHER/path',
    '/$(echo bad)',
    '/`id`',
  ])
    assert.equal(xdgDownloads(`XDG_DOWNLOAD_DIR="${path}"`, home), undefined);
});

test(
  'Linux reads XDG_CONFIG_HOME and falls back to Downloads',
  {
    skip: windows,
  },
  async (t) => {
    const home = await scratch(t),
      configHome = join(home, 'config');
    await mkdir(configHome);
    const filename = join(configHome, 'user-dirs.dirs');
    const options = { platform: 'linux', home, configHome } as const;
    assert.equal(
      await defaultDownloadsDirectory(options),
      join(home, 'Downloads'),
    );
    await writeFile(filename, 'XDG_DOWNLOAD_DIR="$HOME/Other Downloads"\n');
    assert.equal(
      await defaultDownloadsDirectory(options),
      join(home, 'Other Downloads'),
    );
    await writeFile(filename, 'XDG_DOWNLOAD_DIR="$HOME/"\n');
    assert.equal(
      await defaultDownloadsDirectory(options),
      join(home, 'Downloads'),
    );
  },
);

test('macOS defaults to Downloads under the home directory', async () => {
  const home = join('test-home', 'alice');
  assert.equal(
    await defaultDownloadsDirectory({ platform: 'darwin', home }),
    join(home, 'Downloads'),
  );
});

test(
  'Windows returns an absolute path from the Known Folder API',
  {
    skip: !windows,
  },
  async () => {
    assert.ok(win32.isAbsolute(await defaultDownloadsDirectory()));
  },
);
