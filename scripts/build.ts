import { mkdir, cp } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import { nativeFilename } from '../src/native-filename.ts';

const root = fileURLToPath(new URL('../', import.meta.url));
const output = join(root, 'dist', 'native');
if (!process.argv.includes('--native-only'))
  await cp(
    join(root, 'src', 'protocol'),
    join(root, 'dist', 'src', 'protocol'),
    {
      recursive: true,
      filter: (source) => !source.endsWith('.ts'),
    },
  );

const windows = process.platform === 'win32';
if (windows || process.platform === 'darwin') {
  await mkdir(output, { recursive: true });
  const filename = nativeFilename(
    process.platform,
    windows ? process.env.VSCMD_ARG_TGT_ARCH : undefined,
  );
  const args = windows
    ? [
        '/nologo',
        '/std:c11',
        '/O2',
        '/W4',
        '/MT',
        `/Fe:${filename}`,
        join(root, 'native', 'windows.c'),
        '/link',
        'advapi32.lib',
        'shell32.lib',
        'ole32.lib',
      ]
    : [
        '-std=c11',
        '-O2',
        '-Wall',
        '-Wextra',
        '-mmacosx-version-min=13.0',
        '-arch',
        'x86_64',
        '-arch',
        'arm64',
        join(root, 'native', 'keychain.c'),
        '-framework',
        'Security',
        '-framework',
        'CoreFoundation',
        '-o',
        filename,
      ];
  const result = spawnSync(windows ? 'cl.exe' : '/usr/bin/clang', args, {
    cwd: output,
    stdio: 'inherit',
  });
  if (result.error || result.status !== 0)
    throw new Error(
      windows
        ? 'Native build failed. Use the Visual Studio C++ developer shell.'
        : 'Native build failed. Install Xcode Command Line Tools.',
      { cause: result.error },
    );
}
