import { access, mkdir, readFile } from 'node:fs/promises';
import { constants } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import assert from 'node:assert/strict';

const root = fileURLToPath(new URL('../', import.meta.url));
const files = [
  'dist/native/telegram-os',
  'dist/native/telegram-os-x64.exe',
  'dist/native/telegram-os-arm64.exe',
];
const read = async (filename: string) => {
  try {
    return await readFile(join(root, filename));
  } catch (error) {
    throw new Error(`Missing release file: ${filename}. Use the CI build.`, {
      cause: error,
    });
  }
};
const mac = await read(files[0]);
assert.equal(
  mac.readUInt32BE(),
  0xcafebabe,
  'Expected a universal macOS helper',
);
assert.equal(mac.readUInt32BE(4), 2, 'Expected two macOS architecture slices');
assert.deepEqual(
  [mac.readUInt32BE(8), mac.readUInt32BE(28)].sort((a, b) => a - b),
  [0x01000007, 0x0100000c],
  'Expected x64 and ARM64 macOS slices',
);
if (process.platform !== 'win32')
  await access(join(root, files[0]), constants.X_OK);

for (const [file, machine] of [
  [files[1], 0x8664],
  [files[2], 0xaa64],
] as const) {
  const exe = await read(file);
  assert.equal(
    exe.toString('ascii', 0, 2),
    'MZ',
    `Invalid Windows helper ${file}`,
  );
  const header = exe.readUInt32LE(0x3c);
  assert.equal(
    exe.readUInt32LE(header),
    0x4550,
    `Invalid PE header in ${file}`,
  );
  assert.equal(exe.readUInt16LE(header + 4), machine, `Wrong arch in ${file}`);
}

const required = [
  ...files,
  'dist/bin/telegramctl.js',
  'dist/src/protocol/schema.json',
];
for (const file of required.slice(files.length)) await access(join(root, file));

if (!process.argv.includes('--check')) {
  const dest = join(root, 'dist', 'release');
  await mkdir(dest, { recursive: true });
  // npm runs this script with npm_execpath pointing to its JS entry point.
  const npm = process.env.npm_execpath;
  assert.ok(npm, 'Run npm run pack:release');
  const result = spawnSync(
    process.execPath,
    [npm, 'pack', '--ignore-scripts', '--json', '--pack-destination', dest],
    { cwd: root, encoding: 'utf8' },
  );
  if (result.error || result.status !== 0)
    throw new Error(result.stderr || 'npm pack failed', {
      cause: result.error,
    });
  const [archive] = JSON.parse(result.stdout);
  const included = new Set(
    archive.files.map(({ path }: { path: string }) => path),
  );
  for (const file of required)
    assert.ok(included.has(file), `${file} is missing from the tarball`);
  console.log(join(dest, archive.filename));
}
