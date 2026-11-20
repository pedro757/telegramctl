import { readdir, readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { stripTypeScriptTypes } from 'node:module';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { join, relative, sep } from 'node:path';
import assert from 'node:assert/strict';
import type { Schema } from '../src/tl.ts';

const root = fileURLToPath(new URL('../', import.meta.url));
const pkg = JSON.parse(await readFile(join(root, 'package.json'), 'utf8'));
for (const key of [
  'dependencies',
  'optionalDependencies',
  'peerDependencies',
  'bundledDependencies',
])
  assert.ok(
    !pkg[key] || Object.keys(pkg[key]).length === 0,
    `${key} must be empty`,
  );
async function* walk(directory: string): AsyncGenerator<string> {
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    if (
      entry.name.startsWith('.') ||
      ['node_modules', 'coverage', 'dist'].includes(entry.name)
    )
      continue;
    const filename = join(directory, entry.name);
    if (entry.isDirectory()) yield* walk(filename);
    else yield filename;
  }
}
let count = 0;
for await (const filename of walk(root)) {
  if (!filename.endsWith('.ts')) continue;
  const text = await readFile(filename, 'utf8'),
    name = relative(root, filename).split(sep).join('/');
  for (const [index, line] of text.split(/\r?\n/).entries()) {
    assert.ok(
      line.length <= 80 || Array.from(line).length <= 80,
      `${name}:${index + 1}: line exceeds 80 characters`,
    );
  }
  const checked = spawnSync(
    process.execPath,
    ['--input-type=module', '--check'],
    { encoding: 'utf8', input: stripTypeScriptTypes(text) },
  );
  assert.equal(checked.status, 0, `${name}: ${checked.stderr}`);
  assert.ok(
    !/\bnew\s+Date\b|\bDate\s*[.(]/.test(text),
    `${name}: use Temporal, not the legacy clock/calendar API`,
  );
  for (const match of text.matchAll(
    /^import\s+(?:(?:[^'";]+?)\s+from\s+)?['"]([^'"]+)['"]/gm,
  ))
    assert.ok(
      match[1].startsWith('node:') || match[1].startsWith('.'),
      `${name}: non-builtin import ${match[1]}`,
    );
  if (name.startsWith('src/') || name.startsWith('bin/')) {
    assert.ok(
      !/\beval\s*\(|\bnew\s+Function\s*\(|\bimport\s*\(/.test(text),
      `${name}: dynamic execution`,
    );
    if (name !== 'src/native.ts')
      assert.ok(
        !text.includes('node:child_process'),
        `${name}: subprocesses belong only in the native-helper adapter`,
      );
  }
  count++;
}
const schema = await readFile(join(root, 'src/protocol/schema.json'));
const provenance = JSON.parse(
  await readFile(join(root, 'src/protocol/provenance.json'), 'utf8'),
);
assert.equal(
  createHash('sha256').update(schema).digest('hex'),
  provenance.schemaSha256,
  'Generated schema integrity',
);
const parsed: Schema = JSON.parse(schema.toString('utf8'));
assert.deepEqual(
  parsed.definitions
    .filter((definition) => definition[3])
    .map((definition) => parsed.strings[definition[0]])
    .sort(),
  provenance.requests,
  'Only the documented RPC allowlist may be included',
);
assert.equal(parsed.layer, 232);
console.log(
  `Checked ${count} TypeScript modules: syntax, 80-column limit, zero runtime` +
    ' npm dependencies, built-in/local imports, native Temporal policy,' +
    ' isolated native-helper subprocess boundary, no eval, and pinned' +
    ' schema integrity.',
);
