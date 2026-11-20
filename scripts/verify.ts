import { spawnSync } from 'node:child_process';
import { writeFile, readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const check = spawnSync(process.execPath, ['scripts/check.ts'], {
  cwd: root,
  encoding: 'utf8',
  maxBuffer: 4 * 1024 * 1024,
});
process.stdout.write(check.stdout);
process.stderr.write(check.stderr);
const testFiles = 'tests/**/*.test.ts';
const tests = spawnSync(
  process.execPath,
  ['--test', '--test-reporter=tap', testFiles],
  {
    cwd: root,
    encoding: 'utf8',
    maxBuffer: 8 * 1024 * 1024,
  },
);
const counters: Record<string, number> = {};
for (const name of ['tests', 'pass', 'fail', 'cancelled', 'skipped', 'todo'])
  counters[name] = Number(
    new RegExp(`^# ${name} (\\d+)$`, 'm').exec(tests.stdout)?.[1] ?? -1,
  );
const passed =
  check.status === 0 &&
  tests.status === 0 &&
  counters.fail === 0 &&
  counters.tests > 0;
const provenance = JSON.parse(
  await readFile(
    new URL('../src/protocol/provenance.json', import.meta.url),
    'utf8',
  ),
);
await writeFile(
  new URL('../docs/validation-results.json', import.meta.url),
  JSON.stringify(
    {
      verifiedAt: Temporal.Now.instant().toString(),
      node: process.version,
      passed,
      checks: {
        command: 'node scripts/check.ts',
        exitCode: check.status,
        summary: check.stdout.trim(),
      },
      tests: {
        command: `node --test --test-reporter=tap '${testFiles}'`,
        exitCode: tests.status,
        ...counters,
      },
      scope:
        'Offline fixtures/mocked Telegram clients and transports; no' +
        ' real account, credential store or live Telegram connection' +
        ' used.',
      liveInteroperabilityVerified: false,
      independentSecurityAuditComplete: false,
      schema: {
        layer: provenance.layer,
        sha256: provenance.schemaSha256,
        constructors: provenance.constructors,
        rpcDefinitions: provenance.requests.length,
      },
    },
    null,
    2,
  ) + '\n',
);
if (!passed) {
  process.stdout.write(tests.stdout);
  process.stderr.write(tests.stderr);
  process.exitCode = 1;
} else
  process.stdout.write(
    `Offline verification passed: ${counters.pass}/${counters.tests} tests,` +
      ` ${counters.fail} failures, ${counters.skipped} skipped.\n`,
  );
