#!/usr/bin/env node
import { main } from '../src/cli.ts';
import { terminalText } from '../src/common.ts';

if (
  Number(process.versions.node.split('.')[0]) < 26 ||
  typeof Temporal !== 'object'
) {
  process.stderr.write(
    'Telegram requires Node.js 26.0.0 or newer with native Temporal enabled.\n',
  );
  process.exitCode = 1;
} else {
  try {
    await main();
  } catch (error) {
    const failure = error as Error;
    const name = terminalText(failure.name || 'Error');
    const message = terminalText(failure.message || 'Operation failed');
    process.stderr.write(`${name}: ${message}\n`);
    process.exitCode = 1;
  }
}
