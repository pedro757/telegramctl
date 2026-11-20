import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { access } from 'node:fs/promises';
import { constants } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { securityError } from './common.ts';
import { nativeFilename } from './native-filename.ts';

export type HelperResult = {
  code: number;
  stdout: Buffer;
  stderrBytes: number;
};
export const HELPER_MISSING = 10;
export const HELPER_EXISTS = 11;
const MAX_OUTPUT = 32 * 1024;

export function nativeExecutable(platform = process.platform) {
  const name = nativeFilename(platform);
  const base = import.meta.url.endsWith('.ts')
    ? '../dist/native/'
    : '../native/';
  return fileURLToPath(new URL(base + name, import.meta.url));
}

export async function assertExecutable(executable: string, message: string) {
  try {
    await access(executable, constants.X_OK);
  } catch {
    throw securityError(message);
  }
}

export function assertNative(platform = process.platform) {
  return assertExecutable(
    nativeExecutable(platform),
    'Native OS helper is missing. Run npm run build:native from the checkout' +
      ' or reinstall a build for this OS. No file fallback is available.',
  );
}

export async function runNative(
  args: string[],
  input?: Buffer,
  {
    timeoutMs,
    failure,
    console = false,
  }: { timeoutMs?: number; failure: () => Error; console?: boolean } = {
    failure: () => securityError('Native OS helper failed or timed out'),
  },
) {
  await assertNative();
  return runHelper(nativeExecutable(), args, input, {
    timeoutMs,
    failure,
    console,
  });
}

// The only production subprocess boundary. Use an explicit executable, no
// shell, pipes for sensitive payloads, and bounded, discarded diagnostics.
export async function runHelper(
  executable: string,
  args: string[],
  input: Buffer | undefined,
  {
    spawnProcess = spawn,
    timeoutMs = 120_000,
    console = false,
    failure,
  }: {
    spawnProcess?: typeof spawn;
    timeoutMs?: number;
    console?: boolean;
    failure: () => Error;
  },
): Promise<HelperResult> {
  return new Promise((resolve, reject) => {
    let child: ChildProcessWithoutNullStreams;
    try {
      child = spawnProcess(executable, args, {
        shell: false,
        windowsHide: !console,
        stdio: ['pipe', 'pipe', 'pipe'],
      });
    } catch {
      reject(failure());
      return;
    }
    let done = false,
      size = 0,
      stderrBytes = 0;
    const chunks: Buffer[] = [];
    const finish = (error: boolean, code?: number | null) => {
      if (done) return;
      done = true;
      if (timer) clearTimeout(timer);
      if (error) {
        // Windows restores console modes via the helper's control handler;
        // interactive prompts have no forced deadline.
        child.kill('SIGKILL');
        child.stdout.destroy();
        child.stderr.destroy();
        child.stdin.destroy();
      }
      const stdout = error ? undefined : Buffer.concat(chunks, size);
      for (const chunk of chunks) chunk.fill(0);
      if (error) reject(failure());
      else resolve({ code: code!, stdout: stdout!, stderrBytes });
    };
    const timer =
      timeoutMs > 0 ? setTimeout(() => finish(true), timeoutMs) : null;
    child.on('error', () => finish(true));
    child.on('close', (code) => finish(code === null, code));
    child.stdin.on('error', () => finish(true));
    child.stdout.on('error', () => finish(true));
    child.stderr.on('error', () => finish(true));
    child.stdout.on('data', (chunk: Buffer) => {
      if (done) {
        chunk.fill(0);
        return;
      }
      size += chunk.length;
      if (size > MAX_OUTPUT) {
        chunk.fill(0);
        finish(true);
        return;
      }
      chunks.push(chunk);
    });
    child.stderr.on('data', (chunk: Buffer) => {
      stderrBytes += chunk.length;
      chunk.fill(0);
      if (!done && stderrBytes > MAX_OUTPUT) finish(true);
    });
    child.stdin.end(input);
  });
}
