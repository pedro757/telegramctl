import { securityError } from './common.ts';

export function nativeFilename(
  platform: NodeJS.Platform,
  arch: string = process.arch,
) {
  if (platform !== 'win32') return 'telegram-os';
  if (arch !== 'x64' && arch !== 'arm64')
    throw securityError('The Windows native helper supports x64 and ARM64');
  return `telegram-os-${arch}.exe`;
}
