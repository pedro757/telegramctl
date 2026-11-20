// Shared helpers without I/O.

// Error creation and classification.
const kinds = new WeakMap<Error, string>();

function namedError(name: string, message: string) {
  const error = new Error(message);
  error.name = name;
  kinds.set(error, name);
  return error;
}

export const securityError = (message: string) =>
  namedError('SecurityError', message);
export const protocolError = (message: string) =>
  namedError('ProtocolError', message);
export const approvalError = (message: string) =>
  namedError('ApprovalError', message);
export const ambiguousMutationError = () =>
  namedError(
    'AmbiguousMutationError',
    'The connection failed after a mutation was submitted. Its' +
      ' outcome is unknown. Do not repeat it blindly; verify the' +
      ' Telegram state first.',
  );

export function rpcError(code: number, errorMessage: string) {
  // Never include the request or user-provided arguments in exceptions.
  const safe = /^[A-Z0-9_]{1,160}$/.test(errorMessage)
    ? errorMessage
    : 'UNRECOGNIZED_RPC_ERROR';
  return Object.assign(
    namedError('RpcError', `Telegram RPC ${code}: ${safe}`),
    { code, errorMessage: safe },
  );
}

// Retry and sanitization decisions must not trust an arbitrary error.name.
export type RpcError = ReturnType<typeof rpcError>;
type ErrorKind =
  | 'SecurityError'
  | 'ProtocolError'
  | 'RpcError'
  | 'AmbiguousMutationError';
const hasKind = (error: unknown, kind: ErrorKind) =>
  kinds.get(error as Error) === kind;
export const isSecurityError = (error: unknown): error is Error =>
  hasKind(error, 'SecurityError');
export const isProtocolError = (error: unknown): error is Error =>
  hasKind(error, 'ProtocolError');
export const isRpcError = (error: unknown): error is RpcError =>
  hasKind(error, 'RpcError');
export const isAmbiguousMutationError = (error: unknown): error is Error =>
  hasKind(error, 'AmbiguousMutationError');

// Time conversions and duration parsing.
export const now = () => Temporal.Now.instant();
export const epochSeconds = (instant = now()) => {
  const nanos = instant.epochNanoseconds,
    seconds = nanos / 1_000_000_000n;
  return Number(nanos < 0n && nanos % 1_000_000_000n ? seconds - 1n : seconds);
};
export const isoSeconds = (seconds: number) =>
  Temporal.Instant.fromEpochNanoseconds(
    BigInt(seconds) * 1_000_000_000n,
  ).toString();
export const timestamp = () => now().toString();

export function timeFilter(value: string, reference = now()) {
  if (typeof value !== 'string') throw new Error('Expected a time string');
  const match = /^(\d+)([smhdw])$/.exec(value);
  if (!match) {
    try {
      return Temporal.Instant.from(value);
    } catch {
      throw new Error(
        'Time must be an elapsed offset or an ISO instant with an' +
          ' explicit timezone',
      );
    }
  }
  const amount = Number(match[1]);
  const seconds =
    amount *
    { s: 1, m: 60, h: 3600, d: 86400, w: 604800 }[
      match[2] as 's' | 'm' | 'h' | 'd' | 'w'
    ];
  if (!Number.isSafeInteger(seconds) || seconds > 3_155_760_000)
    throw new Error('Time offset is too large');
  return reference.subtract({ seconds });
}

export function muteUntil(value: string, reference = now()) {
  if (value === 'forever') return 2_147_483_647;
  if (!/^\d+[smhdw]$/.test(value))
    throw new Error('Duration must be e.g. 30m, 1h, 7d, or forever');
  const elapsed =
    epochSeconds(reference) - epochSeconds(timeFilter(value, reference));
  const until = epochSeconds(reference) + elapsed;
  if (elapsed <= 0 || until > 2_147_483_647)
    throw new Error('Mute duration is outside Telegram limits');
  return until;
}

// Output escaping for remote content.
export function safeJson(value: unknown, space = 2) {
  return JSON.stringify(
    value,
    (_, item) => (typeof item === 'bigint' ? item.toString() : item),
    space,
  ).replace(
    /[\u007f-\u009f\u2028-\u2029\p{Bidi_Control}]/gu,
    (character) =>
      `\\u${character.charCodeAt(0).toString(16).padStart(4, '0')}`,
  );
}
const terminalControls =
  // oxlint-disable-next-line no-control-regex -- Escape terminal control bytes.
  /[\x00-\x1f\x7f-\x9f\u2028-\u2029\p{Bidi_Control}]/gu;
export const terminalText = (value: unknown) =>
  String(value).replace(
    terminalControls,
    (character) =>
      `\\u${character.charCodeAt(0).toString(16).padStart(4, '0')}`,
  );
