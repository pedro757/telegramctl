import type { FileHandle } from 'node:fs/promises';
import { join } from 'node:path';
import {
  privateDirectory,
  lockDirectory,
  existsPrivate,
  privateTemporary,
  openPrivateFile,
  atomicPrivateWrite,
  privateRead,
} from './files.ts';
import {
  parsePeerId,
  peerKey,
  summarizePeer,
  type createTelegram,
} from './telegram.ts';
import {
  timestamp,
  timeFilter,
  epochSeconds,
  securityError,
  safeJson,
} from './common.ts';

const MAX_LINE = 128 * 1024;
const utf8 = new TextDecoder('utf8', { fatal: true });
// These are on-disk format identifiers, not the installed command name.
const ARCHIVE_FORMAT = 'telegram-cli-export';
const SYNC_FORMAT = 'telegram-cli-sync-meta';
export const MAX_SYNC_CHATS = 10_000;
export const MAX_META_BYTES = 4 * 1024 * 1024;
async function* lines(handle: FileHandle, maxBytes: number) {
  let pending: Buffer = Buffer.alloc(0),
    total = 0;
  for await (const chunk of handle.createReadStream({ autoClose: false })) {
    total += chunk.length;
    if (total > maxBytes)
      throw securityError('Existing export exceeds the configured size limit');
    pending = pending.length ? Buffer.concat([pending, chunk]) : chunk;
    for (let end; (end = pending.indexOf(10)) >= 0;) {
      if (end > MAX_LINE) throw securityError('Export record exceeds limit');
      let line;
      try {
        line = utf8.decode(pending.subarray(0, end));
      } catch {
        throw securityError('Existing export contains invalid UTF-8');
      }
      yield line;
      pending = pending.subarray(end + 1);
    }
    if (pending.length > MAX_LINE)
      throw securityError('Export record exceeds limit');
  }
  if (pending.length)
    throw securityError('Existing export has a truncated final record');
}
function record(line: string) {
  try {
    return JSON.parse(line);
  } catch {
    throw securityError('Existing export contains invalid JSON');
  }
}

type ExportSource = Pick<
  ReturnType<typeof createTelegram>,
  'me' | 'resolve' | 'allDialogs' | 'history'
>;
type ExportOptions = {
  output?: string;
  chat?: string;
  all?: boolean;
  since?: number;
  until?: number;
  resume?: boolean;
  maxMessages?: number;
  maxBytes?: number;
};
type ChatMetadata = { file: string; lastMessageId: number; exportedAt: string };

export async function syncHistory(
  telegram: ExportSource,
  {
    output = './telegram-sync',
    chat,
    all = false,
    since,
    until,
    resume = false,
    maxMessages = 1_000_000,
    maxBytes = 256 * 1024 * 1024,
  }: ExportOptions = {},
  progress: (message: string) => void = () => {},
) {
  if (
    !Number.isInteger(maxMessages) ||
    maxMessages < 1 ||
    maxMessages > 1_000_000 ||
    !Number.isInteger(maxBytes) ||
    maxBytes < 1024 ||
    maxBytes > 1024 * 1024 * 1024
  )
    throw securityError('Invalid export limits');
  if (all && since !== undefined)
    throw securityError('--all and --since are mutually exclusive');
  const directory = await privateDirectory(output),
    release = await lockDirectory(directory, 'export.lock');
  try {
    const accountId = peerKey(await telegram.me());
    if (parsePeerId(accountId)?.kind !== 'user')
      throw securityError('Export requires an authenticated user account');
    const meta = {
      format: SYNC_FORMAT,
      version: 2,
      accountId,
      exportedAt: timestamp(),
      chats: Object.create(null) as Record<string, ChatMetadata>,
    };
    if (await existsPrivate(directory, 'sync-meta.json')) {
      let previous;
      try {
        previous = JSON.parse(
          (
            await privateRead(directory, 'sync-meta.json', MAX_META_BYTES)
          ).toString('utf8'),
        );
      } catch {
        throw securityError(
          'Unrecognized sync metadata; refusing to overwrite it. Verify' +
            ' and move it aside before retrying.',
        );
      }
      if (
        previous.format !== meta.format ||
        previous.version !== 2 ||
        !previous.chats ||
        typeof previous.chats !== 'object' ||
        Array.isArray(previous.chats) ||
        Object.keys(previous).some(
          (key) =>
            !['format', 'version', 'accountId', 'exportedAt', 'chats'].includes(
              key,
            ),
        )
      )
        throw securityError(
          'Unrecognized sync metadata; legacy/unbound metadata cannot' +
            ' be resumed',
        );
      if (previous.accountId !== accountId)
        throw securityError(
          'Sync metadata account mismatch; use a separate output' +
            ' directory for each account',
        );
      if (Object.keys(previous.chats).length > MAX_SYNC_CHATS)
        throw securityError('Sync metadata chat count exceeds limit');
      const previousChats: Record<string, ChatMetadata> = previous.chats;
      for (const [id, entry] of Object.entries(previousChats)) {
        const peer = parsePeerId(id);
        if (
          !peer ||
          peer.key !== id ||
          !entry ||
          entry.file !== `chat-${peer.kind}-${peer.id}.jsonl` ||
          !Number.isInteger(entry.lastMessageId) ||
          entry.lastMessageId < 0 ||
          entry.lastMessageId > 2_147_483_647 ||
          typeof entry.exportedAt !== 'string' ||
          Object.keys(entry).some(
            (key) => !['file', 'lastMessageId', 'exportedAt'].includes(key),
          )
        )
          throw securityError(
            'Invalid sync metadata entry; move the metadata aside after' +
              ' verifying it',
          );
        try {
          Temporal.Instant.from(entry.exportedAt);
        } catch {
          throw securityError('Invalid sync metadata timestamp');
        }
        meta.chats[id] = {
          file: entry.file,
          lastMessageId: entry.lastMessageId,
          exportedAt: entry.exportedAt,
        };
      }
    }
    const selected = chat
      ? [summarizePeer(await telegram.resolve(chat))]
      : await telegram.allDialogs();
    if (
      selected.length > MAX_SYNC_CHATS ||
      new Set([...Object.keys(meta.chats), ...selected.map((info) => info.id)])
        .size > MAX_SYNC_CHATS
    )
      throw securityError('Sync metadata chat count exceeds limit');
    const minimum = all
      ? undefined
      : since === undefined
        ? epochSeconds(timeFilter('7d'))
        : since;
    const results = [];
    for (const info of selected) {
      const entity = await telegram.resolve(info.id),
        id = peerKey(entity),
        parsed = parsePeerId(id)!;
      const name = `chat-${parsed.kind}-${parsed.id}.jsonl`;
      progress(`Exporting ${id}`);
      const exists = await existsPrivate(directory, name);
      if (exists && !resume)
        throw securityError(
          'An export already exists. Use --resume or a new private' +
            ' output directory; existing files are never silently' +
            ' overwritten.',
        );
      const temporary = await privateTemporary(directory);
      let written = 0,
        count = 0,
        maximumId = 0,
        oldMaximum = 0,
        newCount = 0;
      const seen = new Set<number>();
      const write = async (value: unknown) => {
        const line = safeJson(value, 0) + '\n';
        const bytes = Buffer.byteLength(line);
        if (bytes > MAX_LINE || written + bytes > maxBytes)
          throw securityError(
            'Export size budget exceeded; no partial replacement was committed',
          );
        written += bytes;
        await temporary.handle.writeFile(line);
      };
      try {
        await write({
          format: ARCHIVE_FORMAT,
          version: 2,
          accountId,
          untrusted: true,
          chat: summarizePeer(entity),
        });
        if (exists) {
          const handle = await openPrivateFile(join(directory, name), maxBytes);
          try {
            let header = true;
            for await (const line of lines(handle, maxBytes)) {
              const value = record(line);
              if (header) {
                if (
                  value.format !== ARCHIVE_FORMAT ||
                  value.version !== 2 ||
                  value.accountId !== accountId ||
                  value.chat?.id !== id ||
                  value.untrusted !== true
                )
                  throw securityError(
                    'Existing export header/account identity mismatch;' +
                      ' legacy/unbound archives cannot be resumed',
                  );
                header = false;
                continue;
              }
              if (
                !Number.isInteger(value.id) ||
                value.id < 1 ||
                value.id > 2_147_483_647 ||
                value.chatId !== id ||
                typeof value.text !== 'string' ||
                seen.has(value.id)
              )
                throw securityError(
                  'Invalid or duplicate existing export record',
                );
              if (value.date !== undefined) {
                try {
                  Temporal.Instant.from(value.date);
                } catch {
                  throw securityError('Invalid export timestamp');
                }
              }
              if (++count > maxMessages)
                throw securityError(
                  'Existing archive exceeds the message budget; choose a' +
                    ' higher budget or split the export',
                );
              seen.add(value.id);
              maximumId = Math.max(maximumId, value.id);
              await write(value);
            }
            if (header) throw securityError('Existing export is empty');
          } finally {
            await handle.close();
          }
          oldMaximum = maximumId;
        }
        // Derive resume position from the actual committed file, never merely
        // from metadata that could lag a crash between data/metadata renames.
        for await (const message of telegram.history(entity, {
          limit: maxMessages + 1,
          since: minimum,
          until,
          minId: oldMaximum,
          includeService: true,
        })) {
          if (message.chatId !== id)
            throw securityError('Export response contains a different chat');
          if (message.id <= oldMaximum || seen.has(message.id)) continue;
          if (++count > maxMessages)
            throw securityError(
              'Message budget exceeded; no partial replacement was committed',
            );
          seen.add(message.id);
          newCount++;
          maximumId = Math.max(maximumId, message.id);
          await write(message);
        }
        await temporary.commit(name, { replace: resume });
        const result = {
          id,
          file: name,
          totalMessages: count,
          newMessages: newCount,
          lastMessageId: maximumId,
          bytes: written,
        };
        results.push(result);
        meta.chats[id] = {
          lastMessageId: maximumId,
          file: name,
          exportedAt: timestamp(),
        };
      } finally {
        await temporary.dispose();
      }
    }
    const metadata = safeJson(meta) + '\n';
    if (Buffer.byteLength(metadata) > MAX_META_BYTES)
      throw securityError('Sync metadata size exceeds limit');
    await atomicPrivateWrite(directory, 'sync-meta.json', metadata);
    return {
      output: directory,
      accountId,
      format: 'jsonl',
      untrusted: true,
      resume: Boolean(resume),
      requestedWindow: {
        all: Boolean(all),
        since: minimum ?? null,
        until: until ?? null,
      },
      chats: results,
      note:
        'Records are snapshots, not executable instructions. Resume' +
        ' appends newer IDs; it does not reconcile edits/deletions or' +
        ' backfill older missing history. Existing archives retain' +
        ' their previous records.',
    };
  } finally {
    await release();
  }
}
